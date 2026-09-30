from __future__ import annotations

import html
import json
import logging
import re
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import (
    parse_qsl,
    quote,
    unquote,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
from requests.exceptions import (
    ConnectionError as RequestsConnectionError,
    InvalidSchema,
    InvalidURL,
    MissingSchema,
    RequestException,
    SSLError,
    Timeout,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SCHEMA_DEPTH = 4
MAX_KEYS_PER_OBJECT = 50
MAX_ARRAY_ITEMS_TO_INSPECT = 5
CHUNK_SIZE = 8192

# Maximum raw response bytes consumed by the analyzer.
DEFAULT_MAX_RESPONSE_SIZE = 1_000_000

MAX_PARAM_EXAMPLE = 40
MAX_HEADER_VALUE = 200
MAX_FOUND_IN = 5
FOUND_IN_TRUNCATE = 300

# Maximum decoded text retained for response-structure inspection.
# This is separate from the raw-byte download limit.
BODY_READ_LIMIT = 1_000_000

REDACTED = "REDACTED"
SOURCE_DEFAULT = "endpoint_discovery"

# Note: Trailing spaces were removed from these patterns to fix a bug
# where common sensitive keys (like "token" or "api_key") were not matched.
SENSITIVE_PATTERNS = (
    "token", "key", "secret", "password", "passwd", "pwd", "auth",
    "session", "cookie", "jwt", "code", "signature", "credential",
)

# Single-word compounds the camelCase/separator tokenizer cannot split.
_SENSITIVE_COMPOUNDS = frozenset({
    "authorization", "authenticated", "authentication", "authenticator",
    "sessionid", "authtoken", "apikey", "secretkey", "clientsecret",
    "accesstoken", "refreshtoken", "idtoken",
})

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

LOGIN_PATH_RE = re.compile(
    r"(log-?in|sign-?in|sso|oauth2?|authorize)([/.]|$)", re.I
)
NUMERIC_SEG_RE = re.compile(r"\d+")
UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

# Binary/static response media types.
_BINARY_TYPES = {
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "application/wasm",
    "application/gzip",
    "application/x-gzip",
}

# JavaScript/CSS are text/static resources, not binary.
_JS_CSS_TYPES = {
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/css",
}


def _is_binary_content(ct: str | None) -> bool:
    """True for binary/static asset media types."""
    if not ct:
        return False
    if ct.startswith(("image/", "audio/", "video/", "font/")):
        return True
    return ct in _BINARY_TYPES


def _is_json_content(ct: str | None) -> bool:
    """JSON content type: application/json or any *+json media type."""
    if not ct:
        return False
    return ct == "application/json" or ct.endswith("+json")


def _is_xml_content(ct: str | None) -> bool:
    if not ct:
        return False
    return ct in {"application/xml", "text/xml"} or ct.endswith("+xml")


class EndpointAnalyzer:
    """Analyze endpoint candidates from discovery output with safe GET requests."""

    def __init__(
        self,
        timeout: float = 10,
        base_url: str | None = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        request_delay: float = 0.1,
    ) -> None:
        # Strict type validation to prevent raw TypeErrors from leaking
        if type(timeout) not in (int, float):
            raise ValueError("timeout must be a number > 0")
        if timeout <= 0:
            raise ValueError("timeout must be > 0")
            
        if type(max_redirects) is not int:
            raise ValueError("max_redirects must be an integer >= 0")
        if max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
            
        if type(max_response_size) not in (int, float):
            raise ValueError("max_response_size must be a number > 0")
        if max_response_size <= 0:
            raise ValueError("max_response_size must be > 0")
            
        if type(request_delay) not in (int, float):
            raise ValueError("request_delay must be a number >= 0")
        if request_delay < 0:
            raise ValueError("request_delay must be >= 0")

        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.follow_redirects = bool(follow_redirects)
        self.max_redirects = int(max_redirects)
        self.max_response_size = int(max_response_size)
        self.request_delay = float(request_delay)

        self.base_url: str | None = None
        if base_url is not None:
            parsed = self._parse_http_url(str(base_url))
            if parsed is None:
                raise ValueError(f"invalid base_url: {base_url!r}")
            self.base_url = str(base_url).strip()

        self._session = requests.Session()
        # Never use environment proxies or implicit credentials.
        self._session.trust_env = False
        self._session.headers.update({
            "User-Agent": "API-Endpoint-Analyzer/1.0",
            "Accept": "application/json, */*;q=0.8",
        })

        self._last_request_end: float | None = None
        self._wrapper_target: str | None = None

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the underlying HTTP session."""
        try:
            self._session.close()
        except Exception:
            pass

    def __enter__(self) -> "EndpointAnalyzer":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    # -- public analysis API ------------------------------------------------

    def analyze_endpoint(self, candidate: Any) -> dict[str, Any]:
        """Analyze one candidate; never raises, always returns a result record."""
        result = self._new_result()
        try:
            self._analyze_into(result, candidate)
        except Exception as exc:
            logger.debug("unexpected error while analyzing endpoint", exc_info=True)
            result["error"] = {
                "type": "unexpected_error",
                "message": f"{type(exc).__name__}: {exc}",
            }
        return result

    def analyze_candidates(self, candidates: Any) -> list[dict[str, Any]]:
        """Analyze many candidates; accepts list/dict wrapper/single item/None."""
        # Do not leak a previous wrapper target into later calls.
        self._wrapper_target = None
        items: list[Any]

        if candidates is None:
            items = []
        elif isinstance(candidates, list):
            items = candidates
        elif isinstance(candidates, dict):
            inner = candidates.get("endpoints")
            if isinstance(inner, list):
                target = candidates.get("target")
                if isinstance(target, str) and target.strip():
                    self._wrapper_target = target.strip()
                items = inner
            else:
                items = [candidates]
        else:
            items = [candidates]

        try:
            return [self.analyze_endpoint(item) for item in items]
        finally:
            # Prevent stale target state after this batch.
            self._wrapper_target = None

    def analyze_discovery_file(
        self,
        input_path: str,
        output_path: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load discovery JSON, analyze it, optionally write results."""
        with open(input_path, encoding="utf-8") as fh:
            raw = fh.read()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in {input_path}: {exc}") from exc

        if isinstance(data, dict):
            endpoints = data.get("endpoints")
            if not isinstance(endpoints, list):
                raise ValueError(
                    "discovery JSON must contain an 'endpoints' list"
                )
        elif isinstance(data, list):
            endpoints = data
        else:
            raise ValueError("discovery JSON must be an object or a list")

        results = self.analyze_candidates(data)

        if output_path is not None:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2, ensure_ascii=False)

        return results

    # -- core per-candidate flow --------------------------------------------

    def _analyze_into(self, result: dict[str, Any], candidate: Any) -> None:
        url_raw: Any = None
        source = SOURCE_DEFAULT
        found_in: list[str] | None = None

        if isinstance(candidate, str):
            url_raw = candidate
        elif isinstance(candidate, dict):
            url_raw = candidate.get("url")
            src = candidate.get("source")
            if isinstance(src, str) and src.strip():
                source = src
            fi = candidate.get("found_in")
            if isinstance(fi, list):
                strings = [e for e in fi if isinstance(e, str)]
                if strings:
                    found_in = [
                        self._truncate(
                            self._redact_url_string(s),
                            FOUND_IN_TRUNCATE,
                        )
                        for s in strings[:MAX_FOUND_IN]
                    ]

        result["source"] = source
        result["found_in"] = found_in

        if not isinstance(url_raw, str) or not url_raw.strip():
            result["error"] = {
                "type": "invalid_url",
                "message": "candidate has no usable URL string",
            }
            return

        cleaned = url_raw.strip()
        if "&amp;" in cleaned.lower():
            cleaned = html.unescape(cleaned)
            result["warnings"].append(
                "url contained HTML-escaped '&amp;'; decoded before analysis"
            )

        result["url"] = self._redact_url_string(cleaned)

        base = self.base_url or self._wrapper_target

        try:
            probe = urlsplit(cleaned)
        except (ValueError, UnicodeError):
            probe = None

        if (
            probe is not None
            and not probe.scheme
            and not probe.netloc
            and not cleaned.startswith("/")
        ):
            result["error"] = {
                "type": "invalid_url",
                "message": (
                    "candidate is not an absolute or relative URL"
                ),
            }
            return

        try:
            resolved = self._resolve_url(cleaned, base)
        except (ValueError, UnicodeError):
            resolved = None

        if resolved is None:
            result["error"] = {
                "type": "invalid_url",
                "message": "URL could not be parsed or resolved",
            }
            return

        error = self._validate_resolved(resolved)
        if error is not None:
            result["error"] = error
            return

        visible_url = self._rebuild(resolved)

        # Query parameters are extracted from the visible input URL before
        # sensitive values are sanitized.
        result["parameters"] = self._extract_parameters(visible_url)

        request_url, _sent_query, changed = self._sanitize_query(visible_url)
        if changed:
            result["warnings"].append(
                "sensitive parameter values were not sent"
            )

        net = self._perform_request(result, request_url)

        if net is not None:
            result["response_time_ms"] = round(
                net["elapsed_s"] * 1000, 1
            )
            self._finalize(result, net, request_url)

    # -- URL helpers ---------------------------------------------------------

    @staticmethod
    def _parse_http_url(
        url: str,
    ) -> tuple[str, str, str, str, str] | None:
        try:
            parts = urlsplit(url.strip())
        except (ValueError, UnicodeError):
            return None

        if parts.scheme.lower() not in ("http", "https"):
            return None

        try:
            _ = parts.port
        except ValueError:
            return None

        if not parts.hostname:
            return None

        # Reject userinfo (e.g., https://user:pass@host.com)
        if parts.username is not None or parts.password is not None:
            return None

        return (
            parts.scheme,
            parts.netloc,
            parts.path,
            parts.query,
            parts.fragment,
        )

    def _resolve_url(
        self,
        url: str,
        base: str | None,
    ) -> tuple[str, str, str, str, str] | None:
        candidate = url
        if base and not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.\-]*:", url
        ):
            candidate = urljoin(base, url)

        try:
            parts = urlsplit(candidate)
            _ = parts.port
        except (ValueError, UnicodeError):
            return None

        scheme = parts.scheme.lower()

        if not parts.scheme and not parts.netloc:
            return None

        if scheme not in ("http", "https") and not parts.netloc:
            return (scheme, "", parts.path, parts.query, "")

        return (
            scheme,
            parts.netloc,
            parts.path,
            parts.query,
            "",
        )

    @staticmethod
    def _validate_resolved(
        parts: tuple[str, str, str, str, str]
    ) -> dict[str, str] | None:
        candidate = urlunsplit(parts)
        try:
            split = urlsplit(candidate)
            scheme = split.scheme.lower()
            host = (split.hostname or "").lower()
            userinfo = (
                split.username is not None
                or split.password is not None
            )
        except (ValueError, UnicodeError):
            return {
                "type": "invalid_url",
                "message": "URL could not be parsed safely",
            }

        if scheme not in ("http", "https"):
            return {
                "type": "unsupported_scheme",
                "message": (
                    f"URL scheme '{scheme or 'none'}' is not supported "
                    "(http/https only)"
                ),
            }

        if not host:
            return {
                "type": "invalid_url",
                "message": "URL has no hostname",
            }

        if userinfo:
            return {
                "type": "invalid_url",
                "message": "URL contains userinfo which is rejected",
            }

        return None

    @staticmethod
    def _rebuild(
        parts: tuple[str, str, str, str, str]
    ) -> str:
        scheme, netloc, path, query, _frag = parts
        return urlunsplit(
            (scheme, netloc, path, query, "")
        )

    def _is_sensitive_key(self, key: str) -> bool:
        try:
            decoded = unquote(key)
        except Exception:
            decoded = key
        # Token-based match (split on separators + camelCase humps) so
        # that "author" does NOT match the "auth" pattern while
        # "api_key"/"authToken"/"password" still do. Substring matching
        # here blanked innocent params and produced false 404s.
        # _SENSITIVE_COMPOUNDS covers single-word compounds the
        # tokenizer cannot split ("authorization", "sessionid").
        try:
            tokens = re.findall(
                r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+", decoded
            )
        except (TypeError, re.error):
            tokens = []
        if not tokens:
            norm = decoded.lower().replace("-", "").replace("_", "")
            return any(p in norm for p in SENSITIVE_PATTERNS)
        for tok in tokens:
            low = tok.lower()
            if low in SENSITIVE_PATTERNS or low in _SENSITIVE_COMPOUNDS:
                return True
            if low.endswith("s") and low[:-1] in SENSITIVE_PATTERNS:
                return True  # plurals: tokens, keys, secrets, cookies
        return False

    def _sanitize_query(
        self,
        url: str,
    ) -> tuple[str, str | None, bool]:
        """
        Blank sensitive query values.
        Returns:
            (request_url, sanitized_query, changed)
        """
        parts = urlsplit(url)
        if not parts.query:
            return url, None, False

        pairs = parse_qsl(
            parts.query,
            keep_blank_values=True,
        )
        changed = False
        out: list[str] = []

        for name, value in pairs:
            encoded_name = quote(name, safe="")
            if self._is_sensitive_key(name) and value:
                out.append(f"{encoded_name}=")
                changed = True
            else:
                out.append(
                    f"{encoded_name}={quote(value, safe='')}"
                )

        new_query = "&".join(out)
        rebuilt = urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                new_query,
                "",
            )
        )
        return rebuilt, new_query, changed

    def _redact_url_string(self, url: str) -> str:
        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return url

        if not parts.query:
            return url

        out = []
        for pair in parts.query.split("&"):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            if self._is_sensitive_key(name) and value:
                out.append(f"{name}={REDACTED}")
            else:
                out.append(pair)

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                "&".join(out),
                parts.fragment,
            )
        )

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        return text if len(text) <= limit else text[:limit]

    @staticmethod
    def _safe_log_url(url: str) -> str:
        try:
            p = urlsplit(url)
            return f"{p.scheme}://{p.netloc}{p.path}"
        except (ValueError, UnicodeError):
            return "<unparseable-url>"

    # -- networking ----------------------------------------------------------

    def _throttle(self) -> None:
        """Enforce request_delay between network requests."""
        if self._last_request_end is None or self.request_delay <= 0:
            return
        elapsed = time.monotonic() - self._last_request_end
        if elapsed < self.request_delay:
            time.sleep(self.request_delay - elapsed)

    def _mark_request_done(self) -> None:
        self._last_request_end = time.monotonic()

    def _set_network_error(
        self,
        result: dict[str, Any],
        error_type: str,
        message: str,
        chain: list[str],
    ) -> None:
        result["method"] = "GET"
        result["final_url"] = self._redact_url_string(chain[-1])
        result["redirect_chain"] = [
            self._redact_url_string(u) for u in chain
        ]
        result["redirected"] = len(chain) > 1
        result["error"] = {
            "type": error_type,
            "message": self._short(message),
        }

    def _perform_request(
        self,
        result: dict[str, Any],
        initial_url: str,
    ) -> dict[str, Any] | None:
        """Manual-redirect GET loop."""
        current_url = initial_url
        chain: list[str] = [initial_url]
        redirect_host = self._redirect_host(initial_url)
        hops = 0
        connect_s = 0.0
        body_s = 0.0
        
        # Wrap the loop to ensure cookies are cleared EXACTLY ONCE per candidate,
        # allowing them to persist across redirect hops but isolating them between candidates.
        try:
            while True:
                self._throttle()
                logger.debug(
                    "requesting %s",
                    self._safe_log_url(current_url),
                )
                t_conn0 = time.perf_counter()
                try:
                    response = self._session.get(
                        current_url,
                        allow_redirects=False,
                        stream=True,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                except Timeout as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "timeout", str(exc), chain
                    )
                    return None
                except SSLError as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "ssl_error", str(exc), chain
                    )
                    return None
                except (
                    InvalidURL,
                    InvalidSchema,
                    MissingSchema,
                ) as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "invalid_url", str(exc), chain
                    )
                    return None
                except RequestsConnectionError as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "connection_error", str(exc), chain
                    )
                    return None
                except RequestException as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result, "request_error", str(exc), chain
                    )
                    return None
                except Exception as exc:
                    self._mark_request_done()
                    self._set_network_error(
                        result,
                        "unexpected_error",
                        f"{type(exc).__name__}: {exc}",
                        chain,
                    )
                    return None
                
                connect_s += time.perf_counter() - t_conn0
                try:
                    status = response.status_code
                    headers = {
                        k.lower(): v
                        for k, v in response.headers.items()
                    }
                    content_type = self._normalize_content_type(
                        headers.get("content-type")
                    )
                    location = headers.get("location")
                    is_redirect = (
                        status in REDIRECT_STATUSES
                        and bool(location and location.strip())
                    )
                    
                    if is_redirect and self.follow_redirects:
                        if hops >= self.max_redirects:
                            t_body0 = time.perf_counter()
                            observed = self._read_body(
                                response,
                                headers,
                                content_type,
                                result,
                            )
                            body_s += time.perf_counter() - t_body0
                            observed["status"] = status
                            observed["final_url"] = current_url
                            observed["chain"] = chain
                            observed["blocked"] = False
                            observed["too_many"] = True
                            observed["location"] = location
                            observed["elapsed_s"] = (
                                connect_s + body_s
                            )
                            return observed
                            
                        nxt, blocked_reason = self._resolve_redirect(
                            current_url,
                            location,
                            redirect_host,
                        )
                        if nxt is None:
                            observed = {
                                "headers": headers,
                                "content_type": content_type,
                                "body": None,
                                "size": None,
                                "truncated": False,
                                "deadline": False,
                            }
                            observed["status"] = status
                            observed["final_url"] = chain[-1]
                            observed["chain"] = chain
                            observed["blocked"] = True
                            observed["too_many"] = False
                            observed["block_reason"] = (
                                blocked_reason
                                or "redirect target blocked"
                            )
                            observed["location"] = location
                            observed["elapsed_s"] = (
                                connect_s + body_s
                            )
                            return observed
                        
                        try:
                            response.close()
                        except Exception:
                            pass
                            
                        nxt_request, _, hop_changed = (
                            self._sanitize_query(nxt)
                        )
                        if hop_changed:
                            result["warnings"].append(
                                "sensitive parameter values were not sent"
                            )
                        current_url = nxt_request
                        chain.append(nxt_request)
                        hops += 1
                        continue  # Inner finally handles cleanup & timestamp
                    
                    # Final response for this candidate.
                    t_body0 = time.perf_counter()
                    observed = self._read_body(
                        response,
                        headers,
                        content_type,
                        result,
                    )
                    body_s += time.perf_counter() - t_body0
                    observed["status"] = status
                    observed["final_url"] = current_url
                    observed["chain"] = chain
                    observed["blocked"] = False
                    observed["too_many"] = False
                    observed["location"] = location
                    observed["elapsed_s"] = (
                        connect_s + body_s
                    )
                    if (
                        status in REDIRECT_STATUSES
                        and not (location and location.strip())
                    ):
                        result["warnings"].append(
                            "redirect without Location"
                        )
                    return observed
                finally:
                    try:
                        response.close()
                    except Exception:
                        pass
                    # Handled here for both normal returns and 'continue' statements
                    self._mark_request_done()
        finally:
            try:
                self._session.cookies.clear()
            except Exception:
                pass

    @staticmethod
    def _short(message: str) -> str:
        message = message.replace("\n", " ").strip()
        return message[:200] or "request failed"

    def _redirect_host(
        self,
        url: str,
    ) -> tuple[str, str, int] | None:
        try:
            parts = urlsplit(url)
        except (ValueError, UnicodeError):
            return None

        host = (parts.hostname or "").lower()
        # Strict hostname literal matching (no www. stripping)
        
        try:
            port = parts.port
        except ValueError:
            return None

        if port is None:
            port = (
                443
                if parts.scheme.lower() == "https"
                else 80
            )

        return (
            parts.scheme.lower(),
            host,
            port,
        )

    def _resolve_redirect(
        self,
        current_url: str,
        location: str,
        origin: tuple[str, str, int] | None,
    ) -> tuple[str | None, str | None]:
        try:
            target = urljoin(
                current_url,
                location.strip(),
            )
            parts = urlsplit(target)
        except (ValueError, UnicodeError):
            return None, "redirect target could not be parsed"

        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            return None, "redirect target uses an unsupported scheme"

        if (
            parts.username is not None
            or parts.password is not None
        ):
            return None, "redirect target contains userinfo"

        try:
            tport = parts.port
        except ValueError:
            return None, "redirect target has an invalid port"

        thost = (parts.hostname or "").lower()
        # Strict hostname literal matching (no www. stripping)
        
        if not thost:
            return None, "redirect target has no hostname"

        if tport is None:
            tport = 443 if scheme == "https" else 80

        if origin is not None:
            oscheme, ohost, oport = origin

            if thost != ohost:
                return None, "redirect target is on a different host"

            if scheme != oscheme:
                if not (
                    oscheme == "http"
                    and scheme == "https"
                    and oport == 80
                    and tport == 443
                ):
                    return None, "redirect target changes scheme"

            if tport != oport and not (
                oscheme == "http"
                and scheme == "https"
                and oport == 80
                and tport == 443
            ):
                return None, "redirect target changes port"

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                parts.query,
                "",
            )
        ), None

    # -- body reading --------------------------------------------------------

    def _read_body(
        self,
        response: requests.Response,
        headers: dict[str, str],
        content_type: str | None,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Read at most max_response_size RAW bytes.
        The raw-byte limit is enforced before UTF-8 decoding. A separate
        decoded-text limit prevents pathological expansion from consuming
        excessive memory while still allowing normal JSON responses up to
        the configured raw response limit to be analyzed.
        """
        raw_size = 0
        truncated = False
        deadline_exceeded = False
        chunks: list[str] = []
        collected_chars = 0
        deadline = time.monotonic() + self.timeout

        try:
            for raw in response.iter_content(
                chunk_size=CHUNK_SIZE
            ):
                if not raw:
                    continue
                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break

                remaining = (
                    self.max_response_size - raw_size
                )
                if remaining <= 0:
                    truncated = True
                    break

                if len(raw) > remaining:
                    raw = raw[:remaining]
                    truncated = True

                raw_size += len(raw)

                # Keep enough decoded text for structure inference.
                if collected_chars < BODY_READ_LIMIT:
                    piece = raw.decode(
                        "utf-8-sig",
                        errors="replace",
                    )
                    remaining_chars = (
                        BODY_READ_LIMIT - collected_chars
                    )
                    if len(piece) > remaining_chars:
                        piece = piece[:remaining_chars]
                    chunks.append(piece)
                    collected_chars += len(piece)

                if truncated:
                    break

                if time.monotonic() > deadline:
                    deadline_exceeded = True
                    break
        except Exception as exc:
            result["warnings"].append(
                "body read interrupted: "
                f"{type(exc).__name__}: "
                f"{self._short(str(exc))}"
            )

        if truncated:
            result["warnings"].append(
                f"body truncated at {self.max_response_size} bytes"
            )
        if deadline_exceeded:
            result["warnings"].append(
                "body read deadline exceeded"
            )

        return {
            "headers": headers,
            "content_type": content_type,
            "body": "".join(chunks),
            # Response size is deliberately a RAW byte count.
            "size": raw_size,
            "truncated": truncated,
            "deadline": deadline_exceeded,
        }

    # -- post-response finalization ------------------------------------------

    @staticmethod
    def _status_category(status: int) -> str:
        if 100 <= status < 200:
            return "informational"
        if 200 <= status < 300:
            return "success"
        if 300 <= status < 400:
            return "redirect"
        if 400 <= status < 500:
            return "client_error"
        if 500 <= status < 600:
            return "server_error"
        return "unknown"

    def _finalize(
        self,
        result: dict[str, Any],
        net: dict[str, Any],
        initial_url: str,
    ) -> None:
        headers: dict[str, str] = net["headers"]
        content_type: str | None = net["content_type"]
        status: int = net["status"]
        body: str | None = net["body"]
        chain: list[str] = net["chain"]
        final_url: str = net["final_url"]

        result["method"] = "GET"
        result["status"] = status
        result["status_category"] = self._status_category(status)
        result["content_type"] = content_type
        result["response_size"] = net["size"]
        result["response_size_truncated"] = bool(
            net["truncated"]
        )
        result["redirected"] = len(chain) > 1
        result["redirect_chain"] = [
            self._redact_url_string(u)
            for u in chain
        ]
        result["final_url"] = self._redact_url_string(
            final_url
        )
        result["headers"] = self._extract_headers(headers)

        # Only add path parameters from URLs that were actually requested.
        result["parameters"].extend(
            self._path_parameters(final_url)
        )

        if body is None:
            struct = None
        else:
            struct = self._detect_structure(
                body,
                content_type,
                net,
                result,
            )

        result["response_structure"] = struct

        if content_type is None:
            result["warnings"].append(
                "missing Content-Type header"
            )

        ctx = {
            "status": status,
            "content_type": content_type,
            "struct": struct,
            "body": body,
            "headers": headers,
            "chain": chain,
            "final_url": final_url,
            "initial_url": initial_url,
            "truncated": net["truncated"],
            "deadline": net.get("deadline", False),
            "followed_same_host": len(chain) > 1,
        }

        result["api_behavior"] = (
            self._classify_api_behavior(ctx)
        )
        result["access"] = self._classify_access(ctx)

        if net.get("blocked"):
            result["error"] = {
                "type": "blocked_redirect",
                "message": net.get(
                    "block_reason",
                    "redirect target blocked",
                ),
            }
        elif net.get("too_many"):
            result["error"] = {
                "type": "too_many_redirects",
                "message": (
                    f"more than {self.max_redirects} "
                    "redirects encountered"
                ),
            }

    @staticmethod
    def _normalize_content_type(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        ct = value.strip().lower()
        if not ct:
            return None
        return ct.split(";", 1)[0].strip() or None

    def _extract_headers(
        self,
        headers: dict[str, str],
    ) -> dict[str, str | None]:
        wanted = (
            "content-length",
            "server",
            "allow",
            "www-authenticate",
            "location",
            "access-control-allow-origin",
        )
        out: dict[str, str | None] = {}

        for key in wanted:
            value = headers.get(key)
            if value is None:
                out[key] = None
                continue
            value = value.strip()
            if key == "location":
                value = self._redact_url_string(value)
            out[key] = self._truncate(
                value,
                MAX_HEADER_VALUE,
            )

        return out

    # -- parameters ----------------------------------------------------------

    def _extract_parameters(
        self,
        url: str,
    ) -> list[dict[str, Any]]:
        """Visible query parameters; sensitive values are redacted."""
        try:
            query = urlsplit(url).query
        except (ValueError, UnicodeError):
            return []

        seen: set[str] = set()
        params: list[dict[str, Any]] = []

        for name, value in parse_qsl(
            query,
            keep_blank_values=True,
        ):
            if name in seen:
                continue
            seen.add(name)

            if self._is_sensitive_key(name):
                example = REDACTED
            else:
                example = self._truncate(
                    value,
                    MAX_PARAM_EXAMPLE,
                )

            params.append({
                "name": name,
                "location": "query",
                "example_value": example,
            })

        return params

    def _path_parameters(
        self,
        url: str,
    ) -> list[dict[str, Any]]:
        """Detect obvious numeric-ID / UUID path segments."""
        try:
            path = urlsplit(url).path
        except (ValueError, UnicodeError):
            return []

        out: list[dict[str, Any]] = []
        try:
            segments = [
                s for s in path.split("/") if s
            ]
        except Exception:
            return []

        for idx, seg in enumerate(segments):
            kind = None
            if NUMERIC_SEG_RE.fullmatch(seg):
                kind = "possible_identifier"
            elif UUID_SEG_RE.fullmatch(seg):
                kind = "possible_identifier"

            if kind:
                out.append({
                    "name": None,
                    "location": "path",
                    "segment": self._truncate(
                        seg,
                        MAX_PARAM_EXAMPLE,
                    ),
                    "position": idx,
                    "parameter_type": kind,
                })

        return out

    # -- response structure --------------------------------------------------

    def _looks_like_html(self, body: str) -> bool:
        head = body.lstrip()[:200].lower()
        return (
            head.startswith("<!doctype html")
            or head.startswith("<html")
        )

    def _try_parse_json(
        self,
        text: str,
    ) -> tuple[bool, Any]:
        try:
            return True, json.loads(text)
        except RecursionError:
            return False, None
        except (ValueError, TypeError):
            return False, None
        except Exception:
            return False, None

    def _detect_structure(
        self,
        body: str,
        content_type: str | None,
        net: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """FIRST MATCH WINS response-structure detection."""
        if body is None:
            return None

        stripped = body.strip()

        # 1. empty body
        if not stripped:
            if _is_json_content(content_type):
                result["warnings"].append(
                    "empty JSON body"
                )
            return {"type": "empty"}

        # 2. binary/static
        if _is_binary_content(content_type):
            return {"type": "binary"}

        json_ct = _is_json_content(content_type)
        starts_json = stripped[0] in "{["

        # 3. JSON
        if json_ct or starts_json:
            ok, parsed = self._try_parse_json(
                stripped
            )
            if ok:
                if (
                    not json_ct
                    and isinstance(parsed, (dict, list))
                ):
                    result["warnings"].append(
                        "JSON despite content type "
                        f"{content_type or 'unknown'}"
                    )
                return self._infer_structure(
                    parsed,
                    1,
                )
            if json_ct:
                if (
                    net["truncated"]
                    or net["deadline"]
                ):
                    return {"type": "unknown"}
                if self._looks_like_html(stripped):
                    if _is_xml_content(content_type):
                        return {"type": "xml"}
                    return {"type": "html"}
                result["warnings"].append(
                    "malformed JSON"
                )
                return {"type": "unknown"}

        # 4. XML
        if (
            _is_xml_content(content_type)
            or stripped.lower().startswith("<?xml")
            or stripped[:1] == "<"
            and self._looks_like_xml(stripped)
        ):
            if net["truncated"] or net["deadline"]:
                return {"type": "unknown"}
            struct = None
            if not self._looks_like_html(stripped):
                struct = self._parse_xml_structure(stripped)
            if struct is not None:
                if (
                    not _is_xml_content(content_type)
                    and not stripped.lower().startswith("<?xml")
                ):
                    result["warnings"].append(
                        "XML despite content type "
                        f"{content_type or 'unknown'}"
                    )
                return struct
            if _is_xml_content(content_type):
                result["warnings"].append(
                    "malformed XML"
                )
                return {"type": "unknown"}
            # Angle-bracket body that is actually HTML falls through.

        # 5. HTML
        if (
            content_type == "text/html"
            or self._looks_like_html(stripped)
        ):
            return {"type": "html"}

        # 6. Text
        if (
            (content_type or "").startswith("text/")
            or content_type in _JS_CSS_TYPES
        ):
            return {"type": "text"}

        # 7. unknown
        return {"type": "unknown"}

    @staticmethod
    def _looks_like_xml(stripped: str) -> bool:
        head = stripped[:200].lower()
        return head.startswith("<") and re.match(
            r"<\??[a-z_][\w\-.]*[:\s/>?]", head
        ) is not None

    @staticmethod
    def _strip_ns(tag: str) -> tuple[str, str | None]:
        """Split '{namespace}local' -> (local, namespace)."""
        if tag.startswith("{"):
            ns, _, local = tag[1:].partition("}")
            return local, ns or None
        return tag, None

    def _parse_xml_structure(
        self, stripped: str
    ) -> dict[str, Any] | None:
        """Parse XML body -> detailed structure (None if not XML).

        Uses stdlib ElementTree only (no external entities resolved).
        Depth capped at MAX_SCHEMA_DEPTH, children capped at
        MAX_KEYS_PER_OBJECT, mirroring JSON inference.
        """
        try:
            root = ET.fromstring(stripped)
        except ET.ParseError:
            return None
        except (ValueError, MemoryError, RecursionError):
            return None
        except Exception:
            return None
        local, _ns = self._strip_ns(root.tag)
        struct: dict[str, Any] = self._infer_xml_element(
            root, 1
        )
        # RSS/Atom feed flag: content syndication, not an API.
        low = local.lower()
        if low == "rss" or (
            low == "feed"
            and "entry" in (struct.get("children") or {})
        ):
            struct["feed"] = "rss" if low == "rss" else "atom"
        elif low == "feed" and "item" in (
            struct.get("children") or {}
        ):
            struct["feed"] = "rss"
        # SOAP envelope flag.
        if low == "envelope":
            body_child = None
            fault = False
            for child in struct.get("children") or {}:
                if child.lower() == "body":
                    nested = (struct.get("nested") or {}).get(
                        child
                    ) or {}
                    ops = list(
                        (nested.get("children") or {}).keys()
                    )
                    if ops:
                        body_child = ops[0]
                        op_nested = (nested.get("nested") or {}).get(
                            ops[0]
                        ) or {}
                        fault = "fault" in (
                            op_nested.get("children") or {}
                        ) or ops[0].lower() == "fault"
                    break
            struct["soap"] = True
            if body_child:
                struct["operation"] = body_child
            if fault:
                struct["fault"] = True
        return struct

    def _infer_xml_element(
        self, elem: Any, depth: int
    ) -> dict[str, Any]:
        """Recursive XML element inference down to MAX_SCHEMA_DEPTH."""
        local, ns = self._strip_ns(elem.tag)
        struct: dict[str, Any] = {
            "type": "xml",
            "root": local,
        }
        if ns:
            struct["namespace"] = ns[:MAX_PARAM_EXAMPLE]
        if elem.attrib:
            attrs = sorted(str(k).split("}")[-1] for k in elem.attrib)
            struct["attributes"] = attrs[:MAX_KEYS_PER_OBJECT]
            if len(attrs) > MAX_KEYS_PER_OBJECT:
                struct["note"] = (
                    f"only first {MAX_KEYS_PER_OBJECT} "
                    "attributes recorded"
                )
        counts: dict[str, int] = {}
        order: list[str] = []
        for child in list(elem)[: MAX_KEYS_PER_OBJECT * 2]:
            try:
                name, _ = self._strip_ns(child.tag)
            except (ValueError, AttributeError):
                continue
            counts[name] = counts.get(name, 0) + 1
            if name not in order:
                order.append(name)
        if order:
            struct["children"] = {
                n: counts[n] for n in order[:MAX_KEYS_PER_OBJECT]
            }
            repeated = sorted(
                n for n, c in counts.items() if c > 1
            )
            if repeated:
                struct["repeated"] = repeated[:MAX_KEYS_PER_OBJECT]
            if depth < MAX_SCHEMA_DEPTH:
                nested: dict[str, Any] = {}
                seen: set[str] = set()
                for child in list(elem):
                    try:
                        name, _ = self._strip_ns(child.tag)
                    except (ValueError, AttributeError):
                        continue
                    if name in seen:
                        continue
                    seen.add(name)
                    if len(nested) >= MAX_KEYS_PER_OBJECT:
                        break
                    nested[name] = self._infer_xml_element(
                        child, depth + 1
                    )
                    if len(seen) >= MAX_KEYS_PER_OBJECT:
                        break
                if nested:
                    struct["nested"] = nested
        else:
            text = (elem.text or "").strip()
            if text:
                struct["text"] = text[:MAX_PARAM_EXAMPLE]
        return struct

    def _primitive_type(self, value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "number"
        if isinstance(value, str):
            return "string"
        return "unknown"

    def _infer_structure(
        self,
        value: Any,
        depth: int = 1,
    ) -> dict[str, Any]:
        """Infer compact JSON structure down to MAX_SCHEMA_DEPTH."""
        if isinstance(value, dict):
            keys = list(value.keys())
            struct: dict[str, Any] = {
                "type": "object",
                "keys": keys[:MAX_KEYS_PER_OBJECT],
            }
            if len(keys) > MAX_KEYS_PER_OBJECT:
                struct["note"] = (
                    f"only first {MAX_KEYS_PER_OBJECT} "
                    "keys recorded"
                )

            nested: dict[str, Any] = {}
            if depth < MAX_SCHEMA_DEPTH:
                for key in keys[:MAX_KEYS_PER_OBJECT]:
                    child = value[key]
                    if isinstance(child, (dict, list)):
                        nested[str(key)] = (
                            self._infer_structure(
                                child,
                                depth + 1,
                            )
                        )
            if nested:
                struct["nested"] = nested

            return struct

        if isinstance(value, list):
            struct = {
                "type": "array",
                "length": len(value),
                "item_type": None,
            }
            if value:
                inspected = value[
                    :MAX_ARRAY_ITEMS_TO_INSPECT
                ]
                types = []
                for item in inspected:
                    if isinstance(item, dict):
                        types.append("object")
                    elif isinstance(item, list):
                        types.append("array")
                    else:
                        types.append(
                            self._primitive_type(item)
                        )
                unique = sorted(set(types))
                if len(unique) == 1:
                    struct["item_type"] = unique[0]
                else:
                    struct["item_type"] = "mixed"
                    struct["item_types"] = unique

                obj_keys: list[str] = []
                seen: set[str] = set()
                for item in inspected:
                    if isinstance(item, dict):
                        for key in item.keys():
                            if key not in seen:
                                seen.add(key)
                                obj_keys.append(key)
                if obj_keys:
                    struct["item_keys"] = obj_keys[
                        :MAX_KEYS_PER_OBJECT
                    ]

            return struct

        return {
            "type": self._primitive_type(value)
        }

    # -- classification -----------------------------------------------------

    def _parsed_container(
        self,
        struct: dict[str, Any] | None,
    ) -> bool:
        return (
            isinstance(struct, dict)
            and struct.get("type") in ("object", "array")
        )

    def _classify_api_behavior(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """FIRST MATCH WINS API-behavior classification."""
        struct = ctx["struct"]
        ct = ctx["content_type"]
        status = ctx["status"]
        body = ctx["body"]
        headers = ctx["headers"]

        json_ct = _is_json_content(ct)
        container = self._parsed_container(struct)
        primitive_json = (
            isinstance(struct, dict)
            and struct.get("type") in (
                "string",
                "number",
                "boolean",
                "null",
            )
            and json_ct
        )
        stype = (
            struct.get("type")
            if isinstance(struct, dict)
            else None
        )

        if stype is None:
            return self._behavior(
                "uncertain",
                [
                    "1: request failed or response body "
                    "unavailable"
                ],
            )

        if (
            container
            and json_ct
            and status not in (404, 410)
        ):
            return self._behavior(
                "confirmed",
                [
                    f"2: JSON {stype} returned with JSON "
                    f"content type (status {status})"
                ],
            )

        if container and status in (404, 410):
            return self._behavior(
                "likely",
                [
                    f"3: JSON {stype} returned with "
                    f"error status {status}"
                ],
            )

        if primitive_json:
            return self._behavior(
                "likely",
                [
                    "4: JSON primitive with JSON "
                    "content type"
                ],
            )

        if (
            (ctx["truncated"] or ctx.get("deadline"))
            and (
                json_ct
                or (
                    isinstance(body, str)
                    and body.lstrip()[:1] in "{["
                )
            )
        ):
            return self._behavior(
                "likely",
                [
                    "5: body truncated while looking "
                    "like JSON"
                ],
            )

        if json_ct and stype == "unknown":
            return self._behavior(
                "likely",
                [
                    "6: JSON content type but body "
                    "could not be parsed"
                ],
            )

        if _is_xml_content(ct) and stype == "unknown":
            return self._behavior(
                "likely",
                [
                    "6b: XML content type but body "
                    "could not be parsed"
                ],
            )

        if json_ct and stype == "empty":
            return self._behavior(
                "uncertain",
                [
                    "7: JSON content type with empty body"
                ],
            )

        if container and not json_ct:
            return self._behavior(
                "likely",
                [
                    f"8: JSON {stype} served with "
                    "non-JSON content type"
                ],
            )

        if (
            stype == "binary"
            or ct in _JS_CSS_TYPES
        ):
            return self._behavior(
                "unlikely",
                [
                    "9: static/binary or "
                    "JavaScript/CSS response"
                ],
            )

        if stype == "xml":
            feed = struct.get("feed") if isinstance(
                struct, dict
            ) else None
            if feed:
                return self._behavior(
                    "uncertain",
                    [
                        f"10: {feed.upper()} feed response, "
                        "not an API"
                    ],
                )
            root = struct.get("root") if isinstance(
                struct, dict
            ) else None
            detail = f" (root <{root}>)" if root else ""
            if isinstance(struct, dict) and struct.get("fault"):
                op = struct.get("operation")
                return self._behavior(
                    "likely",
                    [
                        "10: SOAP fault response"
                        + (f" (operation {op})" if op else "")
                    ],
                )
            if isinstance(struct, dict) and struct.get("soap"):
                op = struct.get("operation")
                return self._behavior(
                    "likely",
                    [
                        "10: SOAP envelope response"
                        + (f" (operation {op})" if op else "")
                        + detail
                    ],
                )
            return self._behavior(
                "likely",
                [f"10: XML response{detail}"],
            )

        if (
            status in (401, 403, 405)
            and stype != "html"
            and (
                headers.get("www-authenticate")
                or headers.get("allow")
            )
        ):
            evidence = [
                f"11: status {status} with "
                "machine-readable error response"
            ]
            if headers.get("www-authenticate"):
                evidence.append(
                    "11: WWW-Authenticate header present"
                )
            if headers.get("allow"):
                evidence.append(
                    "11: Allow header present"
                )
            return self._behavior(
                "likely",
                evidence,
            )

        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(
                self._path_of(ctx["final_url"])
            )
        ):
            return self._behavior(
                "uncertain",
                [
                    "12: redirected to a login/"
                    "authentication path"
                ],
            )

        if status in (401, 403, 405):
            return self._behavior(
                "uncertain",
                [
                    f"13: status {status} indicates "
                    "restricted access"
                ],
            )

        if stype == "html":
            return self._behavior(
                "unlikely",
                ["14: HTML page response"],
            )

        return self._behavior(
            "uncertain",
            ["15: insufficient evidence to classify"],
        )

    @staticmethod
    def _behavior(
        classification: str,
        evidence: list[str],
    ) -> dict[str, Any]:
        return {
            "classification": classification,
            "evidence": evidence,
        }

    def _path_of(self, url: str) -> str:
        try:
            return urlsplit(url).path or ""
        except (ValueError, UnicodeError):
            return ""

    def _classify_access(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """FIRST MATCH WINS access classification."""
        status = ctx["status"]
        headers = ctx["headers"]

        if (
            status == 401
            or headers.get("www-authenticate")
        ):
            ev = []
            if status == 401:
                ev.append(
                    "1: status 401 Unauthorized"
                )
            if headers.get("www-authenticate"):
                ev.append(
                    "1: WWW-Authenticate header present"
                )
            return {
                "classification": "authentication_required",
                "evidence": ev,
            }

        if status == 403:
            return {
                "classification": "forbidden",
                "evidence": [
                    "2: status 403 Forbidden"
                ],
            }

        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(
                self._path_of(ctx["final_url"])
            )
        ):
            return {
                "classification": "authentication_required",
                "evidence": [
                    "3: redirected to a login/"
                    "authentication path"
                ],
            }

        if 200 <= status < 300:
            return {
                "classification": "public",
                "evidence": [
                    "4: 2xx response without "
                    "supplied credentials"
                ],
            }

        return {
            "classification": "unknown",
            "evidence": [
                "5: no access signal matched"
            ],
        }

    # -- result scaffolding -------------------------------------------------

    @staticmethod
    def _new_result() -> dict[str, Any]:
        """Canonical single-schema result with neutral defaults."""
        return {
            "url": None,
            "source": SOURCE_DEFAULT,
            "found_in": None,
            "method": None,
            "status": None,
            "status_category": None,
            "content_type": None,
            "parameters": [],
            "response_structure": None,
            "final_url": None,
            "redirected": False,
            "redirect_chain": [],
            "response_time_ms": None,
            "response_size": None,
            "response_size_truncated": False,
            "headers": {
                "content-length": None,
                "server": None,
                "allow": None,
                "www-authenticate": None,
                "location": None,
                "access-control-allow-origin": None,
            },
            "api_behavior": {
                "classification": "uncertain",
                "evidence": [],
            },
            "access": {
                "classification": "unknown",
                "evidence": [],
            },
            "warnings": [],
            "error": None,
        }


# ---------------------------------------------------------------------------
# Convenience function and minimal entry point
# ---------------------------------------------------------------------------

def analyze_discovery_file(
    input_path: str,
    output_path: str | None = None,
    **options: Any,
) -> list[dict[str, Any]]:
    """Build an EndpointAnalyzer, analyze the file, always close."""
    analyzer = EndpointAnalyzer(**options)
    try:
        return analyzer.analyze_discovery_file(
            input_path,
            output_path,
        )
    finally:
        analyzer.close()


def main(argv: list[str]) -> int:
    """Minimal entry point."""
    if len(argv) < 2:
        print(
            "usage: python endpoint_analysis.py "
            "<discovery.json> [analysis.json]",
            file=sys.stderr,
        )
        return 1

    input_path = argv[1]
    output_path = (
        argv[2]
        if len(argv) > 2
        else None
    )

    try:
        results = analyze_discovery_file(
            input_path,
            output_path,
        )
    except ValueError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(
            f"error: {type(exc).__name__}: "
            f"{exc.strerror or exc}",
            file=sys.stderr,
        )
        return 1

    if output_path is None:
        print(
            json.dumps(
                results,
                ensure_ascii=True,
                indent=2,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
