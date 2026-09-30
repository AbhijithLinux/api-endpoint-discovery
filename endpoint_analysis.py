from __future__ import annotations

import codecs
import html
import ipaddress
import json
import logging
import math
import re
import sys
import time
from typing import Any
from urllib.parse import (
    parse_qsl,
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

MAX_SCHEMA_DEPTH = 4
MAX_KEYS_PER_OBJECT = 50
MAX_ARRAY_ITEMS_TO_INSPECT = 5
CHUNK_SIZE = 8192

DEFAULT_MAX_RESPONSE_SIZE = 1_000_000

MAX_PARAM_EXAMPLE = 40
MAX_HEADER_VALUE = 200
MAX_FOUND_IN = 5
FOUND_IN_TRUNCATE = 300

BODY_READ_LIMIT = 1_000_000

REDACTED = "REDACTED"
SOURCE_DEFAULT = "endpoint_discovery"

SENSITIVE_PATTERNS = (
    "token", "access_token", "refresh_token", "id_token", "bearer",
    "api_key", "apikey", "key", "secret", "password", "passwd", "pwd",
    "auth", "authorization", "session", "sessionid", "cookie", "jwt",
    "csrf", "xsrf", "code", "signature", "credential", "private_key",
    "client_secret", "webhook_secret", "database_password", "db_password",
    "sid", "sig",
)

SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\b(?:eyJ[A-Za-z0-9_-]{5,}\.){2}[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
)
MAX_SENSITIVE_FINDINGS = 20
MAX_SENSITIVE_VALUE = 500


REDIRECT_STATUSES = {301, 302, 303, 307, 308}

LOGIN_PATH_RE = re.compile(
    r"(log-?in|sign-?in|sso|oauth2?|authorize)([/.]|$)", re.I
)
NUMERIC_SEG_RE = re.compile(r"\d+")
UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
HEX24_SEG_RE = re.compile(r"[0-9a-fA-F]{24}")

_BINARY_TYPES = {
    "application/pdf",
    "application/zip",
    "application/octet-stream",
    "application/wasm",
    "application/gzip",
    "application/x-gzip",
}

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
    """Passive endpoint analysis with bounded HTTP observation and explainable findings."""

    def __init__(
        self,
        timeout: float = 10,
        base_url: str | None = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        request_delay: float = 0.1,
        redact_sensitive: bool = False,
        send_sensitive_params: bool = False,
        options_probe: bool = True,
        allowed_hosts: list[str] | tuple[str, ...] | set[str] | None = None,
        allowed_redirect_hosts: list[str] | tuple[str, ...] | set[str] | None = None,
        inspect_sensitive_response_data: bool = True,
        max_sensitive_findings: int = MAX_SENSITIVE_FINDINGS,
    ) -> None:
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
        if type(max_sensitive_findings) is not int or max_sensitive_findings < 0:
            raise ValueError("max_sensitive_findings must be an integer >= 0")

        for numeric_name, numeric_value in (("timeout", timeout), ("max_response_size", max_response_size), ("request_delay", request_delay)):
            if isinstance(numeric_value, float) and not math.isfinite(numeric_value):
                raise ValueError(f"{numeric_name} must be finite")

        self.timeout = float(timeout)
        self.verify_ssl = bool(verify_ssl)
        self.follow_redirects = bool(follow_redirects)
        self.max_redirects = int(max_redirects)
        self.max_response_size = int(max_response_size)
        self.request_delay = float(request_delay)
        self.redact_sensitive = bool(redact_sensitive)
        self.send_sensitive_params = bool(send_sensitive_params)
        self.options_probe = bool(options_probe)
        self.allowed_hosts = self._normalize_host_set(allowed_hosts)
        self.allowed_redirect_hosts = self._normalize_host_set(allowed_redirect_hosts)
        self.inspect_sensitive_response_data = bool(inspect_sensitive_response_data)
        self.max_sensitive_findings = max_sensitive_findings

        self.base_url: str | None = None
        if base_url is not None:
            parsed = self._parse_http_url(str(base_url))
            if parsed is None:
                raise ValueError(f"invalid base_url: {base_url!r}")
            self.base_url = str(base_url).strip()

        self._session = requests.Session()
        self._session.trust_env = False
        self._session.headers.update({
            "User-Agent": "API-Endpoint-Analyzer/1.0",
            "Accept": "application/json, */*;q=0.8",
        })

        self._last_request_end: float | None = None
        self._wrapper_target: str | None = None

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

        error = self._validate_resolved(resolved, self.allowed_hosts)
        if error is not None:
            result["error"] = error
            return

        visible_url = self._rebuild(resolved)

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
        parts: tuple[str, str, str, str, str],
        allowed_hosts: set[str] | None = None,
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

        if allowed_hosts is not None and host not in allowed_hosts:
            return {
                "type": "host_not_allowed",
                "message": "URL hostname is not in allowed_hosts",
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
        norm = decoded.lower().replace("-", "").replace("_", "")
        return any(p in norm for p in SENSITIVE_PATTERNS)

    def _sanitize_query(
        self,
        url: str,
    ) -> tuple[str, str | None, bool]:
        """
        Blank sensitive query values while preserving original query encoding.
        """
        parts = urlsplit(url)
        if not parts.query:
            return url, None, False

        changed = False
        out: list[str] = []

        for pair in parts.query.split("&"):
            if not pair:
                continue

            name, sep, value = pair.partition("=")

            if (
                sep
                and value
                and self._is_sensitive_key(name)
                and not self.send_sensitive_params
            ):
                out.append(f"{name}=")
                changed = True
            else:
                out.append(pair)

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
        if not self.redact_sensitive:
            return url

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
        """Manual-redirect GET loop with optional OPTIONS fallback on 405."""
        current_url = initial_url
        chain: list[str] = [initial_url]
        redirect_host = self._redirect_host(initial_url)
        hops = 0
        connect_s = 0.0
        body_s = 0.0

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
                        continue

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

                    if status == 405 and self.options_probe:
                        try:
                            response.close()
                        except Exception:
                            pass

                        self._mark_request_done()
                        observed["options"] = self._perform_options(
                            current_url,
                            result,
                        )

                    return observed
                finally:
                    try:
                        response.close()
                    except Exception:
                        pass
                    self._mark_request_done()
        finally:
            try:
                self._session.cookies.clear()
            except Exception:
                pass

    def _perform_options(
        self,
        url: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Perform a lightweight OPTIONS probe after a 405 GET response."""
        try:
            self._throttle()
            logger.debug(
                "OPTIONS probe for %s",
                self._safe_log_url(url),
            )
            t0 = time.perf_counter()
            response = self._session.request(
                "OPTIONS",
                url,
                allow_redirects=False,
                stream=False,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            elapsed = time.perf_counter() - t0
            headers = {
                k.lower(): v
                for k, v in response.headers.items()
            }
            status = response.status_code

            try:
                response.close()
            except Exception:
                pass

            self._mark_request_done()
            return {
                "status": status,
                "headers": headers,
                "error": None,
                "elapsed_s": elapsed,
            }
        except Timeout as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "timeout",
                    "message": self._short(str(exc)),
                },
                "elapsed_s": None,
            }
        except SSLError as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "ssl_error",
                    "message": self._short(str(exc)),
                },
                "elapsed_s": None,
            }
        except (
            InvalidURL,
            InvalidSchema,
            MissingSchema,
        ) as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "invalid_url",
                    "message": self._short(str(exc)),
                },
                "elapsed_s": None,
            }
        except RequestsConnectionError as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "connection_error",
                    "message": self._short(str(exc)),
                },
                "elapsed_s": None,
            }
        except RequestException as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "request_error",
                    "message": self._short(str(exc)),
                },
                "elapsed_s": None,
            }
        except Exception as exc:
            self._mark_request_done()
            return {
                "status": None,
                "headers": {},
                "error": {
                    "type": "unexpected_error",
                    "message": self._short(
                        f"{type(exc).__name__}: {exc}"
                    ),
                },
                "elapsed_s": None,
            }

    def _short(self, message: str) -> str:
        message = message.replace("\n", " ").strip()
        # Requests exceptions can embed a full URL. Keep useful diagnostics while
        # preventing accidental query-string leakage when redaction is enabled.
        if self.redact_sensitive:
            try:
                message = re.sub(
                    r"(?i)([?&](?:[^=&]*?(?:token|key|secret|password|auth|session|cookie|jwt|code|signature|credential)[^=&]*)=)[^&\s]+",
                    r"\1" + REDACTED,
                    message,
                )
            except re.error:
                pass
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

        if not thost:
            return None, "redirect target has no hostname"

        if tport is None:
            tport = 443 if scheme == "https" else 80

        if origin is not None:
            oscheme, ohost, oport = origin

            same_site = self._same_site_host(thost, ohost)
            explicitly_allowed = self._host_allowed(thost, self.allowed_redirect_hosts)
            if not same_site and not explicitly_allowed:
                return None, "redirect target is on a different host"

            upgrade = oscheme == "http" and scheme == "https"

            if scheme != oscheme and not upgrade:
                return None, "redirect target changes scheme"

            if tport != oport and not upgrade and not explicitly_allowed:
                return None, "redirect target changes port"

            if self.allowed_hosts is not None and not self._host_allowed(thost, self.allowed_hosts):
                return None, "redirect target hostname is not in allowed_hosts"

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                parts.query,
                "",
            )
        ), None

    def _read_body(
        self,
        response: requests.Response,
        headers: dict[str, str],
        content_type: str | None,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Read at most max_response_size RAW bytes.
        """
        raw_size = 0
        truncated = False
        deadline_exceeded = False
        chunks: list[str] = []
        collected_chars = 0
        deadline = time.monotonic() + self.timeout
        decoder = codecs.getincrementaldecoder("utf-8-sig")("replace")

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

                if collected_chars < BODY_READ_LIMIT:
                    piece = decoder.decode(raw)
                    remaining_chars = (
                        BODY_READ_LIMIT - collected_chars
                    )
                    if len(piece) > remaining_chars:
                        piece = piece[:remaining_chars]
                    if piece:
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
        finally:
            try:
                if collected_chars < BODY_READ_LIMIT:
                    final_piece = decoder.decode(b"", final=True)
                    remaining_chars = (
                        BODY_READ_LIMIT - collected_chars
                    )
                    if len(final_piece) > remaining_chars:
                        final_piece = final_piece[:remaining_chars]
                    if final_piece:
                        chunks.append(final_piece)
                        collected_chars += len(final_piece)
            except Exception:
                pass

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
            "size": raw_size,
            "truncated": truncated,
            "deadline": deadline_exceeded,
        }

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

        options = net.get("options")
        if options is not None:
            opt_headers = self._extract_headers(
                options.get("headers", {})
            )
            opt_elapsed = options.get("elapsed_s")
            result["options_probe"] = {
                "status": options.get("status"),
                "headers": opt_headers,
                "error": options.get("error"),
                "response_time_ms": (
                    round(opt_elapsed * 1000, 1)
                    if opt_elapsed is not None
                    else None
                ),
            }
            if options.get("error"):
                result["warnings"].append(
                    "OPTIONS probe failed: "
                    f"{options['error'].get('type', 'unknown')}"
                )
        else:
            result["options_probe"] = None

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
        result["sensitive_findings"] = self._extract_sensitive_findings(
            body, content_type, result
        )

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
            "options": result.get("options_probe"),
        }

        result["api_behavior"] = (
            self._classify_api_behavior(ctx)
        )
        result["access"] = self._classify_access(ctx)
        result["security_posture"] = (
            self._classify_security_posture(ctx)
        )

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
            "access-control-allow-methods",
            "access-control-allow-credentials",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "cache-control",
            "vary",
            "retry-after",
            "server-timing",
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

    def _extract_parameters(
        self,
        url: str,
    ) -> list[dict[str, Any]]:
        """Visible query parameters."""
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

            if self._is_sensitive_key(name) and self.redact_sensitive:
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
                "sensitive": self._is_sensitive_key(name),
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
            elif HEX24_SEG_RE.fullmatch(seg):
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

    @staticmethod
    def _is_graphql_payload(parsed: Any) -> bool:
        """Heuristic detection of GraphQL-shaped JSON payloads."""
        if not isinstance(parsed, dict):
            return False

        if "__schema" in parsed:
            return True

        if "data" in parsed and "errors" in parsed:
            return True

        errors = parsed.get("errors")
        if isinstance(errors, list) and errors:
            return any(
                isinstance(item, dict) and "message" in item
                for item in errors[:5]
            )

        return False

    def _detect_structure(
        self,
        body: str,
        content_type: str | None,
        net: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Response-structure detection."""
        if body is None:
            return None

        stripped = body.strip()

        if not stripped:
            if _is_json_content(content_type):
                result["warnings"].append(
                    "empty JSON body"
                )
            return {"type": "empty"}

        if _is_binary_content(content_type):
            return {"type": "binary"}

        json_ct = _is_json_content(content_type)
        starts_json = stripped[0] in "{["

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

                struct = self._infer_structure(
                    parsed,
                    1,
                )

                if self._is_graphql_payload(parsed):
                    if isinstance(struct, dict):
                        struct["api_hint"] = "graphql"

                return struct

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

        if (
            _is_xml_content(content_type)
            or stripped.lower().startswith("<?xml")
        ):
            return {"type": "xml"}

        if (
            content_type == "text/html"
            or self._looks_like_html(stripped)
        ):
            return {"type": "html"}

        if (
            (content_type or "").startswith("text/")
            or content_type in _JS_CSS_TYPES
        ):
            return {"type": "text"}

        return {"type": "unknown"}

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

    def _parsed_container(
        self,
        struct: dict[str, Any] | None,
    ) -> bool:
        return (
            isinstance(struct, dict)
            and struct.get("type") in ("object", "array")
        )

    def _normalize_host_set(
        self,
        hosts: list[str] | tuple[str, ...] | set[str] | None,
    ) -> set[str] | None:
        if hosts is None:
            return None
        normalized: set[str] = set()
        for raw in hosts:
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("host allowlists must contain non-empty strings")
            value = raw.strip().lower().rstrip(".")
            if "://" in value:
                try:
                    parsed = urlsplit(value)
                    value = (parsed.hostname or "").lower().rstrip(".")
                except (ValueError, UnicodeError):
                    value = ""
            if value.startswith("[") and value.endswith("]"):
                value = value[1:-1]
            if not value:
                raise ValueError("invalid host in allowlist")
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                pass
            normalized.add(value)
        return normalized

    @staticmethod
    def _host_allowed(host: str, allowed: set[str] | None) -> bool:
        if allowed is None:
            return True
        h = host.lower().rstrip(".")
        return h in allowed

    @staticmethod
    def _same_site_host(a: str, b: str) -> bool:
        a = a.lower().rstrip(".")
        b = b.lower().rstrip(".")
        if a == b:
            return True
        return (
            a.removeprefix("www.") == b.removeprefix("www.")
            and (a.startswith("www.") or b.startswith("www."))
        )

    def _extract_sensitive_findings(
        self,
        body: str | None,
        content_type: str | None,
        result: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Find likely secret-bearing response fields without retaining the whole body."""
        if not body or not self.inspect_sensitive_response_data:
            return []

        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        def add(path: str, value: Any, reason: str) -> None:
            if len(findings) >= self.max_sensitive_findings:
                return
            key = (path, reason)
            if key in seen:
                return
            seen.add(key)
            if self.redact_sensitive:
                shown: Any = REDACTED
            elif isinstance(value, (str, int, float, bool)) or value is None:
                shown = self._truncate(str(value), MAX_SENSITIVE_VALUE)
            else:
                shown = f"<{type(value).__name__}>"
            findings.append({
                "path": path,
                "reason": reason,
                "value": shown,
            })

        parsed_ok, parsed = self._try_parse_json(body)
        if parsed_ok:
            def walk(value: Any, path: str, depth: int = 0) -> None:
                if len(findings) >= self.max_sensitive_findings or depth > MAX_SCHEMA_DEPTH + 2:
                    return
                if isinstance(value, dict):
                    for key, child in value.items():
                        key_text = str(key)
                        child_path = f"{path}.{key_text}" if path else key_text
                        if self._is_sensitive_key(key_text):
                            add(child_path, child, "sensitive field name")
                        walk(child, child_path, depth + 1)
                elif isinstance(value, list):
                    for idx, child in enumerate(value[:MAX_ARRAY_ITEMS_TO_INSPECT]):
                        walk(child, f"{path}[{idx}]", depth + 1)
            walk(parsed, "")

        # Also identify high-confidence token formats in non-JSON text.
        for pattern in SENSITIVE_VALUE_PATTERNS:
            if len(findings) >= self.max_sensitive_findings:
                break
            for match in pattern.finditer(body):
                add(f"<text:{match.start()}>", match.group(0), "high-confidence secret pattern")
                if len(findings) >= self.max_sensitive_findings:
                    break

        if findings:
            result["warnings"].append(
                f"{len(findings)} sensitive response finding(s) detected; response body itself was not stored"
            )
        return findings

    def _classify_api_behavior(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Weighted API-behavior classification.
        """
        struct = ctx["struct"]
        ct = ctx["content_type"]
        status = ctx["status"]
        body = ctx["body"]
        headers = ctx["headers"]
        options = ctx.get("options") or {}

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
        api_hint = (
            struct.get("api_hint")
            if isinstance(struct, dict)
            else None
        )

        scores = {
            "confirmed": 0,
            "likely": 0,
            "uncertain": 0,
            "unlikely": 0,
        }
        evidence: list[str] = []

        def add(
            classification: str,
            weight: int,
            message: str,
        ) -> None:
            scores[classification] += weight
            evidence.append(
                f"{classification} +{weight}: {message}"
            )

        if stype is None:
            add(
                "uncertain",
                100,
                "request failed or response body unavailable",
            )

        if (
            container
            and json_ct
            and status not in (404, 410)
        ):
            add(
                "confirmed",
                100,
                f"JSON {stype} returned with JSON content type "
                f"(status {status})",
            )

        if api_hint == "graphql":
            if json_ct:
                add(
                    "confirmed",
                    45,
                    "GraphQL-style JSON payload detected",
                )
            else:
                add(
                    "likely",
                    35,
                    "GraphQL-style payload without JSON content type",
                )

        if container and status in (404, 410):
            add(
                "likely",
                75,
                f"JSON {stype} returned with error status {status}",
            )

        if primitive_json:
            add(
                "likely",
                60,
                "JSON primitive with JSON content type",
            )

        looks_json = (
            isinstance(body, str)
            and body.lstrip()[:1] in "{["
        )
        if (
            (ctx["truncated"] or ctx.get("deadline"))
            and (json_ct or looks_json)
        ):
            add(
                "likely",
                55,
                "body truncated while looking like JSON",
            )

        if json_ct and stype == "unknown":
            add(
                "likely",
                50,
                "JSON content type but body could not be parsed",
            )

        if json_ct and stype == "empty":
            add(
                "uncertain",
                35,
                "JSON content type with empty body",
            )

        if container and not json_ct:
            add(
                "likely",
                55,
                f"JSON {stype} served with non-JSON content type",
            )

        opt_status = options.get("status")
        opt_headers = options.get("headers") or {}
        opt_allow = opt_headers.get("allow") or ""
        opt_acam = opt_headers.get(
            "access-control-allow-methods"
        ) or ""

        if opt_status in (200, 204) and (opt_allow or opt_acam):
            add(
                "likely",
                85,
                f"OPTIONS probe returned {opt_status} with allowed methods",
            )

            methods: set[str] = set()
            for value in (
                opt_allow,
                opt_acam,
                headers.get("allow"),
            ):
                if not value:
                    continue
                for item in str(value).split(","):
                    item = item.strip().upper()
                    if item:
                        methods.add(item)

            if methods - {"GET", "HEAD", "OPTIONS"}:
                add(
                    "confirmed",
                    20,
                    "OPTIONS probe advertises non-GET methods",
                )

        if (
            stype == "binary"
            or ct in _JS_CSS_TYPES
        ):
            add(
                "unlikely",
                100,
                "static/binary or JavaScript/CSS response",
            )

        if stype == "xml":
            add(
                "likely",
                65,
                "XML response",
            )

        if (
            status in (401, 403, 405)
            and stype != "html"
            and (
                headers.get("www-authenticate")
                or headers.get("allow")
            )
        ):
            add(
                "likely",
                80,
                f"status {status} with machine-readable API signal",
            )
            if headers.get("www-authenticate"):
                add(
                    "likely",
                    10,
                    "WWW-Authenticate header present",
                )
            if headers.get("allow"):
                add(
                    "likely",
                    10,
                    "Allow header present",
                )

        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(
                self._path_of(ctx["final_url"])
            )
        ):
            add(
                "uncertain",
                65,
                "redirected to a login/authentication path",
            )

        if status in (401, 403, 405):
            add(
                "uncertain",
                45,
                f"status {status} indicates restricted access",
            )

        if stype == "html":
            if status in (401, 403, 405):
                add(
                    "uncertain",
                    70,
                    "HTML response with restricted status",
                )
            else:
                add(
                    "unlikely",
                    95,
                    "HTML page response",
                )

        if stype == "text":
            add(
                "uncertain",
                25,
                "plain text or static text-like response",
            )

        if not evidence:
            add(
                "uncertain",
                1,
                "insufficient evidence to classify",
            )

        order = ("confirmed", "likely", "uncertain", "unlikely")
        best = max(
            order,
            key=lambda name: (scores[name], -order.index(name)),
        )
        return self._behavior(best, evidence)

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

    def _scheme_of(self, url: str) -> str:
        try:
            return urlsplit(url).scheme.lower()
        except (ValueError, UnicodeError):
            return ""

    def _classify_access(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """Weighted access classification."""
        status = ctx["status"]
        headers = ctx["headers"]

        scores = {
            "authentication_required": 0,
            "forbidden": 0,
            "public": 0,
            "unknown": 0,
        }
        evidence: list[str] = []

        def add(
            classification: str,
            weight: int,
            message: str,
        ) -> None:
            scores[classification] += weight
            evidence.append(
                f"{classification} +{weight}: {message}"
            )

        if (
            status == 401
            or headers.get("www-authenticate")
        ):
            if status == 401:
                add(
                    "authentication_required",
                    100,
                    "status 401 Unauthorized",
                )
            if headers.get("www-authenticate"):
                add(
                    "authentication_required",
                    20,
                    "WWW-Authenticate header present",
                )

        if status == 403:
            add(
                "forbidden",
                95,
                "status 403 Forbidden",
            )

        if (
            ctx["followed_same_host"]
            and LOGIN_PATH_RE.search(
                self._path_of(ctx["final_url"])
            )
        ):
            add(
                "authentication_required",
                85,
                "redirected to a login/authentication path",
            )

        if 200 <= status < 300:
            add(
                "public",
                80,
                "2xx response without supplied credentials",
            )

        if not evidence:
            add(
                "unknown",
                1,
                "no access signal matched",
            )

        order = (
            "authentication_required",
            "forbidden",
            "public",
            "unknown",
        )
        best = max(
            order,
            key=lambda name: (scores[name], -order.index(name)),
        )

        return {
            "classification": best,
            "evidence": evidence,
        }

    def _classify_security_posture(
        self,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        """Context-aware passive security-header/CORS posture observations."""
        headers = ctx["headers"]
        final_url = ctx["final_url"]
        scheme = self._scheme_of(final_url)
        struct = ctx.get("struct") or {}
        is_html = struct.get("type") == "html"
        is_browser_facing = is_html or ctx.get("status") in (401, 403)

        issues: list[str] = []
        evidence: list[str] = []
        observations: list[str] = []

        acao = (headers.get("access-control-allow-origin") or "").strip()
        acac = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
        if acao == "*":
            observations.append("CORS wildcard origin is enabled")
            if acac:
                issues.append("cors_wildcard_with_credentials_signal")
                evidence.append(
                    "Access-Control-Allow-Origin is '*' and credentials are advertised; browsers normally reject credentialed wildcard CORS"
                )

        if acao and acao != "*":
            observations.append(f"CORS allows explicit origin: {self._truncate(acao, MAX_HEADER_VALUE)}")

        hsts = headers.get("strict-transport-security")
        if scheme == "https":
            if hsts:
                observations.append("HSTS is present on HTTPS response")
            else:
                issues.append("missing_hsts")
                evidence.append("HTTPS response is missing Strict-Transport-Security")

        xcto = (headers.get("x-content-type-options") or "").strip().lower()
        if xcto == "nosniff":
            observations.append("X-Content-Type-Options: nosniff")
        elif is_browser_facing:
            issues.append("missing_or_invalid_x_content_type_options")
            evidence.append("browser-facing response is missing X-Content-Type-Options: nosniff")

        if is_browser_facing:
            if headers.get("content-security-policy"):
                observations.append("Content-Security-Policy is present")
            else:
                issues.append("missing_csp")
                evidence.append("browser-facing response is missing Content-Security-Policy")

            if headers.get("x-frame-options"):
                observations.append("X-Frame-Options is present")
            else:
                issues.append("missing_x_frame_options")
                evidence.append("browser-facing response is missing X-Frame-Options")

        if headers.get("cache-control"):
            observations.append(f"Cache-Control: {self._truncate(headers['cache-control'], MAX_HEADER_VALUE)}")

        if issues:
            classification = "risky" if any("cors_" in i for i in issues) else "needs_review"
        elif scheme == "https":
            classification = "hardened"
            evidence.append("No basic passive security-header issue was observed")
        else:
            classification = "unknown"
            evidence.append("Passive header checks did not establish a hardened HTTPS posture")

        return {
            "classification": classification,
            "issues": issues,
            "observations": observations,
            "evidence": evidence,
        }

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
                "access-control-allow-methods": None,
                "access-control-allow-credentials": None,
                "strict-transport-security": None,
                "x-content-type-options": None,
                "x-frame-options": None,
                "content-security-policy": None,
            },
            "options_probe": None,
            "api_behavior": {
                "classification": "uncertain",
                "evidence": [],
            },
            "access": {
                "classification": "unknown",
                "evidence": [],
            },
            "security_posture": {
                "classification": "unknown",
                "issues": [],
                "observations": [],
                "evidence": [],
            },
            "sensitive_findings": [],
            "warnings": [],
            "error": None,
        }


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
