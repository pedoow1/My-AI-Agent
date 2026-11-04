import os
import re
import random
import string
import urllib.request
import urllib.error
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Tuple
from .base import Agent
from ..models import Finding, Severity

# --- Active probing tuning (keep polite + bounded, even on a long mission) ---
MAX_CRAWL_PAGES = 10
MAX_FORMS_PER_PAGE = 5
MAX_PARAMS_PER_TARGET = 8
MAX_ACTIVE_REQUESTS = 80
REQUEST_TIMEOUT = 8
MAX_BODY_BYTES = 400_000

SQLI_PAYLOADS = ["'", "' OR '1'='1"]

# Common error-based SQLi signatures across major DB engines. This is a
# well-known, publicly documented category of error strings (used by tools
# like sqlmap/Nikto), reproduced here in our own minimal form for detection.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"sqlstate\[",
    r"pg_query\(\)\s*:",
    r"postgresql.*error",
    r"ora-\d{5}",
    r"microsoft (odbc|ole db|jet database)",
    r"sqlite3\.(operationalerror|programmingerror)",
    r"system\.data\.sqlclient",
    r"syntax error.*near",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

LINK_RE = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)
FORM_BLOCK_RE = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
INPUT_NAME_RE = re.compile(r'<(?:input|textarea|select)\b[^>]*\bname=["\']([^"\']+)["\']', re.IGNORECASE)


class WebVulnScanAgent(Agent):
    def __init__(self):
        super().__init__(
            name="WebVulnScanAgent",
            description="Performs advanced web vulnerability scanning (OWASP Top 10 SAST, SQLi, XSS, SSRF, Path Traversal, weak JWT secrets, insecure CORS, and HTTP security header/cookie audits)."
        )
        self.sql_injection_pattern = re.compile(
            r"(execute|query|raw)\s*\(\s*(f['\"'].*SELECT|['\"'].*SELECT.*%|['\"'].*SELECT.*\+|\bSELECT\b.*\b(request|req|params|query|input)\b)",
            re.IGNORECASE
        )
        self.xss_pattern = re.compile(
            r"(dangerouslySetInnerHTML|innerHTML\s*=|render_template_string\s*\(|v-html\s*=|res\.(send|render)\s*\(\s*(req\.query|req\.body|request\.args|request\.form))",
            re.IGNORECASE
        )
        self.ssrf_pattern = re.compile(
            r"(requests\.(get|post|request)|axios\.(get|post)|fetch|urlopen)\s*\(\s*(req\.|request\.|params\.|query\.|input\b)",
            re.IGNORECASE
        )
        self.path_traversal_pattern = re.compile(
            r"(open\s*\(\s*(req\.|request\.|params\.|query\.|filename|path)|fs\.(readFile|readFileSync)\s*\(\s*(req\.|request\.|params\.|query\.|filename))",
            re.IGNORECASE
        )
        self.weak_jwt_pattern = re.compile(
            r"(jwt\.sign\s*\(.*['\"](secret|password|123456|changeme|key)['\"]|JWT_SECRET\s*=\s*['\"](secret|password|123456)['\"])",
            re.IGNORECASE
        )
        self.insecure_cors_pattern = re.compile(
            r"(Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}\)|cors\s*\(\s*\))",
            re.IGNORECASE
        )
        self.ssti_pattern = re.compile(
            r"(render_template_string|Jinja2|ejs\.render|Handlebars\.compile)\s*\(.*(req\.|request\.|params\.|query\.|input)",
            re.IGNORECASE
        )
        self.prototype_pollution_pattern = re.compile(
            r"(Object\.assign\s*\(.*req\.|lodash\.merge\s*\(.*req\.|deepMerge\s*\(.*req\.|\[\s*req\..*\]\s*=)",
            re.IGNORECASE
        )
        self.bola_idor_pattern = re.compile(
            r"(find|findById|findOne|getById|query)\s*\(\s*(req\.params|req\.query|request\.args|params\.)",
            re.IGNORECASE
        )
        self.deserialization_pattern = re.compile(
            r"(pickle\.loads?|yaml\.load\s*\((?!.*SafeLoader)|unserialize\s*\()",
            re.IGNORECASE
        )
        self.jwt_verify_pattern = re.compile(
            r"jwt\.verify\s*\([^)]*\b(?!algorithms)\b[^)]*\)",
            re.IGNORECASE
        )
        self._request_budget = MAX_ACTIVE_REQUESTS

    def run(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        active = bool(context.get("active"))
        self._request_budget = MAX_ACTIVE_REQUESTS

        # Check if target is a URL
        if target.startswith(("http://", "https://")):
            findings.extend(self._audit_url(target, active=active))
        elif os.path.exists(target):
            if os.path.isfile(target):
                findings.extend(self._audit_file(target))
            elif os.path.isdir(target):
                for root, _, files in os.walk(target):
                    if any(part.startswith('.') for part in root.split(os.sep)):
                        continue
                    for file in files:
                        file_path = os.path.join(root, file)
                        findings.extend(self._audit_file(file_path))

        return findings

    def _audit_file(self, file_path: str) -> List[Finding]:
        findings: List[Finding] = []
        basename = os.path.basename(file_path).lower()

        if not basename.endswith((".py", ".js", ".ts", ".php", ".rb", ".html", ".jsx", ".tsx", ".vue", ".env", ".json", ".yml", ".yaml", ".conf")):
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                for idx, line in enumerate(lines, start=1):
                    # SQL Injection check
                    if self.sql_injection_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-SQLI-{idx}",
                            title="Potential SQL Injection (SQLi) Vulnerability",
                            severity=Severity.CRITICAL,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected raw SQL query construction with unvalidated input on line {idx}.",
                            remediation="Use parameterized queries, prepared statements, or ORM query builders (e.g., SQLAlchemy, Prisma, TypeORM) instead of string formatting/concatenation.",
                            cvss_score=9.3
                        ))

                    # Cross-Site Scripting (XSS) check
                    if self.xss_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-XSS-{idx}",
                            title="Potential Cross-Site Scripting (XSS) Vulnerability",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected direct rendering or assignment of unescaped user input on line {idx}.",
                            remediation="Sanitize all user-supplied data before rendering in templates or DOM (e.g. DOMPurify, auto-escaping template engines).",
                            cvss_score=8.1
                        ))

                    # SSRF check
                    if self.ssrf_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-SSRF-{idx}",
                            title="Potential Server-Side Request Forgery (SSRF)",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected outgoing HTTP request using unvalidated user input URL on line {idx}.",
                            remediation="Implement strict URL allowlisting, validate and sanitize destination URLs, and block requests to internal private IP ranges (RFC 1918).",
                            cvss_score=8.6
                        ))

                    # Path Traversal / LFI check
                    if self.path_traversal_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-TRAVERSAL-{idx}",
                            title="Potential Path Traversal / Local File Inclusion (LFI)",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected file operation using user-supplied path parameter on line {idx}.",
                            remediation="Use `os.path.basename`, resolve paths against a safe root directory, and validate that resolved paths stay within allowed boundaries.",
                            cvss_score=8.5
                        ))

                    # Weak JWT Secret check
                    if self.weak_jwt_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-JWT-{idx}",
                            title="Weak or Hardcoded JWT Secret / Key",
                            severity=Severity.CRITICAL,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected hardcoded weak JWT signing secret or key on line {idx}.",
                            remediation="Use strong, cryptographically secure random secrets (at least 256 bits) loaded exclusively from secure environment variables.",
                            cvss_score=9.1
                        ))

                    # Insecure CORS check
                    if self.insecure_cors_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-CORS-{idx}",
                            title="Overly Permissive CORS Policy",
                            severity=Severity.MEDIUM,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected wildcard or overly permissive CORS configuration on line {idx}.",
                            remediation="Restrict CORS origins to trusted domains explicitly rather than using '*' or allowing arbitrary origins with credentials.",
                            cvss_score=6.5
                        ))

                    # Server-Side Template Injection (SSTI) check
                    if self.ssti_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-SSTI-{idx}",
                            title="Potential Server-Side Template Injection (SSTI)",
                            severity=Severity.CRITICAL,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected dynamic template rendering with unvalidated user input on line {idx}.",
                            remediation="Pass user input strictly as template context variables rather than evaluating untrusted template strings.",
                            cvss_score=9.8
                        ))

                    # Prototype Pollution check
                    if self.prototype_pollution_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-PROTO-{idx}",
                            title="Potential Prototype Pollution Vulnerability",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected unsafe recursive object merge or property assignment on line {idx}.",
                            remediation="Freeze object prototypes (`Object.freeze`), validate property keys against '__proto__', 'constructor', 'prototype', or use safe lodash clone methods.",
                            cvss_score=8.7
                        ))

                    # BOLA / IDOR check
                    if self.bola_idor_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-BOLA-{idx}",
                            title="Potential Broken Object-Level Authorization (BOLA / IDOR)",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected database query using client-supplied object ID parameters without explicit authorization verification on line {idx}.",
                            remediation="Implement robust server-side authorization checks verifying that the authenticated user owns or has permissions to access the requested object ID.",
                            cvss_score=8.8
                        ))

                    # Insecure Deserialization check
                    if self.deserialization_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-DESERIALIZE-{idx}",
                            title="Insecure Deserialization Vulnerability",
                            severity=Severity.CRITICAL,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected unsafe deserialization mechanism (pickle/yaml/unserialize) on line {idx}.",
                            remediation="Avoid deserializing untrusted data. Use safe formats like JSON or safe loaders (e.g. `yaml.safe_load`).",
                            cvss_score=9.8
                        ))

                    # Insecure JWT Verification check
                    if self.jwt_verify_pattern.search(line):
                        findings.append(Finding(
                            id=f"WEB-JWT-VERIFY-{idx}",
                            title="Insecure JWT Verification (Missing Algorithm Restriction)",
                            severity=Severity.HIGH,
                            agent=self.name,
                            file_path=file_path,
                            line_number=idx,
                            description=f"Detected `jwt.verify` without explicit allowed algorithms specification on line {idx}.",
                            remediation="Explicitly specify allowed algorithms (e.g., `algorithms=['HS256']`) in `jwt.verify` to prevent algorithm substitution attacks.",
                            cvss_score=8.1
                        ))
        except Exception:
            pass

        return findings

    def _audit_url(self, url: str, active: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        body = ""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberSentinel-WebVulnScanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}
                try:
                    body = response.read(MAX_BODY_BYTES).decode("utf-8", errors="ignore")
                except Exception:
                    body = ""
                
                # Check security headers
                if "content-security-policy" not in headers:
                    findings.append(Finding(
                        id="WEB-HDR-CSP",
                        title="Missing Content Security Policy (CSP) Header",
                        severity=Severity.MEDIUM,
                        agent=self.name,
                        file_path=url,
                        description="Target web application is missing the Content-Security-Policy header, increasing vulnerability to XSS and data injection attacks.",
                        remediation="Implement a strong Content-Security-Policy response header.",
                        cvss_score=5.3
                    ))

                if "strict-transport-security" not in headers and url.startswith("https://"):
                    findings.append(Finding(
                        id="WEB-HDR-HSTS",
                        title="Missing HTTP Strict Transport Security (HSTS) Header",
                        severity=Severity.MEDIUM,
                        agent=self.name,
                        file_path=url,
                        description="HTTPS target is missing the Strict-Transport-Security (HSTS) header.",
                        remediation="Add HSTS header with appropriate max-age and includeSubDomains directives.",
                        cvss_score=5.0
                    ))

                if "x-frame-options" not in headers:
                    findings.append(Finding(
                        id="WEB-HDR-XFO",
                        title="Missing X-Frame-Options Header",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=url,
                        description="Target web application is missing the X-Frame-Options header, risking Clickjacking attacks.",
                        remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                        cvss_score=4.3
                    ))

                if "x-content-type-options" not in headers:
                    findings.append(Finding(
                        id="WEB-HDR-XCTO",
                        title="Missing X-Content-Type-Options Header",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=url,
                        description="Target web application is missing 'X-Content-Type-Options: nosniff' header.",
                        remediation="Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
                        cvss_score=3.7
                    ))

                if "permissions-policy" not in headers:
                    findings.append(Finding(
                        id="WEB-HDR-PERMISSIONS",
                        title="Missing Permissions-Policy Header",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=url,
                        description="Target application is missing the Permissions-Policy header, which restricts browser features and APIs.",
                        remediation="Implement a Permissions-Policy header to control browser API access.",
                        cvss_score=3.5
                    ))

                if "referrer-policy" not in headers:
                    findings.append(Finding(
                        id="WEB-HDR-REFERRER",
                        title="Missing Referrer-Policy Header",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=url,
                        description="Target application is missing the Referrer-Policy header, potentially leaking sensitive URL paths in Referer headers.",
                        remediation="Set a strict Referrer-Policy such as 'strict-origin-when-cross-origin'.",
                        cvss_score=3.1
                    ))

                if "server" in headers or "x-powered-by" in headers:
                    server_val = headers.get("server", headers.get("x-powered-by", ""))
                    findings.append(Finding(
                        id="WEB-HDR-DISCLOSURE",
                        title="Server Software Version Disclosure",
                        severity=Severity.LOW,
                        agent=self.name,
                        file_path=url,
                        description=f"Response headers disclose underlying server/framework software version: '{server_val}'.",
                        remediation="Disable or obfuscate detailed server and framework version headers in production.",
                        cvss_score=4.0
                    ))

                # Check CORS header in response
                acao = headers.get("access-control-allow-origin", "")
                if acao == "*":
                    findings.append(Finding(
                        id="WEB-HDR-CORS",
                        title="Insecure Wildcard CORS Header (*)",
                        severity=Severity.MEDIUM,
                        agent=self.name,
                        file_path=url,
                        description="Response specifies 'Access-Control-Allow-Origin: *', allowing any origin to read sensitive response data.",
                        remediation="Specify trusted specific origins instead of wildcard '*' when handling authenticated or sensitive data.",
                        cvss_score=6.5
                    ))

                # Check Set-Cookie headers for security flags
                set_cookies = response.headers.get_all("Set-Cookie") if hasattr(response.headers, "get_all") else []
                if not set_cookies:
                    # Fallback check
                    raw_headers = response.headers._headers
                    set_cookies = [v for k, v in raw_headers if k.lower() == "set-cookie"]

                for cookie in set_cookies:
                    cookie_lower = cookie.lower()
                    if "httponly" not in cookie_lower:
                        findings.append(Finding(
                            id="WEB-COOKIE-HTTPONLY",
                            title="Cookie Missing HttpOnly Flag",
                            severity=Severity.MEDIUM,
                            agent=self.name,
                            file_path=url,
                            description=f"Detected cookie lacking the 'HttpOnly' flag: {cookie[:50]}...",
                            remediation="Set the 'HttpOnly' attribute on sensitive cookies to prevent client-side script access (XSS mitigation).",
                            cvss_score=5.4
                        ))
                    if "secure" not in cookie_lower and url.startswith("https://"):
                        findings.append(Finding(
                            id="WEB-COOKIE-SECURE",
                            title="Cookie Missing Secure Flag",
                            severity=Severity.MEDIUM,
                            agent=self.name,
                            file_path=url,
                            description=f"Detected cookie lacking the 'Secure' flag over HTTPS: {cookie[:50]}...",
                            remediation="Set the 'Secure' attribute on cookies to ensure they are only transmitted over encrypted connections.",
                            cvss_score=5.0
                        ))
                    if "samesite" not in cookie_lower:
                        findings.append(Finding(
                            id="WEB-COOKIE-SAMESITE",
                            title="Cookie Missing SameSite Attribute",
                            severity=Severity.LOW,
                            agent=self.name,
                            file_path=url,
                            description=f"Detected cookie lacking the 'SameSite' attribute: {cookie[:50]}...",
                            remediation="Set 'SameSite=Lax' or 'SameSite=Strict' to mitigate Cross-Site Request Forgery (CSRF).",
                            cvss_score=4.3
                        ))

        except urllib.error.URLError:
            pass
        except Exception:
            pass

        if active:
            findings.extend(self._active_probe(url, body))

        return findings

    # ------------------------------------------------------------------
    # Active probing: crawl same-origin pages/forms and inject lightweight,
    # well-known test payloads to confirm SQLi/XSS rather than only
    # checking response headers. Bounded by MAX_* constants so even a long
    # mission stays polite to the target.
    # ------------------------------------------------------------------

    def _fetch(self, url: str, method: str = "GET", data: Optional[bytes] = None) -> Tuple[Optional[str], Optional[int]]:
        if self._request_budget <= 0:
            return None, None
        self._request_budget -= 1
        try:
            req = urllib.request.Request(
                url, data=data, method=method,
                headers={"User-Agent": "CyberSentinel-WebVulnScanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                raw = resp.read(MAX_BODY_BYTES)
                return raw.decode("utf-8", errors="ignore"), resp.status
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(MAX_BODY_BYTES)
                return raw.decode("utf-8", errors="ignore"), e.code
            except Exception:
                return None, e.code
        except Exception:
            return None, None

    @staticmethod
    def _same_origin(base_url: str, candidate: str) -> bool:
        b, c = urlparse(base_url), urlparse(candidate)
        return c.scheme in ("http", "https") and c.netloc == b.netloc

    def _extract_links(self, base_url: str, body: str) -> List[str]:
        links = []
        for m in LINK_RE.finditer(body or ""):
            absolute = urljoin(base_url, m.group(1)).split("#")[0]
            if self._same_origin(base_url, absolute) and absolute not in links:
                links.append(absolute)
        return links

    @staticmethod
    def _extract_forms(base_url: str, body: str) -> List[Dict[str, Any]]:
        forms = []
        for m in FORM_BLOCK_RE.finditer(body or ""):
            attrs, inner = m.group(1), m.group(2)
            action_m = ACTION_RE.search(attrs)
            method_m = METHOD_RE.search(attrs)
            action = urljoin(base_url, action_m.group(1)) if action_m else base_url
            method = (method_m.group(1).lower() if method_m else "get")
            names = list(dict.fromkeys(INPUT_NAME_RE.findall(inner)))  # de-dup, keep order
            if names:
                forms.append({"action": action, "method": method, "params": names[:MAX_PARAMS_PER_TARGET]})
        return forms

    @staticmethod
    def _set_query_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def _probe_reflection_and_sqli(self, send, param: str, marker: str) -> List[Finding]:
        """send(payload) -> (body, status, locator). Shared GET/POST probe logic."""
        findings: List[Finding] = []

        for payload in SQLI_PAYLOADS:
            body, status, locator = send(payload)
            if body and SQL_ERROR_RE.search(body):
                findings.append(Finding(
                    id=f"WEB-ACTIVE-SQLI-{abs(hash((locator, param)))}",
                    title="Confirmed SQL Injection (error-based)",
                    severity=Severity.CRITICAL,
                    agent=self.name,
                    file_path=locator,
                    description=(
                        f"Injecting `{payload}` into parameter '{param}' triggered a database "
                        f"error message in the response, confirming unsanitized input reaches a SQL query."
                    ),
                    remediation="Use parameterized queries / prepared statements for all queries built from this parameter. Never interpolate request input into SQL strings.",
                    cvss_score=9.6,
                    metadata={"parameter": param, "payload": payload}
                ))
                break  # one confirmed SQLi per parameter is enough evidence

        xss_marker = f"<{marker}>"
        body, status, locator = send(xss_marker)
        if body and xss_marker in body:
            findings.append(Finding(
                id=f"WEB-ACTIVE-XSS-{abs(hash((locator, param)))}",
                title="Confirmed Reflected Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                agent=self.name,
                file_path=locator,
                description=(
                    f"Parameter '{param}' is reflected back in the response unescaped: a literal "
                    f"`{xss_marker}` marker survived round-trip, confirming the application does not "
                    f"HTML-encode this input before rendering it."
                ),
                remediation="HTML-encode all user-supplied data before rendering it into HTML, or use an auto-escaping template engine / DOMPurify on the client.",
                cvss_score=7.4,
                metadata={"parameter": param}
            ))

        return findings

    def _test_get_param(self, url: str, param: str, marker: str) -> List[Finding]:
        def send(payload: str):
            test_url = self._set_query_param(url, param, payload)
            body, status = self._fetch(test_url)
            return body, status, test_url
        return self._probe_reflection_and_sqli(send, param, marker)

    def _test_form_param(self, form: Dict[str, Any], param: str, marker: str) -> List[Finding]:
        action, method = form["action"], form["method"]
        other_params = [p for p in form["params"] if p != param]

        def send(payload: str):
            data = {p: "cybersentinel" for p in other_params}
            data[param] = payload
            if method == "post":
                body, status = self._fetch(action, method="POST", data=urlencode(data).encode("utf-8"))
            else:
                test_url = urlunparse(urlparse(action)._replace(query=urlencode(data)))
                body, status = self._fetch(test_url, method="GET")
            return body, status, f"{action} [{method.upper()} form field '{param}']"
        return self._probe_reflection_and_sqli(send, param, marker)

    def _active_probe(self, base_url: str, base_body: str) -> List[Finding]:
        findings: List[Finding] = []
        marker = "zz" + "".join(random.choices(string.ascii_lowercase, k=6))
        tested: set = set()

        pages = [(base_url, base_body)]
        seen = {base_url}
        for link in self._extract_links(base_url, base_body):
            if len(pages) >= MAX_CRAWL_PAGES or self._request_budget <= 0:
                break
            if link in seen:
                continue
            seen.add(link)
            body, _ = self._fetch(link)
            if body is not None:
                pages.append((link, body))

        for page_url, page_body in pages:
            if self._request_budget <= 0:
                break

            parsed = urlparse(page_url)
            for param in list(parse_qs(parsed.query).keys())[:MAX_PARAMS_PER_TARGET]:
                key = ("q", parsed.path, param)
                if key in tested or self._request_budget <= 0:
                    continue
                tested.add(key)
                findings.extend(self._test_get_param(page_url, param, marker))

            for form in self._extract_forms(page_url, page_body)[:MAX_FORMS_PER_PAGE]:
                for param in form["params"]:
                    key = ("f", form["action"], param)
                    if key in tested or self._request_budget <= 0:
                        continue
                    tested.add(key)
                    findings.extend(self._test_form_param(form, param, marker))

        return findings
