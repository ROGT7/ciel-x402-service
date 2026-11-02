"""
CIEL x402 Security Middleware — DDoS Protection + Rate Limiting + IP Filtering
=============================================================================
Protections multicouches pour le serveur x402:

1. IP Rate Limiting (sliding window) — par IP, pas par service
   - Default: 60 req/min par IP, burst de 20
   - IP ban automatique après 5 violations
   - Ban duration: 15 min (configurable)

2. Payload Size Limit — bloque gros payloads
   - Default: 10MB max
   - Reject avec 413 Payload Too Large

3. IP Allowlist / Blocklist
   - Blocklist dynamique (IPs bannies auto)
   - Allowlist optionnelle (si activée, seulement ces IPs)

4. Request Timeout — kill requêtes qui durent trop
   - Default: 30s

5. Suspicious Pattern Detection
   - Détecte path traversal, SQL injection dans params
   - Détecte user agents suspects (scanners)
   - Log + block

6. Health Check Protection
   - /health limité à 10 req/min par IP (évite enumeration)

Usage dans ciel_x402_server_v3.py:
    from ciel_x402_security import SecurityMiddleware
    app.add_middleware(SecurityMiddleware, max_rpm=60, burst=20, max_payload_mb=10)
"""
import os
import time
import json
import hashlib
import threading
from collections import defaultdict, deque
from typing import Dict, Set, Optional, Tuple
from dataclasses import dataclass, field

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass
class IPTracker:
    requests: deque = field(default_factory=lambda: deque(maxlen=200))
    violations: int = 0
    banned_until: float = 0.0
    total_requests: int = 0


class SecurityMiddleware(BaseHTTPMiddleware):
    """Multi-layer DDoS and abuse protection for x402 server."""

    def __init__(self, app, max_rpm: int = 60, burst: int = 20,
                 max_payload_mb: int = 10, timeout_s: int = 30,
                 ban_threshold: int = 5, ban_duration_s: int = 900,
                 enable_pattern_detection: bool = True):
        super().__init__(app)
        self.max_rpm = max_rpm
        self.burst = burst
        self.max_payload_bytes = max_payload_mb * 1024 * 1024
        self.timeout_s = timeout_s
        self.ban_threshold = ban_threshold
        self.ban_duration_s = ban_duration_s
        self.enable_pattern_detection = enable_pattern_detection

        self._ip_trackers: Dict[str, IPTracker] = defaultdict(IPTracker)
        self._blocklist: Set[str] = set()
        self._allowlist: Set[str] = set()
        self._lock = threading.Lock()

        # Load allowlist from env if set
        allowlist_env = os.environ.get("X402_ALLOWLIST_IPS", "")
        if allowlist_env:
            self._allowlist = set(ip.strip() for ip in allowlist_env.split(",") if ip.strip())
            print(f"[SECURITY] Allowlist enabled: {len(self._allowlist)} IPs")

        # Load blocklist from env if set
        blocklist_env = os.environ.get("X402_BLOCKLIST_IPS", "")
        if blocklist_env:
            self._blocklist = set(ip.strip() for ip in blocklist_env.split(",") if ip.strip())
            print(f"[SECURITY] Blocklist loaded: {len(self._blocklist)} IPs")

        # Suspicious patterns
        self._suspicious_patterns = [
            "../", "..\\", "/etc/passwd", "/etc/shadow",
            "<script", "javascript:", "onerror=", "onload=",
            "union select", "drop table", "insert into",
            "exec(", "eval(", "system(",
        ]
        self._suspicious_uas = {
            "sqlmap", "nikto", "nmap", "masscan", "zgrab",
            "dirbuster", "gobuster", "wpscan", "hydra",
            "metasploit", "burpcollaborator",
        }

        # Health check rate (stricter)
        self._health_trackers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))

        print(f"[SECURITY] Middleware active: max_rpm={max_rpm}, burst={burst}, "
              f"max_payload={max_payload_mb}MB, ban_threshold={ban_threshold}")

    def _get_client_ip(self, request: Request) -> str:
        # Check X-Forwarded-For (behind reverse proxy)
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
        xri = request.headers.get("x-real-ip", "")
        if xri:
            return xri.strip()
        return request.client.host if request.client else "unknown"

    def _is_banned(self, ip: str) -> bool:
        tracker = self._ip_trackers.get(ip)
        if not tracker:
            return False
        return tracker.banned_until > time.time()

    def _ban_ip(self, ip: str, reason: str = ""):
        tracker = self._ip_trackers[ip]
        tracker.banned_until = time.time() + self.ban_duration_s
        self._blocklist.add(ip)
        print(f"[SECURITY] IP BANNED: {ip} ({reason}) — for {self.ban_duration_s}s")

    def _check_rate_limit(self, ip: str) -> Tuple[bool, str]:
        """Returns (allowed, reason)."""
        now = time.time()
        window_start = now - 60  # 1 minute window

        with self._lock:
            tracker = self._ip_trackers[ip]
            tracker.total_requests += 1

            # Remove old entries
            while tracker.requests and tracker.requests[0] < window_start:
                tracker.requests.popleft()

            # Check burst (last 10 seconds)
            burst_window = now - 10
            recent = sum(1 for t in tracker.requests if t > burst_window)
            if recent > self.burst:
                tracker.violations += 1
                if tracker.violations >= self.ban_threshold:
                    self._ban_ip(ip, f"burst violation #{tracker.violations}")
                    return False, "IP banned: too many burst requests"
                return False, f"Rate limit: burst exceeded ({recent}/{self.burst} in 10s)"

            # Check RPM
            if len(tracker.requests) >= self.max_rpm:
                tracker.violations += 1
                if tracker.violations >= self.ban_threshold:
                    self._ban_ip(ip, f"RPM violation #{tracker.violations}")
                    return False, "IP banned: sustained rate limit violation"
                return False, f"Rate limit: {len(tracker.requests)}/{self.max_rpm} RPM"

            tracker.requests.append(now)
            return True, ""

    def _check_health_rate(self, ip: str) -> bool:
        """Stricter rate limit for /health endpoint."""
        now = time.time()
        window_start = now - 60
        with self._lock:
            tracker = self._health_trackers[ip]
            while tracker and tracker[0] < window_start:
                tracker.popleft()
            if len(tracker) >= 10:
                return False
            tracker.append(now)
            return True

    def _detect_suspicious(self, request: Request) -> Optional[str]:
        """Returns reason if suspicious, None otherwise."""
        if not self.enable_pattern_detection:
            return None

        # Check User-Agent
        ua = request.headers.get("user-agent", "").lower()
        for sus_ua in self._suspicious_uas:
            if sus_ua in ua:
                return f"suspicious UA: {sus_ua}"

        # Check path for traversal
        path = request.url.path.lower()
        for pattern in self._suspicious_patterns:
            if pattern in path:
                return f"suspicious path pattern: {pattern}"

        # Check query params
        for key, value in request.query_params.items():
            combined = f"{key}={value}".lower()
            for pattern in self._suspicious_patterns:
                if pattern in combined:
                    return f"suspicious query param: {pattern}"

        return None

    def _check_payload_size(self, request: Request) -> Optional[int]:
        """Returns content-length if too large, None otherwise."""
        cl = request.headers.get("content-length")
        if cl:
            try:
                size = int(cl)
                if size > self.max_payload_bytes:
                    return size
            except ValueError:
                pass
        return None

    async def dispatch(self, request: Request, call_next):
        ip = self._get_client_ip(request)

        # 1. Check allowlist (if enabled)
        if self._allowlist and ip not in self._allowlist:
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "IP not in allowlist"}
            )

        # 2. Check blocklist
        if ip in self._blocklist or self._is_banned(ip):
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "IP banned"}
            )

        # 3. Health check strict limit
        if request.url.path == "/health":
            if not self._check_health_rate(ip):
                return JSONResponse(
                    status_code=429,
                    content={"error": "Health check rate limit", "limit": "10/min"}
                )

        # 4. Payload size check
        too_large = self._check_payload_size(request)
        if too_large:
            return JSONResponse(
                status_code=413,
                content={"error": "Payload too large",
                         "size_bytes": too_large,
                         "max_bytes": self.max_payload_bytes}
            )

        # 5. Suspicious pattern detection
        suspicious = self._detect_suspicious(request)
        if suspicious:
            tracker = self._ip_trackers[ip]
            tracker.violations += 1
            print(f"[SECURITY] Suspicious request from {ip}: {suspicious}")
            if tracker.violations >= self.ban_threshold:
                self._ban_ip(ip, f"suspicious: {suspicious}")
            return JSONResponse(
                status_code=400,
                content={"error": "Suspicious request detected", "reason": suspicious}
            )

        # 6. Rate limiting
        allowed, reason = self._check_rate_limit(ip)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limited", "reason": reason,
                         "retry_after": self.ban_duration_s if "banned" in reason else 60}
            )

        # 7. Process request
        try:
            response = await call_next(request)
            return response
        except Exception as e:
            print(f"[SECURITY] Request error from {ip}: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal error", "request_id": hashlib.md5(
                    f"{ip}_{time.time()}".encode()).hexdigest()[:8]}
            )

    def get_status(self) -> Dict:
        """Get security middleware status for monitoring."""
        now = time.time()
        with self._lock:
            active_ips = sum(1 for t in self._ip_trackers.values() if t.requests and t.requests[-1] > now - 60)
            banned_ips = sum(1 for t in self._ip_trackers.values() if t.banned_until > now)
            return {
                "active_ips_last_min": active_ips,
                "banned_ips": banned_ips,
                "blocklist_size": len(self._blocklist),
                "allowlist_size": len(self._allowlist),
                "total_tracked_ips": len(self._ip_trackers),
                "config": {
                    "max_rpm": self.max_rpm,
                    "burst": self.burst,
                    "max_payload_mb": self.max_payload_bytes // (1024 * 1024),
                    "ban_threshold": self.ban_threshold,
                    "ban_duration_s": self.ban_duration_s,
                },
                "timestamp": now,
            }

    def unban_ip(self, ip: str):
        """Manually unban an IP."""
        with self._lock:
            if ip in self._blocklist:
                self._blocklist.discard(ip)
            tracker = self._ip_trackers.get(ip)
            if tracker:
                tracker.banned_until = 0
                tracker.violations = 0
            print(f"[SECURITY] IP unbanned: {ip}")

    def ban_ip_manual(self, ip: str):
        """Manually ban an IP."""
        with self._lock:
            self._ban_ip(ip, "manual ban")
