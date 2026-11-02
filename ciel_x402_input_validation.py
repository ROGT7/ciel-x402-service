"""
CIEL x402 Input Validation & SSRF Protection
=============================================
Valide et sanitise tous les inputs des 93 endpoints.

Protections:
1. URL Sanitization — bloque file://, ftp://, metadata IPs, localhost, private ranges
2. Pydantic models par endpoint — taille max, format, type strict
3. Payload size limits par champ (texte max, URL max, etc.)
4. SQL injection / command injection detection dans les champs texte
5. Path traversal blocking
"""
import os
import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator, HttpUrl


# ============================================================
# 1. SSRF PROTECTION — URL Sanitization
# ============================================================

BLOCKED_PROTOCOLS = {"file", "ftp", "gopher", "dict", "ldap", "smb", "tftp", "rtsp"}
BLOCKED_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP metadata
    "169.254.170.2",    # ECS metadata
    "100.100.100.200",  # Alibaba metadata
}
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 500_000  # 500KB max for text fields
MAX_CODE_LENGTH = 200_000  # 200KB for code fields
MAX_LIST_ITEMS = 10_000
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024  # 2MB max JSON body


def sanitize_url(url: str, allow_private: bool = False) -> tuple[bool, str, Optional[str]]:
    """
    Validate and sanitize a URL.
    Returns (is_valid, cleaned_url, error_reason).
    """
    if not url or not isinstance(url, str):
        return False, "", "URL is empty or not a string"

    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return False, "", f"URL too long ({len(url)} > {MAX_URL_LENGTH})"

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, "", f"URL parse error: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        if scheme in BLOCKED_PROTOCOLS:
            return False, "", f"Blocked protocol: {scheme}"
        if not scheme:
            return False, "", "No URL scheme provided"
        return False, "", f"Unsupported protocol: {scheme}"

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False, "", "No hostname in URL"

    if hostname in BLOCKED_HOSTS:
        return False, "", f"Blocked host: {hostname}"

    if not allow_private:
        try:
            ip = ipaddress.ip_address(hostname)
            for network in BLOCKED_IP_RANGES:
                if ip in network:
                    return False, "", f"Blocked private/internal IP: {hostname}"
        except ValueError:
            pass

    if "@" in url.split("://")[-1].split("/")[0]:
        return False, "", "URL contains credentials (@ symbol)"

    return True, url, None


def sanitize_text(text: str, max_length: int = MAX_TEXT_LENGTH) -> tuple[bool, str, Optional[str]]:
    """
    Validate and sanitize a text input.
    Returns (is_valid, cleaned_text, error_reason).
    """
    if text is None:
        return False, "", "Text is None"
    if not isinstance(text, str):
        return False, "", "Input is not a string"

    if len(text) > max_length:
        return False, "", f"Text too long ({len(text)} > {max_length})"

    return True, text, None


def detect_injection(text: str) -> Optional[str]:
    """
    Detect SQL injection, command injection, and path traversal attempts.
    Returns reason if detected, None otherwise.
    """
    if not text or not isinstance(text, str):
        return None

    text_lower = text.lower()

    sql_patterns = [
        r"'\s*or\s*'?\d*'?\s*=\s*'?\d*'?",
        r"'\s*or\s*'?\w*'?\s*=\s*'?\w*'?",
        r"union\s+select",
        r"drop\s+table",
        r"insert\s+into",
        r"delete\s+from",
        r"--\s*$",
        r";\s*drop",
        r"'\s*;\s*",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, text_lower):
            return f"SQL injection pattern detected: {pattern}"

    cmd_patterns = [
        r";\s*(rm|cat|ls|wget|curl|bash|sh|nc|python|perl)\s",
        r"\|\s*(rm|cat|ls|wget|curl|bash|sh|nc)\s",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"&&\s*(rm|cat|ls|wget|curl|bash|sh)\s",
    ]
    for pattern in cmd_patterns:
        if re.search(pattern, text_lower):
            return f"Command injection pattern detected: {pattern}"

    path_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self/",
        r"C:\\windows\\",
        r"\\windows\\system32",
    ]
    for pattern in path_patterns:
        if re.search(pattern, text):
            return f"Path traversal detected: {pattern}"

    return None


def sanitize_params(params: Dict[str, Any], endpoint: str) -> tuple[Dict[str, Any], Optional[str]]:
    """
    Validate and sanitize params for a given endpoint.
    Returns (cleaned_params, error_reason).
    """
    cleaned = {}
    text_fields = {"text", "content", "prompt", "query", "strategy", "code", "logs", "data", "json", "cv", "job_offer", "topic"}
    url_fields = {"url", "u", "image_url", "audio_url", "webhook_url"}
    address_fields = {"address", "wallet", "to", "from"}
    list_fields = {"data", "history", "stops", "tags", "parties"}

    for key, value in params.items():
        if key in url_fields:
            ok, clean_url, err = sanitize_url(str(value))
            if not ok:
                return {}, f"Field '{key}': {err}"
            cleaned[key] = clean_url

        elif key in text_fields:
            max_len = MAX_CODE_LENGTH if key == "code" else MAX_TEXT_LENGTH
            ok, clean_text, err = sanitize_text(str(value), max_len)
            if not ok:
                return {}, f"Field '{key}': {err}"
            injection = detect_injection(clean_text)
            if injection:
                return {}, f"Field '{key}': {injection}"
            cleaned[key] = clean_text

        elif key in address_fields:
            addr = str(value).strip()
            if not re.match(r'^0x[a-fA-F0-9]{40}$', addr):
                return {}, f"Field '{key}': invalid address format"
            cleaned[key] = addr

        elif key in list_fields:
            if isinstance(value, list):
                if len(value) > MAX_LIST_ITEMS:
                    return {}, f"Field '{key}': too many items ({len(value)} > {MAX_LIST_ITEMS})"
                cleaned[key] = value
            elif isinstance(value, str):
                ok, clean_text, err = sanitize_text(value, MAX_TEXT_LENGTH)
                if not ok:
                    return {}, f"Field '{key}': {err}"
                cleaned[key] = clean_text
            else:
                cleaned[key] = value

        elif key == "count" or key == "limit":
            try:
                val = int(value)
                val = max(1, min(val, 1000))
                cleaned[key] = val
            except (ValueError, TypeError):
                return {}, f"Field '{key}': must be an integer"

        else:
            if isinstance(value, str):
                if len(value) > MAX_TEXT_LENGTH:
                    return {}, f"Field '{key}': value too long ({len(value)})"
                injection = detect_injection(value)
                if injection:
                    return {}, f"Field '{key}': {injection}"
            cleaned[key] = value

    return cleaned, None


# ============================================================
# 2. PYDANTIC MODELS — Per-endpoint validation schemas
# ============================================================

class BaseRequest(BaseModel):
    """Base validation model — all endpoints inherit from this."""
    class Config:
        extra = "forbid"  # Reject unknown fields


class URLRequest(BaseRequest):
    url: str = Field(..., max_length=MAX_URL_LENGTH)

    @validator("url")
    def validate_url(cls, v):
        ok, _, err = sanitize_url(v)
        if not ok:
            raise ValueError(err)
        return v


class TextRequest(BaseRequest):
    text: str = Field(..., max_length=MAX_TEXT_LENGTH)

    @validator("text")
    def validate_text(cls, v):
        injection = detect_injection(v)
        if injection:
            raise ValueError(injection)
        return v


class CodeRequest(BaseRequest):
    code: str = Field(..., max_length=MAX_CODE_LENGTH)
    lang: str = Field("python", max_length=20)


class AddressRequest(BaseRequest):
    address: str = Field(..., pattern=r'^0x[a-fA-F0-9]{40}$')


class PromptRequest(BaseRequest):
    prompt: str = Field(..., max_length=MAX_TEXT_LENGTH)


# Endpoint → Pydantic model mapping for strict validation
ENDPOINT_MODELS: Dict[str, type[BaseModel]] = {
    "/api/rag-markdown": URLRequest,
    "/api/stealth-fetch": URLRequest,
    "/api/phishing-scan": URLRequest,
    "/api/rag-extreme": URLRequest,
    "/api/uptime-monitor": URLRequest,
    "/api/residential-ping": URLRequest,
    "/api/yt-summary": URLRequest,
    "/api/code-audit": CodeRequest,
    "/api/code-translate": CodeRequest,
    "/api/inference": PromptRequest,
    "/api/context-compress": TextRequest,
    "/api/pii-mask": TextRequest,
    "/api/anti-scam": TextRequest,
    "/api/log-anomaly": TextRequest,
    "/api/jailbreak-prompt": PromptRequest,
    "/api/prompt-route": PromptRequest,
    "/api/prompt-optimize": PromptRequest,
    "/api/logic-validator": PromptRequest,
    "/api/video-script": PromptRequest,
    "/api/cv-generator": BaseRequest,
    "/api/cv-parse": TextRequest,
    "/api/scan-contract": AddressRequest,
    "/api/honeypot-scan": AddressRequest,
    "/api/sybil-evaluator": AddressRequest,
    "/api/contract-audit": AddressRequest,
    "/api/smart-money-tracker": AddressRequest,
    "/api/json-repair": TextRequest,
    "/api/email-validate": BaseRequest,
    "/api/finance-meme": BaseRequest,
    "/api/qr-generate": BaseRequest,
    "/api/phone-format": BaseRequest,
    "/api/domain-watch": BaseRequest,
    "/api/sentiment": BaseRequest,
    "/api/funding-rates": BaseRequest,
    "/api/synth-identity": BaseRequest,
    "/api/synth-fingerprint": BaseRequest,
    "/api/synth-data": BaseRequest,
    "/api/data-clean": BaseRequest,
    "/api/tts": TextRequest,
    "/api/srt-generate": URLRequest,
    "/api/invoice-ocr": URLRequest,
    "/api/video-shorts": TextRequest,
    "/api/reddit-trends": BaseRequest,
    "/api/twitter-alpha": BaseRequest,
    "/api/orderbook-spoof": BaseRequest,
    "/api/gas-oracle": BaseRequest,
    "/api/flash-loan-route": BaseRequest,
    "/api/web3-trace-cleaner": BaseRequest,
    "/api/human-behavior": BaseRequest,
    "/api/proxy-ephemeral": BaseRequest,
    "/api/cf-bypass": URLRequest,
    "/api/sms-bridge": BaseRequest,
    "/api/multi-farm": BaseRequest,
    "/api/rebalance": BaseRequest,
    "/api/dust-consolidate": BaseRequest,
    "/api/mev-liquidate": BaseRequest,
    "/api/dex-arb": BaseRequest,
    "/api/liquidity-snipe": BaseRequest,
    "/api/mm-hf": BaseRequest,
    "/api/mempool-watch": BaseRequest,
    "/api/crypto-taxes": BaseRequest,
    "/api/vectorize": TextRequest,
    "/api/graphql-fuzzer": URLRequest,
    "/api/subdomain-takeover": BaseRequest,
    "/api/payload-gen": BaseRequest,
    "/api/api-key-leak": BaseRequest,
    "/api/linkedin-scraper": URLRequest,
    "/api/tor-indexer": BaseRequest,
    "/api/discord-scraper": BaseRequest,
    "/api/plagiarism-check": BaseRequest,
    "/api/ecommerce-margin": BaseRequest,
    "/api/ecommerce-sheet": BaseRequest,
    "/api/legal-contract": BaseRequest,
    "/api/email-warmup": BaseRequest,
    "/api/webhook-relay": BaseRequest,
    "/api/format-convert": BaseRequest,
    "/api/route-optimize": BaseRequest,
    "/api/time-series-predict": BaseRequest,
    "/api/fx-historical": BaseRequest,
    "/api/bittensor-validate": BaseRequest,
    "/api/compute-provider": BaseRequest,
    "/api/m2m-relay": BaseRequest,
    "/api/captcha-solve": BaseRequest,
    "/api/osint": BaseRequest,
    "/api/proxy-scan": BaseRequest,
}


def validate_request(endpoint: str, params: Dict[str, Any]) -> tuple[Dict[str, Any], Optional[str]]:
    """
    Validate request params against the endpoint's Pydantic model.
    Returns (validated_params, error_reason).
    """
    model_cls = ENDPOINT_MODELS.get(endpoint)
    if model_cls:
        try:
            model = model_cls(**params)
            return model.dict(), None
        except Exception as e:
            return {}, str(e)

    # Fallback: generic sanitization
    return sanitize_params(params, endpoint)
