"""Local heuristic URL analyzer for phishing detection."""
from __future__ import annotations

import math
import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "wallet",
    "secure",
    "bonus",
    "confirm",
    "update",
    "bank",
)

SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
}

TRUSTED_BRANDS = (
    "google",
    "paypal",
    "apple",
    "facebook",
    "amazon",
    "microsoft",
    "binance",
    "instagram",
    "twitter",
    "netflix",
)

IMPERSONATION_KEYWORDS = (
    "login",
    "verify",
    "secure",
    "account",
    "auth",
    "update",
    "wallet",
)

COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "7": "t",
    "@": "a",
}


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").strip().lower()


def _extract_raw_host(url: str) -> str:
    """Extract host-like text from netloc while preserving case."""
    parsed = urlparse(url)
    netloc = (parsed.netloc or "").strip()
    if not netloc:
        return ""

    # Remove userinfo if present: user:pass@host:port
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    # Strip port for non-IPv6 hosts
    if netloc.startswith("["):
        # IPv6 form [::1]:443
        end = netloc.find("]")
        return netloc[1:end] if end != -1 else netloc.strip("[]")

    return netloc.split(":", 1)[0]


def _extract_main_domain_label(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if not parts:
        return ""
    return parts[-2] if len(parts) >= 2 else parts[0]


def _extract_subdomain(host: str) -> str:
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def _tokenize_domain_part(value: str, *, lower: bool = True) -> list[str]:
    text = value.lower() if lower else value
    return [t for t in re.split(r"[^A-Za-z0-9@]+", text) if t]


def _is_ip_host(host: str) -> bool:
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (0 if ca == cb else 1)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


def _substitution_note(token_raw: str, brand: str) -> str | None:
    """
    Build an explanation if token appears to use common phishing substitutions.
    Example: g00gle -> Digits "00" may be replacing the letters "oo".
    """
    token_lower = token_raw.lower()
    if len(token_lower) != len(brand):
        return None

    src_chars: list[str] = []
    dst_chars: list[str] = []
    has_upper_i_for_l = False

    for i, (c_tok, c_brand) in enumerate(zip(token_raw, brand)):
        c_tok_low = c_tok.lower()
        mapped = COMMON_SUBSTITUTIONS.get(c_tok_low)
        if mapped and mapped == c_brand:
            src_chars.append(c_tok)
            dst_chars.append(c_brand)
            continue

        # Special visual confusable: uppercase I used where lowercase l is expected.
        if c_tok == "I" and c_brand == "l":
            has_upper_i_for_l = True

    if src_chars:
        src = "".join(src_chars)
        dst = "".join(dst_chars)
        if src.isdigit():
            return f'Digits "{src}" may be replacing the letters "{dst}".'
        return f'Characters "{src}" may be replacing the letters "{dst}".'

    if has_upper_i_for_l:
        return "Uppercase 'I' may be replacing lowercase 'l'."

    return None


def detect_typosquatting(host: str, *, raw_host: str | None = None) -> list[dict[str, str]]:
    """
    Detect typosquatting against trusted brands.
    Returns a list of matches with token/brand and optional substitution note.
    """
    main_domain_raw = _extract_main_domain_label(raw_host or host)
    tokens_raw = _tokenize_domain_part(main_domain_raw, lower=False)
    if not tokens_raw:
        return []

    findings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for token_raw in tokens_raw:
        token = token_raw.lower()
        if len(token) < 4:
            continue

        for brand in TRUSTED_BRANDS:
            if token == brand:
                continue
            dist = _levenshtein_distance(token, brand)
            if dist <= 1 or (dist <= 2 and len(token) > 5):
                key = (token_raw, brand)
                if key in seen:
                    continue
                seen.add(key)

                item = {
                    "token": token_raw,
                    "brand": brand,
                }
                note = _substitution_note(token_raw, brand)
                if note:
                    item["note"] = note
                findings.append(item)

    return findings


def detect_brand_impersonation(url: str, host: str) -> list[str]:
    parsed = urlparse(url)
    main_domain = _extract_main_domain_label(host)
    subdomain = _extract_subdomain(host)
    path = (parsed.path or "").lower()

    domain_tokens = set(_tokenize_domain_part(main_domain))
    sub_tokens = set(_tokenize_domain_part(subdomain))
    path_tokens = set(_tokenize_domain_part(path))
    all_tokens = domain_tokens | sub_tokens | path_tokens

    has_impersonation_keyword = any(k in all_tokens for k in IMPERSONATION_KEYWORDS)
    if not has_impersonation_keyword:
        return []

    detected: set[str] = set()
    for brand in TRUSTED_BRANDS:
        if brand in all_tokens:
            detected.add(brand)
    return sorted(detected)


def _domain_entropy(domain: str) -> float:
    if not domain:
        return 0.0
    freq: dict[str, int] = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(domain)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _is_suspicious_subdomain(host: str) -> bool:
    if host.count(".") < 2:
        return False

    parts = host.split(".")
    left = ".".join(parts[:-2])
    if not left:
        return False

    suspicious_words = ("login", "secure", "verify", "update", "account", "bank")
    return any(word in left for word in suspicious_words)


def analyze_url_heuristic(url: str) -> dict[str, Any]:
    """Return heuristic URL analysis: risk_score, verdict, reasons."""
    parsed = urlparse(url)
    host = _extract_host(url)
    raw_host = _extract_raw_host(url)
    full = f"{parsed.netloc}{parsed.path}?{parsed.query}".lower()

    risk_score = 0
    reasons: list[str] = []

    if not host:
        return {
            "risk_score": 5,
            "verdict": "phishing",
            "reasons": ["Domain could not be resolved from the URL."],
        }

    if _is_ip_host(host):
        risk_score += 3
        reasons.append("IP address is used instead of a domain name.")

    if "@" in url:
        risk_score += 2
        reasons.append("URL contains '@', which can be used to obscure destinations.")

    if "xn--" in host:
        risk_score += 2
        reasons.append("Punycode domain detected (xn--).")

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full:
            risk_score += 1
            reasons.append(f'Suspicious keyword detected: "{keyword}".')

    if host in SHORTENER_DOMAINS:
        risk_score += 2
        reasons.append("URL shortener domain detected.")

    if _is_suspicious_subdomain(host):
        risk_score += 2
        reasons.append("Suspicious subdomain structure detected.")

    if len(host) > 45:
        risk_score += 1
        reasons.append("Unusually long domain name.")

    entropy = _domain_entropy(host)
    if entropy >= 3.8:
        risk_score += 2
        reasons.append("Domain entropy is unusually high.")

    digit_ratio = len(re.findall(r"\d", host)) / max(1, len(host))
    if digit_ratio >= 0.25:
        risk_score += 1
        reasons.append("Domain contains an unusually high ratio of digits.")

    typosquatted = detect_typosquatting(host, raw_host=raw_host)
    if typosquatted:
        risk_score += 3
        for finding in typosquatted:
            token = finding["token"]
            brand = finding["brand"]
            reasons.append(
                f'Possible typosquatting detected: "{token}" resembles the brand "{brand}".'
            )
            if "note" in finding:
                reasons.append(finding["note"])

    impersonated = detect_brand_impersonation(url, host)
    if impersonated:
        risk_score += 3
        for brand in impersonated:
            reasons.append(f"Brand impersonation detected: {brand}.")

    if risk_score >= 5:
        verdict = "phishing"
    elif risk_score >= 2:
        verdict = "suspicious"
    else:
        verdict = "clean"

    if not reasons and verdict == "clean":
        reasons.append("No explicit phishing indicators were detected.")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
    }
