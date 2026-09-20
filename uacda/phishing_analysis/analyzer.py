"""Analyze RFC 5322 email messages for phishing indicators."""

from __future__ import annotations

import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from difflib import SequenceMatcher
from ipaddress import ip_address
from typing import Literal, Sequence
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_KNOWN_BRANDS = (
    "amazon",
    "apple",
    "bankofamerica",
    "docusign",
    "facebook",
    "google",
    "instagram",
    "linkedin",
    "microsoft",
    "netflix",
    "paypal",
    "slack",
    "zoom",
)

_URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_AUTH_STATUS_PATTERN = re.compile(
    r"\b(?P<protocol>spf|dkim|dmarc)=(?P<status>pass|fail|softfail|neutral|none|temperror|permerror)\b",
    re.IGNORECASE,
)
_SUSPICIOUS_ATTACHMENT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".sys",
    ".vbe",
    ".vbs",
    ".wsf",
    ".xlsm",
    ".docm",
    ".pptm",
    ".iso",
    ".img",
    ".rar",
    ".zip",
}


class PhishingVerdict(BaseModel):
    """Evidence-backed classification of an email message."""

    model_config = ConfigDict(extra="forbid")

    verdict: Literal["phishing", "suspicious", "clean"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)


def _decode_part(part: Message) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else str(content)
    except (LookupError, UnicodeError, TypeError):
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        return str(payload or "")


def _message_text(message: Message) -> str:
    parts: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart" or part.get_filename():
            continue
        if part.get_content_type() in {"text/plain", "text/html"}:
            parts.append(_decode_part(part))
    return "\n".join(parts)


def _extract_urls(message: Message) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for match in _URL_PATTERN.findall(_message_text(message)):
        url = match.rstrip(".,;:!?)]}")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _domain_token(hostname: str) -> str:
    labels = [label for label in hostname.lower().rstrip(".").split(".") if label]
    return labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")


def _brand_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower().split(".")[0])


def _lookalike_brand(hostname: str, known_brands: Sequence[str]) -> tuple[str, float] | None:
    labels = [label for label in hostname.lower().split(".") if label]
    candidates = {
        re.sub(r"[^a-z0-9]", "", part)
        for label in labels
        for part in label.split("-")
        if part
    }
    candidates.update(re.sub(r"[^a-z0-9]", "", label) for label in labels)
    candidates.add(re.sub(r"[^a-z0-9]", "", _domain_token(hostname)))
    best_match: tuple[str, float] | None = None
    for brand in known_brands:
        normalized_brand = _brand_token(brand)
        if not normalized_brand:
            continue
        for candidate in candidates:
            if candidate == normalized_brand:
                continue
            similarity = SequenceMatcher(None, candidate, normalized_brand).ratio()
            if similarity >= 0.78 and (best_match is None or similarity > best_match[1]):
                best_match = (normalized_brand, similarity)
    return best_match


def _analyze_urls(urls: Sequence[str], known_brands: Sequence[str]) -> list[str]:
    evidence: list[str] = []
    for url in urls:
        parsed = urlsplit(url if "://" in url else f"https://{url}")
        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            continue
        try:
            ip_address(hostname)
        except ValueError:
            match = _lookalike_brand(hostname, known_brands)
            if match:
                brand, similarity = match
                evidence.append(
                    f"URL {url} uses a lookalike domain for {brand} "
                    f"(similarity {similarity:.2f})."
                )
        else:
            evidence.append(f"URL {url} uses a raw IP address instead of a domain name.")
    return evidence


def _authentication_evidence(message: Message) -> list[str]:
    headers = "\n".join(message.get_all("Authentication-Results", []))
    headers += "\n" + "\n".join(message.get_all("Received-SPF", []))
    statuses: dict[str, str] = {}
    for match in _AUTH_STATUS_PATTERN.finditer(headers):
        statuses[match.group("protocol").lower()] = match.group("status").lower()
    evidence: list[str] = []
    for protocol in ("spf", "dkim", "dmarc"):
        status = statuses.get(protocol)
        if status in {"fail", "softfail", "permerror", "temperror"}:
            evidence.append(f"{protocol.upper()} authentication {status}.")
    return evidence


def _reply_to_evidence(message: Message) -> list[str]:
    sender = parseaddr(message.get("From", ""))[1].rsplit("@", maxsplit=1)[-1].lower()
    reply_to = parseaddr(message.get("Reply-To", ""))[1].rsplit("@", maxsplit=1)[-1].lower()
    if sender and reply_to and sender != reply_to:
        return [f"Reply-To domain {reply_to} differs from sender domain {sender}."]
    return []


def _attachment_evidence(message: Message) -> list[str]:
    evidence: list[str] = []
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        suffix = Path(filename).suffix.lower()
        if suffix in _SUSPICIOUS_ATTACHMENT_SUFFIXES:
            evidence.append(f"Attachment {filename} has a suspicious file type ({suffix}).")
    return evidence


def analyze_eml(
    path: str | Path,
    *,
    known_brands: Sequence[str] = DEFAULT_KNOWN_BRANDS,
) -> PhishingVerdict:
    """Parse and classify a raw .eml file using explainable phishing signals."""

    with Path(path).open("rb") as handle:
        message = BytesParser(policy=policy.default).parse(handle)

    evidence = [
        *_authentication_evidence(message),
        *_reply_to_evidence(message),
        *_analyze_urls(_extract_urls(message), known_brands),
        *_attachment_evidence(message),
    ]
    # The score represents accumulated independent indicators, bounded for a stable API.
    score = min(1.0, sum(
        0.25 if "authentication" in reason else
        0.3 if "Reply-To domain" in reason else
        0.45 if "lookalike domain" in reason else
        0.25 if "raw IP address" in reason else
        0.3 if "suspicious file type" in reason else 0.0
        for reason in evidence
    ))
    if score >= 0.7:
        verdict: Literal["phishing", "suspicious", "clean"] = "phishing"
        confidence = min(0.99, 0.65 + score * 0.35)
    elif score > 0:
        verdict = "suspicious"
        confidence = min(0.9, 0.55 + score * 0.35)
    else:
        verdict = "clean"
        confidence = 0.98
    return PhishingVerdict(verdict=verdict, confidence=confidence, evidence=evidence)


__all__ = ["DEFAULT_KNOWN_BRANDS", "PhishingVerdict", "analyze_eml"]