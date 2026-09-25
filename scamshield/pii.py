"""PII masking applied before storage and before anything is sent to the LLM.

Typed placeholders keep enough structure for analysis ("asks for [OTP]") while
removing the value. E-mail domains and URL hosts are kept because they are the
main phishing signal; e-mail local parts, URL query strings and credentials in
URLs are removed.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

_INVISIBLE_RE = re.compile("[​‌‍⁠﻿­᠎‎‏‪-‮⁦-⁩]")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})")
PHONE_RE = re.compile(
    r"(?<![\w/\[])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\w/])"
    r"|(?<![\w/])1-8\d{2}-[A-Z0-9]{3}-[A-Z0-9]{4}(?![\w/])"
    r"|(?<![\w/-])\d{3}-\d{4}(?![\w/-])"
)
_URL_QUERY_RE = re.compile(r"((?:https?|hxxps?)://[^\s?#]+|www\.[^\s?#]+)([?#][^\s]*)", re.I)
_URL_USERINFO_RE = re.compile(r"((?:https?|hxxps?)://)[^\s/@]+@", re.I)
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
_CARD_RE = re.compile(r"(?<![\d\w])(?:\d[ -]?){12,18}\d(?![\d\w])")
_SSN_RE = re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}(?![\d-])")
_SSN_CONTEXT_RE = re.compile(r"(?i)\b(ssn|social security)\b[^.\n]{0,30}?(?<!\d)(\d{9})(?!\d)")
_OTP_CONTEXT_RE = re.compile(
    r"(?i)\b(code|otp|pin|passcode|password|one[- ]time|verification|2fa|security)\b[^.\n\d]{0,30}?"
    r"(?<![\w$£€.,])([A-Z]-)?(\d{4,8})(?![\d,.]?\d)"
)
_OTP_TRAILING_RE = re.compile(
    r"(?i)(?<![\w$£€.,])(?:[A-Z]-)?(\d{4,8})(?![\d,.]?\d)(?=\s+(?:is|as)\s+(?:your|the)\b[^.\n]{0,40}\b(code|otp|pin|passcode))"
)
_STANDALONE_CODE_RE = re.compile(r"(?<![\w$£€.,:/#-])(\d{6,8})(?![\w%.,:/-]|\s?(?:usd|dollars|eur|gbp)\b)", re.I)

PLACEHOLDERS = ("[EMAIL]", "[PHONE]", "[CARD]", "[SSN]", "[IBAN]", "[OTP]", "[QUERY]", "[CREDENTIALS]")


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_valid(candidate: str) -> bool:
    s = candidate.replace(" ", "").upper()
    if not 15 <= len(s) <= 34 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


@dataclass(frozen=True)
class MaskResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def mask_text(text: str) -> MaskResult:
    counts: Counter[str] = Counter()
    # Zero-width characters must go first or they split digits past every regex below.
    text = _INVISIBLE_RE.sub("", text)

    def sub(pattern: re.Pattern[str], repl, kind: str, s: str) -> str:
        def _r(m: re.Match[str]) -> str:
            out = repl(m) if callable(repl) else repl
            if out != m.group(0):
                counts[kind] += 1
            return out

        return pattern.sub(_r, s)

    text = sub(_URL_USERINFO_RE, lambda m: m.group(1) + "[CREDENTIALS]@", "credentials", text)
    text = sub(_URL_QUERY_RE, lambda m: m.group(1) + "?[QUERY]", "query", text)
    text = sub(EMAIL_RE, lambda m: "[EMAIL]@" + m.group(1), "email", text)
    text = sub(_IBAN_RE, lambda m: "[IBAN]" if iban_valid(m.group(0)) else m.group(0), "iban", text)
    text = sub(
        _CARD_RE, lambda m: "[CARD]" if luhn_valid(re.sub(r"\D", "", m.group(0))) else m.group(0), "card", text
    )
    text = sub(_SSN_RE, "[SSN]", "ssn", text)
    text = sub(_SSN_CONTEXT_RE, lambda m: m.group(0).replace(m.group(2), "[SSN]"), "ssn", text)
    text = sub(PHONE_RE, lambda m: "[PHONE]" if 7 <= len(re.sub(r"\D", "", m.group(0))) <= 15 else m.group(0), "phone", text)
    def _otp_after_keyword(m: re.Match[str]) -> str:
        code_start = m.start(2) if m.group(2) else m.start(3)  # include "G-" style prefixes
        return m.group(0)[: code_start - m.start(0)] + "[OTP]"

    text = sub(_OTP_CONTEXT_RE, _otp_after_keyword, "otp", text)
    text = sub(_OTP_TRAILING_RE, "[OTP]", "otp", text)
    text = sub(_STANDALONE_CODE_RE, "[OTP]", "otp", text)
    return MaskResult(text=text, counts=dict(counts))


def mask_sender(sender: str | None) -> str | None:
    """Mask a sender identifier while keeping what an analyst needs to triage."""
    if not sender:
        return sender
    sender = _INVISIBLE_RE.sub("", sender.strip())
    m = EMAIL_RE.fullmatch(sender) or EMAIL_RE.search(sender)
    if m:
        return "[EMAIL]@" + m.group(1)
    digits = re.sub(r"\D", "", sender)
    if digits and len(digits) <= 6 and not re.search(r"[A-Za-z]", sender):
        return sender  # SMS short code: an organisation, not a person
    if 7 <= len(digits) <= 15:
        return f"[PHONE …{digits[-2:]}]"
    return "[HANDLE]"
