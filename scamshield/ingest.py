"""Stage 1 - signal capture.

Normalises the raw message (NFKC, zero-width stripping, homoglyph folding),
extracts URLs / domains / phones / amounts / crypto addresses, and runs
data-quality gates. Returns ``Signals`` with an explicit ``INSUFFICIENT_DATA``
status instead of guessing on bad input. Nothing here touches the network.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from scamshield.brands import SHORTENERS, official_brand_for_domain, registrable_domain
from scamshield.config import Config, Limits
from scamshield.models import (
    Channel,
    Entity,
    ExtractedURL,
    IngestStatus,
    MessageInput,
    ObfuscationReport,
    Signals,
)

# Invisible / formatting characters used to split words past keyword filters.
ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎‎‏")
BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
_INVISIBLE = ZERO_WIDTH | BIDI_CONTROLS

# 1:1 confusable map (Cyrillic / Greek / Latin-extended -> ASCII). Kept 1:1 so
# analysis offsets stay aligned with the display text.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lower
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d",
    "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "ɡ": "g", "ь": "b",
    # Cyrillic upper
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "ε": "e", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Latin extended look-alikes
    "ı": "i", "ł": "l", "ɑ": "a", "ɩ": "i", "ʏ": "y", "ǀ": "l",
}
_HOMOGLYPH_TABLE = str.maketrans(HOMOGLYPHS)

_EN_STOPWORDS = frozenset(
    "the you your is to and for this we are of a on in please will it be have has our "
    "with at from not i me my can if was that just been".split()
)
_FOREIGN_STOPWORDS = frozenset(
    # es / fr / de / pt / it markers chosen to not collide with English words
    "que los las por para una usted está gracias hola cuenta sus "
    "vous votre est les des une pour avec nous dans merci bonjour "
    "und der das ist nicht sie ihr ihre bitte konto mit ein eine "
    "você não sua seu com uma conta obrigado "
    "il della sono questo grazie".split()
)

# Bare (scheme-less) domains are matched only against these TLDs; very common
# English words ("in", "it", "to", "so", "at", "be", "no") are left out on purpose.
_TLDS = (
    "com|net|org|info|biz|io|co|us|uk|ca|de|fr|ru|cn|xyz|top|app|me|ly|gl|link|click|online|"
    "site|shop|store|live|support|help|vip|club|icu|buzz|cc|tk|ml|ga|cf|gq|pw|ws|tv|gov|edu|"
    "ai|dev|services|security|finance|bank|tech|website|mobi|asia|au|nz|za|br|mx|cam|monster"
)
_URL_RE = re.compile(
    r"(?:(?:https?|hxxps?)://|www\.)[^\s<>\"'()\[\]{}]+"
    r"|(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")(?![\w-])(?:/[^\s<>\"'()]*)?",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}")
_PHONE_RE = re.compile(
    r"(?<![\w/])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]?\d{3,4}[\s.-]?\d{3,4}(?![\w/])"
    r"|(?<![\w/])1-8\d{2}-[A-Z0-9]{3}-[A-Z0-9]{4}(?![\w/])"
    r"|(?<![\w/-])\d{3}-\d{4}(?![\w/-])"
)
_AMOUNT_RE = re.compile(
    r"(?:[$£€¥₹]\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:k|m|million|thousand)\b)?)"
    r"|(?:\b\d[\d,]*(?:\.\d+)?\s?(?:usd|dollars|eur|euros|gbp|pounds|btc|eth|usdt)\b)",
    re.IGNORECASE,
)
_CRYPTO_RE = re.compile(
    r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|T[1-9A-HJ-NP-Za-km-z]{33})\b"
)
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


def _script(ch: str) -> str:
    if ch.isascii():
        return "LATIN" if ch.isalpha() else "OTHER"
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "OTHER"
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER_LETTER" if ch.isalpha() else "OTHER"


def _looks_binary(text: str, limits: Limits) -> bool:
    if "\x00" in text:
        return True
    if not text:
        return False
    control = sum(1 for c in text if unicodedata.category(c) in {"Cc", "Cs", "Co", "Cn"} and c not in "\n\r\t")
    return control / len(text) > limits.max_control_ratio


def _count_compat_letters(raw: str) -> int:
    """Letters that NFKC folds from math-alphanumeric or fullwidth blocks."""
    return sum(1 for c in raw if 0x1D400 <= ord(c) <= 0x1D7FF or 0xFF21 <= ord(c) <= 0xFF5A)


def _strip_invisible(display: str) -> tuple[str, list[int], int, int, int, list[int]]:
    """Remove zero-width/bidi chars. Returns clean text + clean->display offset map."""
    out: list[str] = []
    offsets: list[int] = []
    removed = in_word = bidi = 0
    positions: list[int] = []
    for i, ch in enumerate(display):
        if ch in _INVISIBLE:
            removed += 1
            positions.append(i)
            if ch in BIDI_CONTROLS:
                bidi += 1
            else:
                prev = display[i - 1] if i > 0 else ""
                nxt = display[i + 1] if i + 1 < len(display) else ""
                # ZWJ between emoji is legitimate; only count joins inside words
                if prev.isalnum() and (nxt.isalnum() or nxt in _INVISIBLE):
                    in_word += 1
            continue
        out.append(ch)
        offsets.append(i)
    offsets.append(len(display))
    return "".join(out), offsets, removed, in_word, bidi, positions


def _mixed_script_words(clean: str) -> tuple[list[str], int]:
    """Words mixing Latin with Cyrillic/Greek letters (classic homoglyph spoofing)."""
    mixed: list[str] = []
    for m in _WORD_RE.finditer(clean):
        word = m.group(0)
        scripts = {_script(c) for c in word if c.isalpha()}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            mixed.append(word)
    homoglyph_chars = sum(1 for w in mixed for c in w if c in HOMOGLYPHS)
    return mixed, homoglyph_chars


def _non_latin_ratio(clean: str, mixed_words: list[str]) -> float:
    mixed = set(mixed_words)
    letters = latin = 0
    for m in _WORD_RE.finditer(clean):
        if m.group(0) in mixed:
            letters += len(m.group(0))
            latin += len(m.group(0))
            continue
        for c in m.group(0):
            letters += 1
            latin += _script(c) == "LATIN"
    return 0.0 if letters == 0 else 1 - latin / letters


def _unsupported_language(analysis: str, non_latin_ratio: float) -> bool:
    if non_latin_ratio > 0.3:
        return True
    words = [w.lower() for w in _WORD_RE.findall(analysis)]
    en = sum(w in _EN_STOPWORDS for w in words)
    foreign = sum(w in _FOREIGN_STOPWORDS for w in words)
    return foreign >= 3 and foreign > 2 * en


def _host_from_url(raw: str) -> str:
    url = re.sub(r"^(?:https?|hxxps?)://", "", raw, flags=re.I)
    host = re.split(r"[/?#]", url, maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1]  # user:pass@host
    if host.startswith("["):  # IPv6 literal
        return host.split("]")[0] + "]"
    return host.split(":")[0].lower().rstrip(".")


def _is_ip_literal(host: str) -> bool:
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    # decimal / hex encoded IPv4 (http://3232235777, http://0xC0A80001)
    return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", h, re.I))


def _decode_punycode(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def extract_urls(analysis: str, clean: str | None = None) -> tuple[ExtractedURL, ...]:
    """Find URLs in homoglyph-folded text; ``clean`` (pre-folding) reveals spoofed hosts."""
    urls: list[ExtractedURL] = []
    for m in _URL_RE.finditer(analysis):
        raw = m.group(0).rstrip(".,;:!?)'\"")
        host = _host_from_url(raw)
        if not host or "." not in host and not host.startswith("["):
            continue
        punycode = "xn--" in host
        decoded = _decode_punycode(host).translate(_HOMOGLYPH_TABLE).lower() if punycode else host
        ip_literal = _is_ip_literal(host)
        reg = host if ip_literal else registrable_domain(decoded)
        brand = None if ip_literal else official_brand_for_domain(decoded)
        urls.append(
            ExtractedURL(
                raw=raw,
                start=m.start(),
                end=m.start() + len(raw),
                host=decoded,
                registrable_domain=reg,
                is_shortener=(reg in SHORTENERS or decoded in SHORTENERS) and brand is None,
                is_ip_literal=ip_literal,
                is_punycode=punycode,
                has_homoglyphs=clean is not None and any(c in HOMOGLYPHS for c in clean[m.start() : m.start() + len(raw)]),
            )
        )
    return tuple(urls)


def _entities(pattern: re.Pattern[str], kind: str, text: str, skip: list[tuple[int, int]]) -> tuple[Entity, ...]:
    out = []
    for m in pattern.finditer(text):
        if any(s <= m.start() < e for s, e in skip):
            continue
        digits = re.sub(r"\D", "", m.group(0))
        if kind == "phone" and not 7 <= len(digits) <= 15:
            continue
        out.append(Entity(kind, m.group(0), m.start(), m.end()))
    return tuple(out)


def _insufficient(
    msg: MessageInput, flags: list[str], display: str = "", original_length: int = 0
) -> Signals:
    return Signals(
        status=IngestStatus.INSUFFICIENT_DATA,
        quality_flags=tuple(flags),
        channel=msg.channel,
        sender_id=msg.sender_id,
        claimed_sender=msg.claimed_sender,
        known_contact=msg.known_contact,
        display_text=display,
        analysis_text="",
        offset_map=(),
        original_length=original_length,
    )


def insufficient_signals(msg: MessageInput, flags: list[str] | tuple[str, ...]) -> Signals:
    """INSUFFICIENT_DATA signals for input rejected before text analysis (e.g. an unreadable image)."""
    return _insufficient(msg, list(flags))


def ingest(msg: MessageInput, config: Config) -> Signals:
    limits = config.limits
    raw = msg.text

    # --- decode / binary gate
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return _insufficient(msg, ["binary_input"], original_length=len(raw))
    if not isinstance(raw, str):
        return _insufficient(msg, ["non_text_input"])
    original_length = len(raw)
    if _looks_binary(raw, limits):
        return _insufficient(msg, ["binary_input"], original_length=original_length)

    # --- size gates (before any heavy processing)
    if original_length > limits.reject_over:
        return _insufficient(msg, ["too_long"], original_length=original_length)
    if not raw.strip():
        return _insufficient(msg, ["empty"], original_length=original_length)

    compat = _count_compat_letters(raw)
    display = unicodedata.normalize("NFKC", raw)
    truncated = len(display) > limits.truncate_at
    if truncated:
        display = display[: limits.truncate_at]

    clean, offsets, zw_removed, zw_in_word, bidi, zw_positions = _strip_invisible(display)
    mixed_words, homoglyph_chars = _mixed_script_words(clean)
    analysis = clean.translate(_HOMOGLYPH_TABLE)

    # --- content gates
    stripped = analysis.strip()
    if not any(c.isalnum() for c in stripped):
        return _insufficient(msg, ["no_text_content"], display, original_length)
    if len(stripped) < limits.min_chars:
        return _insufficient(msg, ["too_short"], display, original_length)
    if _unsupported_language(analysis, _non_latin_ratio(clean, mixed_words)):
        return _insufficient(msg, ["unsupported_language"], display, original_length)

    urls = extract_urls(analysis, clean)
    url_spans = [(u.start, u.end) for u in urls]
    emails = _entities(_EMAIL_RE, "email", analysis, [])
    email_spans = [(e.start, e.end) for e in emails]
    skip = url_spans + email_spans
    crypto = _entities(_CRYPTO_RE, "crypto", analysis, skip)
    phones = _entities(_PHONE_RE, "phone", analysis, skip + [(c.start, c.end) for c in crypto])
    amounts = _entities(_AMOUNT_RE, "amount", analysis, skip)
    # URLs that are really e-mail domains ("user@evil.com") are dropped
    urls = tuple(u for u in urls if not any(s <= u.start < e for s, e in email_spans))

    flags = ["truncated"] if truncated else []
    return Signals(
        status=IngestStatus.OK,
        quality_flags=tuple(flags),
        channel=msg.channel,
        sender_id=msg.sender_id,
        claimed_sender=msg.claimed_sender,
        known_contact=msg.known_contact,
        display_text=display,
        analysis_text=analysis,
        offset_map=tuple(offsets),
        original_length=original_length,
        truncated=truncated,
        urls=urls,
        phones=phones,
        emails=emails,
        amounts=amounts,
        crypto_addresses=crypto,
        obfuscation=ObfuscationReport(
            zero_width_removed=zw_removed,
            in_word_zero_width=zw_in_word,
            bidi_controls=bidi,
            homoglyph_chars=homoglyph_chars,
            mixed_script_words=tuple(mixed_words),
            compat_chars=compat,
            zero_width_display_positions=tuple(zw_positions),
        ),
    )


def parse_channel(value: str | Channel | None) -> Channel:
    if isinstance(value, Channel):
        return value
    try:
        return Channel((value or "sms").lower())
    except ValueError:
        return Channel.SMS
