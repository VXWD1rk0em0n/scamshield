"""Brand allowlist, domain helpers, and lookalike-domain detection.

The allowlist is intentionally small and explicit: lookalike detection only works
for brands listed here (documented in LIMITATIONS.md).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    key: str  # canonical token compared against domain labels
    display: str
    domains: tuple[str, ...]  # official registrable domains
    aliases: tuple[str, ...]  # text mentions (case-insensitive)
    case_sensitive_aliases: tuple[str, ...] = ()  # ambiguous words: only match as written
    kind: str = "company"  # bank | government | delivery | tech | company | crypto | payments


BRANDS: tuple[Brand, ...] = (
    Brand("paypal", "PayPal", ("paypal.com", "paypal.me"), ("paypal",), kind="payments"),
    Brand("chase", "Chase", ("chase.com", "jpmorganchase.com"), ("jpmorgan chase", "chase bank"), ("Chase", "CHASE"), kind="bank"),
    Brand("bankofamerica", "Bank of America", ("bankofamerica.com", "bofa.com"), ("bank of america", "bofa"), kind="bank"),
    Brand("wellsfargo", "Wells Fargo", ("wellsfargo.com", "wf.com"), ("wells fargo", "wellsfargo"), kind="bank"),
    Brand("citi", "Citi", ("citi.com", "citibank.com"), ("citibank",), ("Citi",), kind="bank"),
    Brand("capitalone", "Capital One", ("capitalone.com",), ("capital one", "capitalone"), kind="bank"),
    Brand("amex", "American Express", ("americanexpress.com", "amex.com"), ("american express", "amex"), kind="bank"),
    Brand("usps", "USPS", ("usps.com",), ("usps", "postal service"), kind="delivery"),
    Brand("ups", "UPS", ("ups.com",), (), ("UPS",), kind="delivery"),
    Brand("fedex", "FedEx", ("fedex.com",), ("fedex",), kind="delivery"),
    Brand("dhl", "DHL", ("dhl.com",), ("dhl",), kind="delivery"),
    Brand("royalmail", "Royal Mail", ("royalmail.com",), ("royal mail",), kind="delivery"),
    Brand("amazon", "Amazon", ("amazon.com", "amazon.co.uk", "amzn.to", "amazon.ca"), ("amazon",), kind="company"),
    Brand("apple", "Apple", ("apple.com", "icloud.com"), ("apple id", "icloud", "apple support"), ("Apple",), kind="tech"),
    Brand("microsoft", "Microsoft", ("microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com"), ("microsoft", "office 365", "microsoft 365", "windows support", "windows defender"), ("Outlook",), kind="tech"),
    Brand("google", "Google", ("google.com", "gmail.com", "youtube.com", "g.co"), ("google", "gmail"), kind="tech"),
    Brand("netflix", "Netflix", ("netflix.com",), ("netflix",), kind="company"),
    Brand("irs", "IRS", ("irs.gov",), ("internal revenue service", "irs"), kind="government"),
    Brand("ssa", "Social Security Administration", ("ssa.gov",), ("social security administration",), kind="government"),
    Brand("hmrc", "HMRC", ("gov.uk",), ("hmrc",), kind="government"),
    Brand("linkedin", "LinkedIn", ("linkedin.com", "lnkd.in"), ("linkedin",), kind="company"),
    Brand("coinbase", "Coinbase", ("coinbase.com",), ("coinbase",), kind="crypto"),
    Brand("binance", "Binance", ("binance.com",), ("binance",), kind="crypto"),
    Brand("venmo", "Venmo", ("venmo.com",), ("venmo",), kind="payments"),
    Brand("zelle", "Zelle", ("zellepay.com",), ("zelle",), kind="payments"),
    Brand("cashapp", "Cash App", ("cash.app", "squareup.com"), ("cash app", "cashapp"), kind="payments"),
    Brand("docusign", "DocuSign", ("docusign.com", "docusign.net"), ("docusign",), kind="company"),
    Brand("dropbox", "Dropbox", ("dropbox.com",), ("dropbox",), kind="company"),
    Brand("facebook", "Facebook", ("facebook.com", "fb.com", "meta.com"), ("facebook", "meta support"), kind="company"),
    Brand("instagram", "Instagram", ("instagram.com",), ("instagram",), kind="company"),
    Brand("whatsapp", "WhatsApp", ("whatsapp.com", "wa.me"), ("whatsapp",), kind="company"),
    Brand("walmart", "Walmart", ("walmart.com",), ("walmart",), kind="company"),
    Brand("target", "Target", ("target.com",), (), ("Target",), kind="company"),
    Brand("ebay", "eBay", ("ebay.com",), ("ebay",), kind="company"),
    Brand("verizon", "Verizon", ("verizon.com", "vzw.com"), ("verizon",), kind="company"),
    Brand("tmobile", "T-Mobile", ("t-mobile.com",), ("t-mobile", "tmobile"), kind="company"),
    Brand("att", "AT&T", ("att.com",), ("at&t",), kind="company"),
)

BRAND_BY_KEY = {b.key: b for b in BRANDS}

SHORTENERS = frozenset(
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
        "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "bl.ink", "qrco.de",
        "shorte.st", "adf.ly", "v.gd", "tr.im", "x.co", "lnkd.in", "trib.al", "urlz.fr",
    }
)

FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com",
        "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
        "yandex.com", "zoho.com",
    }
)

# Minimal multi-part public suffixes so eTLD+1 is right for common cases.
_MULTI_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.nz", "co.in", "co.jp",
        "com.br", "com.mx", "co.za", "com.sg", "com.hk",
    }
)

# Affixes attackers glue onto brand names ("paypal-secure", "chaseonline").
PHISHY_AFFIXES = frozenset(
    {
        "secure", "security", "login", "signin", "verify", "verification", "support", "alert",
        "alerts", "online", "account", "accounts", "help", "service", "services", "bank",
        "banking", "update", "auth", "id", "portal", "customer", "care", "pay", "payment",
        "refund", "claim", "delivery", "track", "tracking", "package", "parcel", "us", "usa",
        "team", "center", "centre", "notice", "confirm", "app", "mail", "web", "my", "official",
        "gov", "resolution", "restore", "unlock", "billing", "cancel", "request", "wallet",
        "redelivery", "express", "check", "reset", "info", "hold",
    }
)

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


def registrable_domain(host: str) -> str:
    host = host.strip(".").lower()
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def official_brand_for_domain(domain: str) -> Brand | None:
    reg = registrable_domain(domain)
    for brand in BRANDS:
        if reg in brand.domains:
            return brand
    return None


def deleet(token: str) -> str:
    token = token.lower().translate(_LEET)
    return token.replace("rn", "m").replace("vv", "w")


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance (adjacent transpositions count as 1)."""
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


@dataclass(frozen=True)
class LookalikeMatch:
    brand: Brand
    domain: str
    technique: str  # typosquat | brand-in-domain | subdomain-trick | leetspeak


def _token_matches_brand(token: str, brand: Brand) -> str | None:
    if not token:
        return None
    key = brand.key
    raw = token.lower()
    norm = deleet(raw)
    if raw == key:
        return "brand-in-domain"
    if norm == key:
        return "leetspeak"
    # Brands under 6 letters sit one edit from ordinary words (chase/phase), so they
    # only match exactly, via leetspeak, or glued to a phishy affix.
    max_dist = 0 if len(key) < 6 else (1 if len(key) < 9 else 2)
    if max_dist and abs(len(norm) - len(key)) <= max_dist and damerau_levenshtein(norm, key) <= max_dist:
        return "typosquat"
    if norm.startswith(key) and norm[len(key):] in PHISHY_AFFIXES:
        return "brand-in-domain"
    if norm.endswith(key) and norm[: -len(key)] in PHISHY_AFFIXES:
        return "brand-in-domain"
    return None


def find_lookalike(host: str) -> LookalikeMatch | None:
    """Return a match if ``host`` imitates an allowlisted brand without being official."""
    host = host.lower().strip(".")
    if official_brand_for_domain(host):
        return None
    reg = registrable_domain(host)
    reg_label = reg.split(".")[0]
    sub_labels = host[: -len(reg)].strip(".").split(".") if host != reg else []

    for brand in BRANDS:
        # 1) the registrable label itself (paypa1.com, paypal-secure.com)
        candidates = [reg_label, *re.split(r"[-_]", reg_label)]
        for tok in candidates:
            technique = _token_matches_brand(tok, brand)
            if technique:
                return LookalikeMatch(brand, host, technique)
        # 2) brand used as a subdomain of an unrelated domain (paypal.com.evil.io)
        for label in sub_labels:
            for tok in [label, *re.split(r"[-_]", label)]:
                technique = _token_matches_brand(tok, brand)
                if technique:
                    return LookalikeMatch(brand, host, "subdomain-trick")
        # 3) full official domain embedded in a longer host (chase.com-login.net)
        for official in brand.domains:
            if re.search(r"(^|[.-])" + re.escape(official) + r"($|[.-])", host) and not host.endswith("." + official):
                return LookalikeMatch(brand, host, "subdomain-trick")
    return None


_alias_patterns: list[tuple[Brand, re.Pattern[str]]] = []
for _b in BRANDS:
    if _b.aliases:
        _alias_patterns.append(
            (_b, re.compile(r"(?<![\w.-])(" + "|".join(re.escape(a) for a in _b.aliases) + r")(?![\w-])", re.I))
        )
    if _b.case_sensitive_aliases:
        _alias_patterns.append(
            (_b, re.compile(r"(?<![\w.-])(" + "|".join(re.escape(a) for a in _b.case_sensitive_aliases) + r")(?![\w-])"))
        )


def find_brand_mentions(text: str) -> list[tuple[Brand, int, int]]:
    """Brand mentions in free text (not inside URLs/emails), sorted by position."""
    out: list[tuple[Brand, int, int]] = []
    for brand, pat in _alias_patterns:
        for m in pat.finditer(text):
            out.append((brand, m.start(), m.end()))
    out.sort(key=lambda t: t[1])
    return out


def brand_from_claim(claimed_sender: str | None) -> Brand | None:
    if not claimed_sender:
        return None
    mentions = find_brand_mentions(claimed_sender)
    if mentions:
        return mentions[0][0]
    squashed = re.sub(r"[^a-z]", "", claimed_sender.lower())
    for brand in BRANDS:
        if squashed == brand.key or squashed.startswith(brand.key):
            return brand
    return None
