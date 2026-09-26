"""Stage 2a - deterministic rules / heuristics.

Each rule has a stable ID, a configurable weight (config/scamshield.toml) and a
human-readable reason. Rules read ``Signals.analysis_text`` (zero-width stripped,
homoglyphs folded) so obfuscation cannot hide keywords, and every hit carries
the exact spans that triggered it for evidence highlighting.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from scamshield import RULESET_VERSION
from scamshield.brands import (
    BRANDS,
    FREEMAIL_DOMAINS,
    Brand,
    brand_from_claim,
    damerau_levenshtein,
    deleet,
    find_brand_mentions,
    find_lookalike,
    official_brand_for_domain,
    registrable_domain,
)
from scamshield.config import Config
from scamshield.ingest import HOMOGLYPHS
from scamshield.models import RuleHit, RuleResult, Signals


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    name: str
    category: str  # pressure | request | impersonation | link | lure | obfuscation | benign
    description: str


RULE_SPECS: tuple[RuleSpec, ...] = (
    RuleSpec("R01", "URGENCY", "pressure", "Time pressure: 'immediately', 'within 24 hours', 'final notice'"),
    RuleSpec("R02", "THREAT", "pressure", "Threat of loss or punishment: suspension, arrest, legal action"),
    RuleSpec("R03", "CREDENTIAL_REQUEST", "request", "Asks for a password, one-time code, PIN, card or login details"),
    RuleSpec("R04", "PAYMENT_METHOD", "request", "Asks for payment by gift card, crypto, or wire/money transfer"),
    RuleSpec("R05", "P2P_TRANSFER_REQUEST", "request", "Asks for money over Zelle / Venmo / Cash App / PayPal"),
    RuleSpec("R06", "LOOKALIKE_DOMAIN", "impersonation", "Link or sender domain imitates a known brand"),
    RuleSpec("R07", "SENDER_MISMATCH", "impersonation", "Claimed sender does not match sender address or link domains"),
    RuleSpec("R08", "SHORTENED_URL", "link", "Link uses a URL shortener that hides the destination"),
    RuleSpec("R09", "IP_LITERAL_URL", "link", "Link points at a raw IP address instead of a domain"),
    RuleSpec("R10", "NEW_NUMBER_FAMILY", "impersonation", "'Hi Mum, this is my new number' family impersonation pattern"),
    RuleSpec("R11", "TOO_GOOD_TO_BE_TRUE", "lure", "Prize, guaranteed returns, or easy high pay"),
    RuleSpec("R12", "OFF_PLATFORM", "lure", "Pushes the conversation to WhatsApp / Telegram / Signal"),
    RuleSpec("R13", "SECRECY", "pressure", "Asks to keep it secret or not to verify with others"),
    RuleSpec("R14", "OBFUSCATION", "obfuscation", "Zero-width characters, homoglyphs, or disguised letters"),
    RuleSpec("R15", "PROMPT_INJECTION", "obfuscation", "Text aimed at manipulating an AI filter"),
    RuleSpec("R16", "REMOTE_ACCESS", "request", "Tech-support pattern: remote access tools, fake infection"),
    RuleSpec("R17", "PAYMENT_REDIRECTION", "request", "Claims bank/payment details changed; pay a new account"),
    RuleSpec("R18", "UPFRONT_FEE", "request", "Small fee to release a package, prize, job, or loan"),
    RuleSpec("R19", "CALLBACK_LURE", "request", "Pushes you to call a number in the message about a problem"),
    RuleSpec("R20", "AUTHORITY_CLAIM", "impersonation", "Claims to be a bank, government, company, or executive"),
    RuleSpec("R21", "POSSIBLE_LOOKALIKE_OCR", "link", "Screenshot link is one letter off an official domain - lookalike or OCR misread"),
    RuleSpec("N01", "PROTECTIVE_LANGUAGE", "benign", "Legitimate safety wording: 'we will never ask for your code'"),
    RuleSpec("N02", "OFFICIAL_LINKS_ONLY", "benign", "Every link goes to an official brand domain"),
    RuleSpec("N03", "KNOWN_CONTACT", "benign", "User marked the sender as a known contact"),
    RuleSpec("N04", "TRUSTED_SENDER", "benign", "Sender is on this user's trusted list"),
)
SPEC_BY_NAME = {s.name: s for s in RULE_SPECS}

REQUEST_RULES = frozenset(
    {"CREDENTIAL_REQUEST", "PAYMENT_METHOD", "P2P_TRANSFER_REQUEST", "PAYMENT_REDIRECTION", "UPFRONT_FEE"}
)
IMPERSONATION_RULES = frozenset({"LOOKALIKE_DOMAIN", "SENDER_MISMATCH", "NEW_NUMBER_FAMILY"})
# Benign signals an attacker can write into the message themselves are only
# credited when nothing suspicious fired; user-provided context always counts.
ATTACKER_CONTROLLED_BENIGN = frozenset({"PROTECTIVE_LANGUAGE", "OFFICIAL_LINKS_ONLY"})

Span = tuple[int, int]
Detection = tuple[str, list[Span]]  # (reason, spans)

I = re.IGNORECASE


def _rx(pattern: str, flags: int = I) -> re.Pattern[str]:
    return re.compile(pattern, flags)


def _all(patterns: list[re.Pattern[str]], text: str) -> list[Span]:
    spans: list[Span] = []
    for p in patterns:
        spans.extend(m.span() for m in p.finditer(text))
    return sorted(set(spans))


_CLAUSE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+|\s+[-–—]\s+")


def _clauses(text: str) -> list[Span]:
    out, pos = [], 0
    for m in _CLAUSE_SPLIT.finditer(text):
        if m.start() > pos:
            out.append((pos, m.start()))
        pos = m.end()
    if pos < len(text):
        out.append((pos, len(text)))
    return out


_NEGATION = _rx(r"\b(never|not|no one|nobody|without)\b|n['’]t\b")


def _negated_before(text: str, clause_start: int, pos: int, words: int = 5) -> bool:
    window = text[clause_start:pos]
    # stop at commas so "Do not ignore this, reply with your code" is not negated
    window = re.split(r"[,:]", window)[-1]
    tail = " ".join(window.split()[-words:])
    return bool(_NEGATION.search(tail))


# ----------------------------------------------------------------- lexicons

_URGENCY = [
    _rx(r"\burgent(ly)?\b|\bimmediate(ly)?\b|\bright away\b|\basap\b|\bas soon as possible\b"),
    _rx(r"\bact (now|fast|quickly)\b|\b(final|last) (notice|warning|reminder|chance|attempt)\b"),
    _rx(r"\bwithin (the next )?\d+\s*(hours?|hrs?|minutes?|mins?|days?)\b|\b(24|48|72)[- ]?(hours?|hrs?)\b"),
    _rx(r"\bexpires? (today|tonight|soon|in \d+)\b|\bbefore (it|they|the offer|this) expires?\b"),
    _rx(r"\b(before |by )?(the )?end of (the )?day\b|\bby (tonight|eod)\b|\blimited time\b"),
    _rx(r"\bdon['’]?t delay\b|\btime[- ]sensitive\b|\b(today|now),? or (else|your)\b"),
]
_THREAT = [
    _rx(r"\b(arrest(ed)?|warrant|legal action|lawsuit|prosecut\w+|criminal (charges?|case)|jail|deport\w*|court summons)\b"),
    _rx(
        r"\b(account|access|card|service|membership|benefits?|ssn|social security number|profile|mailbox|wallet)\b"
        r"[^.!?\n]{0,40}?\b(will be |has been |have been |is |was |being |are )?"
        r"(suspend|lock|block|terminat|disabl|limit|restrict|froz|freez|cancel|deactivat|delet|clos)\w*"
    ),
    _rx(r"\b(suspend|lock|terminat|deactivat|froz|freez|limit|restrict|block)\w*\s+(your|the)\s+(account|access|card|service|membership|benefits|number)\b"),
    _rx(r"\bto avoid\b[^.!?\n]{0,30}\b(suspension|closure|termination|penalt\w+|charges?|fees?|arrest|legal|cancellation|being (locked|charged|suspended|closed))"),
    _rx(r"\b(permanent(ly)?|irreversibl\w*)\s+(suspen\w*|clos\w*|delet\w*|loss|lock\w*)"),
]

_CRED_TERM = _rx(
    r"\b(one[- ]time (pass)?codes?|one[- ]time pins?|otps?|"
    r"(verification|security|auth(entication)?|access|log[- ]?in|sign[- ]?in|2fa|mfa|\d[- ]digit|confirmation) codes?|"
    r"codes?|pins?( number)?|pass(word|code|phrase)s?|credentials|log[- ]?in (details|info)|sign[- ]?in details|"
    r"user ?name and password|card (number|details|info(rmation)?)|cvv|cvc|security (question|answer)s?|"
    r"social security( number)?|ssn|bank(ing)? (details|login|password)|account (number|password)|routing number|"
    r"seed phrase|recovery phrase|private key|mother['’]?s maiden name)\b"
)
_CODE_NOT_SECRET_BEFORE = frozenset(
    "promo discount coupon zip postal dress source qr tracking area country error reference booking voucher "
    "referral bar colour color morse".split()
)
_CODE_NOT_SECRET_AFTER = _rx(r"^\s*(of conduct|review|base|snippet|repository|block)\b")

_EXFIL_VERB = _rx(
    r"\b(send|sending|share|give|tell|reply|respond|text|forward|provide|read|disclose|dictate|say)\b(?!\s+(you|u)\b)"
)
_ENTRY_VERB = _rx(
    r"\b(enter|confirm|verify|update|submit|input|type|re-?enter|use|log ?in|sign ?in|login|signin|provide)\b"
)
_HAVE_READY = _rx(r"\bhave\b[^.!?\n]{0,70}\bready\b")
_ASK_CODE = _rx(r"\b(what['’]?s|what is|tell me) (the|your) (\w+ )?(code|pin|password|otp)\b")
_VERIFY_ACCOUNT = _rx(
    r"\b(verify|confirm|validate|update|restore|unlock|secure|re-?activate|reactivate|re-?validate)\s+(your\s+)?"
    r"(identity|account|access|log[- ]?in|information|details|billing( information| details| info)?|"
    r"payment (info|information|details|method)|bank details|card)\b"
)
_PROTECTIVE_VERB = _rx(r"\b(ask|share|give|send|request|call|text|email|tell|disclose|forward|requested)\w*\b")
_PROTECTIVE_PHRASES = [
    _rx(r"\b(we|they|\w+) (will|would) never (ask|call|text|email|request)\b"),
    _rx(r"\bnever share\b|\bdo not share\b|\bdon['’]t share\b"),
    _rx(r"\bif (you|this) (did not|didn['’]t|was not|wasn['’]t) (request|make|authori[sz]e|initiate|you)\b"),
    _rx(r"\bif (this|it) was you,? (you )?(don['’]t|do not) need to do anything\b|\bno (further )?action (is )?(needed|required)\b"),
]

_GIFT = r"(gift ?cards?|itunes( gift)? cards?|google play( gift)? (cards?|codes?)|steam (cards?|wallet)|apple( gift)? cards?|amazon( gift)? cards?|vanilla (visa|cards?)|prepaid (visa |debit )?cards?|ebay gift cards?|target gift cards?|walmart gift cards?)"
_CRYPTO = r"(bitcoin|btc|usdt|tether|ethereum|eth|crypto(currency)?|crypto wallet|wallet address|litecoin|dogecoin|bitcoin atm|crypto atm)"
_WIRE = r"(wire transfer|wire (the|it|money|funds|payment|balance)|western union|moneygram|money ?gram|bank transfer|money transfer|transfer ([£$€]\s?\d[\d,.]*|the (money|funds))|cash (by|in the) (mail|courier))"
_PAYMENT_TERM = _rx(r"\b(" + _GIFT + "|" + _CRYPTO + "|" + _WIRE + r")\b")
_PAY_VERB = _rx(
    r"\b(buy|purchase|pay|paying|send|deposit|transfer|wire|get|pick up|load|scratch|invest|convert|move|remit|process|make)\b"
)
_P2P_TERM = _rx(r"\b(zelle|venmo|cash ?app|paypal|apple cash)\b")
_P2P_VERB = _rx(r"\b(send|pay|transfer|venmo me|zelle me|cash ?app me|paypal me|request)\b")

_NEW_NUMBER = [
    _rx(r"\b(this is )?my new (phone )?number\b|\bnew (phone )?number\b"),
    _rx(r"\b(lost|broke|dropped|smashed) my phone\b|\bmy (old )?phone (broke|is broken|died|fell|got (stolen|lost|damaged|wet)|was stolen)"),
    _rx(r"\btexting (you )?from (a |my )?(friend['’]?s|new|different|borrowed)\b|\bsave (this|my new) number\b|\bdelete (the|my) old number\b"),
]
_FAMILY = _rx(r"\b(mum|mom|mommy|mama|dad|daddy|papa|grandma|granny|grandpa|nan|nana|son|daughter|auntie|aunt|uncle)\b|\bit['’]?s me\b")

_TOO_GOOD = [
    _rx(r"\bcongratulations\b|\byou['’]?(ve| have)? (won|been selected|been chosen)\b|\blucky (winner|customer|draw)\b"),
    _rx(r"\b(prize|lottery|jackpot|sweepstakes|giveaway)\b|\bclaim your (reward|prize|gift|funds|refund|winnings)\b"),
    _rx(r"\bfree (iphone|ipad|gift|money|vacation|cruise|laptop)\b|\bguaranteed (returns?|profits?|income|income)\b|\brisk[- ]free\b"),
    _rx(r"\bdouble your (money|crypto|bitcoin|investment|btc)\b|\b\d+\s?% (returns?|profits?|interest)? ?(every|per|each|a) (day|week|month)\b"),
    _rx(r"\bearn \$?\d[\d,]*(\s?[-–]\s?\$?\d[\d,]*)?\s?(per|a|each|/)\s?(day|week|hour|hr)\b|\bearn \$?\d[\d,]*(\s?[-–]\s?\$?\d[\d,]*)? daily\b|\$\d[\d,]*(\s?[-–]\s?\$?\d[\d,]*)? (daily|a day|per day)\b"),
    _rx(r"\bno experience (needed|required|necessary)\b|\bnever (have to )?repay\b|\bpre-?approved\b|\bwork from home and earn\b"),
    _rx(r"\bsend \S+ (btc|eth|bitcoin|ethereum|usdt)\b[^.!?\n]{0,40}\b(receive|get)\b|\b(eligible for|entitled to|owed) (a |an )?(\$[\d,.]+ )?(tax )?(refund|rebate|compensation|payout|reward|grant)\b"),
    _rx(r"\b(unclaimed|pending) (funds|refund|prize|reward|inheritance)\b|\binheritance\b"),
]
_MESSENGERS = r"(whats ?app|telegram|signal|wechat|kik|viber|snapchat|line app|google chat|hangouts)"
_OFF_PLATFORM = [
    _rx(r"\b(contact|message|text|reach|add|talk|chat|continue|move|switch|dm|write|speak)\b[^.!?\n]{0,40}\b(on|via|through|over|to|at)\s+" + _MESSENGERS + r"\b"),
    _rx(r"\b(my|our) " + _MESSENGERS + r"( username| handle| number| id| is|:)"),
    _rx(r"\b" + _MESSENGERS + r"\b[^.!?\n]{0,30}@\w+"),
    _rx(r"\bdon['’]?t (really )?use this (app|site|platform) (much|often)\b"),
]
_SECRECY = [
    _rx(r"\bkeep (this|it) (between us|quiet|confidential|secret|private|to yourself)\b|\bbetween (you and me|us)\b"),
    _rx(r"\b(don['’]?t|do not|please don['’]?t) (tell|mention|inform|discuss|call|contact)\b[^.!?\n]{0,25}\b(anyone|anybody|family|bank|wife|husband|parents|mom|mum|dad|kids|others|office|line|colleagues|manager|police)\b"),
    _rx(r"\b(this is|strictly|highly) (confidential|private|secret)\b|\bdo not discuss (this )?with anyone\b"),
    _rx(r"\bcan['’]?t (talk|take (any )?calls|speak) (right now|now|today)?|\bin (a )?meetings? all day\b"),
    _rx(r"\bdo not call (our|the|my|this)\b"),
]
_INJECTION = [
    _rx(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,30}\b(previous|prior|above|all|earlier|your|the|any)\b[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directions|system)\b"),
    _rx(r"\b(rate|classify|mark|label|score|flag|treat|consider|report)\b[^.\n]{0,30}\b(this|message|email|text|it)\b[^.\n]{0,20}\b(as )?(safe|legitimate|legit|benign|harmless|trusted|low[- ]risk|not (a )?(scam|spam|phishing|fraud))\b"),
    _rx(r"\b(system|developer|admin(istrator)?) (prompt|message|instruction|note|override)\b|^\s*system\s*:|\bsystem\s*:\s"),
    _rx(r"\b(note|message|instructions?) (to|for) (the )?(ai|assistant|model|llm|classifier|filter|bot|chatgpt|claude|scanner)\b"),
    _rx(r"\byou are (now )?(an? )?(ai|assistant|language model|chatgpt|claude)\b|\bas an ai\b"),
    _rx(r"\b(verified|confirmed|certified) (as )?(legitimate|safe|authentic) by\b|</?\s*(system|instructions?|untrusted_message)[^>]*>"),
]
_REMOTE = [
    _rx(r"\b(anydesk|teamviewer|ultraviewer|logmein|supremo|connectwise|screenconnect|quick ?support|rustdesk)\b"),
    _rx(r"\bremote (access|desktop|control|session|support)\b|\bscreen ?shar\w*\b"),
    _rx(r"\b(your )?(computer|pc|device|laptop|phone|system) (has been|is|was|may be) (infected|hacked|compromised|locked)\b"),
    _rx(r"\b(virus|trojan|malware|spyware|ransomware)\b[^.!?\n]{0,30}\b(detected|found|infected|installed)\b"),
    _rx(r"\b(call|contact) (windows|microsoft|apple|norton|mcafee|geek squad) (support|technician|help ?desk)\b"),
    _rx(r"\bdo not (shut down|turn off|restart|close)\b"),
]
_REDIRECTION = [
    _rx(r"\b(bank(ing)?|account|payment|wire|remittance|beneficiary|vendor) (details|information|info|instructions)\b[^.!?\n]{0,30}\b(have |has )?(changed|been (changed|updated)|updated)\b"),
    _rx(r"\b(new|updated|changed|different) (bank(ing)?|payment|wire|remittance|beneficiary) (details|information|info|instructions|account)\b"),
    _rx(r"\b(remit|redirect|send|make|route)\b[^.!?\n]{0,40}\b(payments?|invoices?|funds)\b[^.!?\n]{0,30}\b(new|different|updated|below|following) (account|bank)"),
    _rx(r"\bchange of (bank|account|payment)\b"),
]
_UPFRONT_FEE = [
    _rx(r"\b(redelivery|re-delivery|delivery|shipping|customs|clearance|processing|release|activation|registration|training|equipment|handling|administration|admin|unlock|verification|transfer|tax|insurance) (fee|charge|duty|duties)\b"),
    _rx(r"\bcustoms dut(y|ies)\b|\b(small|one-time|nominal|refundable) fee\b|\bpay (a |the )?(small |one-time |\$[\d.,]+ )?fee\b"),
    _rx(r"\bpurchase (equipment|supplies|software|a laptop)\b[^.!?\n]{0,40}\bvendor\b"),
    _rx(r"\b(send|mail) you a (check|cheque)\b[^.!?\n]{0,80}\b(deposit|wire|send back|return|forward)\b"),
]
_CALL_VERB = _rx(r"\b(call|dial|ring|contact|phone|speak (to|with)|press\s*1)\b")
_CALLBACK_CONTEXT = [
    _rx(r"\bif (this|it) (was|is|wasn['’]t|was not|is not)( not)? you\b|\bdid(n['’]t| not) (make|authori[sz]e|request|attempt)\b"),
    _rx(r"\bto (cancel|dispute|stop|reverse|block|report)\b|\bfraud (department|team|specialist|line)\b|\bspeak (to|with) an? (officer|agent)\b"),
]
_AUTHORITY_GENERIC = [
    _rx(r"\b(irs|fbi|police|sheriff|customs and border|immigration|dmv|medicare|tax (office|department|authority)|federal (agent|government)|government agency)\b"),
    _rx(r"\b(ceo|cfo|coo|cto|managing director|your (boss|manager|supervisor)|hr (department|team)|payroll( department)?|it (department|support)|help ?desk)\b"),
    _rx(r"\b(fraud (department|team|prevention|specialist|alert)|security (team|department)|support team|customer (service|support|care)|account services|technician)\b"),
]
_ORG_SUFFIX = _rx(r"\b(inc|llc|ltd|co|corp|corporation|bank|support|security|team|department|services|group)\b\.?")
_EXEC_TITLE = _rx(r"\b(ceo|cfo|coo|cto|president|chairman|director|founder|owner|boss|manager)\b")

_GENERIC_ORG_WORDS = frozenset("inc llc ltd co corp the and of company group services team support".split())


# ----------------------------------------------------------------- helpers


_CLAIM_PREFIX = _rx(r"\b(this is|from|dear|message from|on behalf of|welcome to|via|sent by)\s+(the\s+)?$")
_CLAIM_SUFFIX = _rx(
    r"^(\s*[:\])|]|\s+(alert|alerts|security|support|notice|fraud|team|customer|account|id|services?|bank|"
    r"notification|warning|update|verification|billing|delivery|express|tracking|care|help|online|mobile|"
    r"member|department|administration|officer|agent)\b)"
)
_YOUR_SUFFIX = _rx(
    r"^(\s+\d+)?\s+(account|id|order|package|parcel|membership|subscription|card|mailbox|wallet|payment|"
    r"delivery|shipment|profile|email|login|password|verification|code|benefits|number|refund)\b"
)


def brand_claims(text: str) -> list[tuple[Brand, int, int]]:
    """Brand mentions in a *claiming* position ("Chase Alert:", "from PayPal", "your
    Amazon account") as opposed to incidental ones ("buy Apple gift cards")."""
    out = []
    for brand, start, end in find_brand_mentions(text):
        before = text[max(0, start - 25) : start]
        after = text[end : end + 30]
        at_start = text[:start].strip(" \t\n[(*#-") == ""
        if (
            at_start
            or _CLAIM_SUFFIX.match(after)
            or _CLAIM_PREFIX.search(before)
            or (re.search(r"\byour\s+$", before, I) and _YOUR_SUFFIX.match(after))
        ):
            out.append((brand, start, end))
    return out


def _claimed_brand(signals: Signals) -> tuple[Brand | None, list[Span]]:
    brand = brand_from_claim(signals.claimed_sender)
    claims = [c for c in brand_claims(signals.analysis_text) if not _in_url(signals, c[1])]
    if brand:
        return brand, [(s, e) for b, s, e in claims if b is brand]
    if claims:
        b = claims[0][0]
        return b, [(s, e) for bb, s, e in claims if bb is b]
    return None, []


def _in_url(signals: Signals, pos: int) -> bool:
    return any(u.start <= pos < u.end for u in signals.urls) or any(e.start <= pos < e.end for e in signals.emails)


def _sender_email_domain(signals: Signals) -> str | None:
    if signals.sender_id and "@" in signals.sender_id:
        return signals.sender_id.rsplit("@", 1)[-1].strip().strip(">").lower()
    return None


def _sender_digits(signals: Signals) -> str:
    if not signals.sender_id or "@" in signals.sender_id:
        return ""
    return re.sub(r"\D", "", signals.sender_id)


def _is_code_secret(text: str, m: re.Match[str]) -> bool:
    term = m.group(0).lower()
    if not re.fullmatch(r"codes?", term):
        return True
    before = text[: m.start()].split()
    prev = re.sub(r"\W", "", before[-1].lower()) if before else ""
    if prev in _CODE_NOT_SECRET_BEFORE:
        return False
    return not _CODE_NOT_SECRET_AFTER.match(text[m.end() :])


def _non_official_urls(signals: Signals) -> list:
    return [
        u
        for u in signals.urls
        if u.is_ip_literal or u.has_homoglyphs or u.is_punycode or official_brand_for_domain(u.host) is None
    ]


# ----------------------------------------------------------------- detectors


def _d_urgency(s: Signals, _: dict) -> Detection | None:
    spans = _all(_URGENCY, s.analysis_text)
    return ("Pressures you to act fast", spans) if spans else None


def _d_threat(s: Signals, _: dict) -> Detection | None:
    spans = _all(_THREAT, s.analysis_text)
    return ("Threatens account loss, penalties or legal action", spans) if spans else None


def _credential_analysis(s: Signals) -> tuple[list[Span], list[Span]]:
    """Returns (request spans, protective spans)."""
    text = s.analysis_text
    request: list[Span] = []
    protective: list[Span] = []
    has_bad_link = bool(_non_official_urls(s))
    for c_start, c_end in _clauses(text):
        clause = text[c_start:c_end]
        terms = [m for m in _CRED_TERM.finditer(clause) if _is_code_secret(clause, m)]
        if not terms:
            continue
        for term in terms:
            t_abs = (c_start + term.start(), c_start + term.end())
            # exfiltration verb before the credential ("reply with the code")
            exfil = [v for v in _EXFIL_VERB.finditer(clause[: term.start()]) if term.start() - v.end() <= 60]
            entry = [v for v in _ENTRY_VERB.finditer(clause[: term.start()]) if term.start() - v.end() <= 60]
            possessive = re.search(r"\byour\b(\s+\S+){0,5}\s*$", clause[: term.start()], I)
            verb_hits = []
            for v in exfil:
                verb_hits.append(v)
            if has_bad_link and possessive:
                verb_hits.extend(entry)
            negated = any(_negated_before(text, c_start, c_start + v.start()) for v in verb_hits)
            neg_protective = bool(_NEGATION.search(clause[: term.start()])) and bool(
                _PROTECTIVE_VERB.search(clause)
            )
            if verb_hits and not negated:
                v = verb_hits[-1]
                request.append((c_start + v.start(), t_abs[1]))
            elif verb_hits and negated or neg_protective:
                protective.append(t_abs)
        # "have your password and the code ready"
        for m in _HAVE_READY.finditer(clause):
            if any(m.start() <= t.start() < m.end() for t in terms) and not _negated_before(text, c_start, c_start + m.start()):
                request.append((c_start + m.start(), c_start + m.end()))
    for m in _ASK_CODE.finditer(text):
        request.append(m.span())
    if has_bad_link:
        for c_start, c_end in _clauses(text):
            for m in _VERIFY_ACCOUNT.finditer(text, c_start, c_end):
                if not _negated_before(text, c_start, m.start()):
                    request.append(m.span())
    return sorted(set(request)), sorted(set(protective))


def _d_credential(s: Signals, _: dict) -> Detection | None:
    request, _protective = _credential_analysis(s)
    if not request:
        return None
    return ("Asks you to hand over a code, password, PIN, or login/card details", request)


def _clause_pair(text: str, term_rx: re.Pattern[str], verb_rx: re.Pattern[str]) -> list[Span]:
    spans: list[Span] = []
    for c_start, c_end in _clauses(text):
        clause = text[c_start:c_end]
        terms = list(term_rx.finditer(clause))
        verbs = list(verb_rx.finditer(clause))
        if not terms or not verbs:
            continue
        for v in verbs:
            if _negated_before(text, c_start, c_start + v.start()):
                continue
            for t in terms:
                spans.append((c_start + t.start(), c_start + t.end()))
            spans.append((c_start + v.start(), c_start + v.end()))
            break
    return sorted(set(spans))


def _d_payment(s: Signals, _: dict) -> Detection | None:
    spans = _clause_pair(s.analysis_text, _PAYMENT_TERM, _PAY_VERB)
    if s.crypto_addresses and _PAY_VERB.search(s.analysis_text):
        spans += [(c.start, c.end) for c in s.crypto_addresses]
    if not spans:
        return None
    return ("Asks for payment by gift card, cryptocurrency, or wire/money transfer (hard to reverse)", sorted(set(spans)))


def _d_p2p(s: Signals, _: dict) -> Detection | None:
    spans = _clause_pair(s.analysis_text, _P2P_TERM, _P2P_VERB)
    return ("Asks you to send money over a peer-to-peer app", spans) if spans else None


def _ocr_ambiguous_typo(s: Signals, host: str) -> Brand | None:
    """For screenshot input only: a host one letter off an official brand domain could be a
    typosquat or an OCR misread ('amazan.com'). Leetspeak, brand+affix and subdomain tricks
    are never ambiguous and still count as lookalikes."""
    if "from_image" not in s.quality_flags:
        return None
    match = find_lookalike(host)
    if not match or match.technique != "typosquat":
        return None
    label = registrable_domain(host).split(".")[0]
    return match.brand if damerau_levenshtein(deleet(label), match.brand.key) <= 1 else None


def _brand_lookalikes(s: Signals) -> list[tuple[str, str, Span | None]]:
    """(domain, explanation, span) for every lookalike host found."""
    found: list[tuple[str, str, Span | None]] = []
    for u in s.urls:
        official = official_brand_for_domain(u.host)
        if (u.has_homoglyphs or u.is_punycode) and official:
            found.append((u.host, f"'{u.host}' spells {official.display} with look-alike Unicode letters", (u.start, u.end)))
            continue
        if _ocr_ambiguous_typo(s, u.host):
            continue  # reported by POSSIBLE_LOOKALIKE_OCR instead
        match = find_lookalike(u.host)
        if match:
            found.append((u.host, f"'{u.host}' imitates {match.brand.display} ({match.technique})", (u.start, u.end)))
    domains = [(e.value.rsplit("@", 1)[-1].lower(), (e.start, e.end)) for e in s.emails]
    sender_dom = _sender_email_domain(s)
    if sender_dom:
        domains.append((sender_dom, None))
    for dom, span in domains:
        match = find_lookalike(dom)
        if match:
            found.append((dom, f"sender domain '{dom}' imitates {match.brand.display} ({match.technique})", span))
    return found


def _claimed_org_tokens(claimed: str | None) -> list[str]:
    if not claimed:
        return []
    words = re.findall(r"[a-z]+", claimed.lower())
    return [w for w in words if len(w) >= 4 and w not in _GENERIC_ORG_WORDS]


def _claimed_org_lookalikes(s: Signals) -> list[tuple[str, str, Span | None]]:
    """Digit-for-letter spoofs of a claimed organisation not in the brand list (acme-supp1y.com)."""
    tokens = _claimed_org_tokens(s.claimed_sender)
    if not tokens:
        return []
    hosts: list[tuple[str, Span | None]] = [(u.host, (u.start, u.end)) for u in s.urls]
    sender_dom = _sender_email_domain(s)
    if sender_dom:
        hosts.append((sender_dom, None))
    out = []
    for host, span in hosts:
        label = registrable_domain(host).split(".")[0]
        raw = re.sub(r"[^a-z0-9]", "", label)
        norm = deleet(raw)
        if raw == norm:
            continue
        spoofed = [t for t in tokens if t in norm and t not in raw]
        if spoofed:
            out.append((host, f"'{host}' swaps letters for digits to imitate '{s.claimed_sender}'", span))
    return out


def _d_lookalike(s: Signals, _: dict) -> Detection | None:
    found = _brand_lookalikes(s) + _claimed_org_lookalikes(s)
    if not found:
        return None
    reason = "; ".join(dict.fromkeys(f[1] for f in found))
    return (f"Lookalike domain: {reason}", [f[2] for f in found if f[2]])


def _d_sender_mismatch(s: Signals, ctx: dict) -> Detection | None:
    brand, brand_spans = ctx["claimed_brand"]
    reasons: list[str] = []
    spans: list[Span] = list(brand_spans[:1])
    sender_dom = _sender_email_domain(s)
    claimed_text = (s.claimed_sender or "") + " " + s.analysis_text[:200]
    if brand:
        if sender_dom and registrable_domain(sender_dom) not in brand.domains:
            reasons.append(f"claims to be {brand.display} but the sender address is @{sender_dom}")
        digits = _sender_digits(s)
        if len(digits) >= 10 and brand.kind in {"bank", "government", "delivery", "payments"}:
            reasons.append(f"{brand.display} alerts come from short codes, not a personal-looking number")
        for u in s.urls:
            reg = u.registrable_domain
            other_official = official_brand_for_domain(u.host)
            if _ocr_ambiguous_typo(s, u.host) is brand:
                continue  # one letter off the brand's own domain in a screenshot: see POSSIBLE_LOOKALIKE_OCR
            if u.has_homoglyphs or u.is_punycode or (reg not in brand.domains and other_official is None):
                reasons.append(f"claims to be {brand.display} but links to {u.host}")
                spans.append((u.start, u.end))
    if sender_dom and registrable_domain(sender_dom) in FREEMAIL_DOMAINS and _EXEC_TITLE.search(claimed_text):
        reasons.append(f"an executive/manager writing from personal webmail (@{sender_dom})")
    if not reasons:
        return None
    return ("Sender mismatch: " + "; ".join(dict.fromkeys(reasons)), spans)


def _d_shortener(s: Signals, _: dict) -> Detection | None:
    urls = [u for u in s.urls if u.is_shortener]
    if not urls:
        return None
    hosts = ", ".join(sorted({u.host for u in urls}))
    return (f"Shortened link ({hosts}) hides the real destination; not expanded (no network fetch)", [(u.start, u.end) for u in urls])


def _d_ip_url(s: Signals, _: dict) -> Detection | None:
    urls = [u for u in s.urls if u.is_ip_literal]
    return ("Link points to a raw IP address, not a named website", [(u.start, u.end) for u in urls]) if urls else None


def _d_new_number(s: Signals, _: dict) -> Detection | None:
    text = s.analysis_text
    spans = _all(_NEW_NUMBER, text)
    if not spans:
        return None
    family = [m.span() for m in _FAMILY.finditer(text)]
    if not family and s.channel.value == "email":
        return None
    return ("'New number' pattern: someone claiming to be family/friend on an unknown number", spans + family[:1])


def _simple(patterns: list[re.Pattern[str]], reason: str) -> Callable[[Signals, dict], Detection | None]:
    def _detect(s: Signals, _: dict) -> Detection | None:
        spans = _all(patterns, s.analysis_text)
        return (reason, spans) if spans else None

    return _detect


def _d_obfuscation(s: Signals, _: dict) -> Detection | None:
    ob = s.obfuscation
    reasons: list[str] = []
    spans: list[Span] = []
    text = s.analysis_text
    if ob.in_word_zero_width:
        reasons.append(f"{ob.in_word_zero_width} invisible character(s) hidden inside words")
        for p in ob.zero_width_display_positions:
            # the analysis index where the invisible char was removed
            i = next((k for k, d in enumerate(s.offset_map) if d > p), len(text))
            start = i
            while start > 0 and text[start - 1].isalnum():
                start -= 1
            end = i
            while end < len(text) and text[end].isalnum():
                end += 1
            if end > start:
                spans.append((start, end))
    if ob.bidi_controls:
        reasons.append("right-to-left override characters that can disguise text")
    if ob.mixed_script_words:
        reasons.append("words mixing Latin with Cyrillic/Greek look-alike letters: " + ", ".join(ob.mixed_script_words[:3]))
        folded = {w.translate(str.maketrans(HOMOGLYPHS)) for w in ob.mixed_script_words}
        for w in folded:
            spans.extend(m.span() for m in re.finditer(re.escape(w), text))
    if ob.compat_chars >= 3:
        reasons.append(f"{ob.compat_chars} stylised (math/fullwidth) letters used to dodge filters")
    for u in s.urls:
        if u.is_punycode:
            reasons.append(f"internationalised (punycode) domain {u.host}")
            spans.append((u.start, u.end))
    if not reasons:
        return None
    return ("Obfuscation: " + "; ".join(reasons), spans)


def _d_callback(s: Signals, ctx: dict) -> Detection | None:
    text = s.analysis_text
    if not (ctx["authority_claimed"] and (ctx["pressure"] or _all(_CALLBACK_CONTEXT, text))):
        return None
    spans: list[Span] = []
    for c_start, c_end in _clauses(text):
        verb = _CALL_VERB.search(text, c_start, c_end)
        phone = next((p for p in s.phones if c_start <= p.start < c_end), None)
        if verb and (phone or "press" in verb.group(0).lower()):
            spans.append(verb.span())
            if phone:
                spans.append((phone.start, phone.end))
    return ("Pushes you to call a number supplied in the message (callback scam)", spans) if spans else None


def _d_authority(s: Signals, ctx: dict) -> Detection | None:
    brand, brand_spans = ctx["claimed_brand"]
    spans = list(brand_spans) + _all(_AUTHORITY_GENERIC, s.analysis_text)
    claimed = s.claimed_sender or ""
    who: list[str] = []
    if brand:
        who.append(brand.display)
    if claimed and (_ORG_SUFFIX.search(claimed) or _EXEC_TITLE.search(claimed) or brand_from_claim(claimed)):
        who.append(f"'{claimed}'")
    if not spans and not who:
        return None
    label = ", ".join(dict.fromkeys(who)) or "an authority/organisation"
    return (f"Claims to be {label}; identity is not verified", spans)


def _d_protective(s: Signals, _: dict) -> Detection | None:
    _request, protective = _credential_analysis(s)
    spans = protective + _all(_PROTECTIVE_PHRASES, s.analysis_text)
    return ("Contains standard safety wording used by legitimate senders", sorted(set(spans))) if spans else None


def _d_official_links(s: Signals, _: dict) -> Detection | None:
    if not s.urls or _non_official_urls(s):
        return None
    brands = sorted({official_brand_for_domain(u.host).display for u in s.urls})  # type: ignore[union-attr]
    return (f"All links go to official {', '.join(brands)} domains", [(u.start, u.end) for u in s.urls])


def _d_possible_ocr_lookalike(s: Signals, _: dict) -> Detection | None:
    hits = [(u, b) for u in s.urls if (b := _ocr_ambiguous_typo(s, u.host))]
    if not hits:
        return None
    names = ", ".join(sorted({f"'{u.host}' (vs {b.display})" for u, b in hits}))
    return (
        f"Link {names} is one letter off the official domain - either a lookalike or a misread of the "
        "screenshot. Check the link in the original message letter by letter.",
        [(u.start, u.end) for u, _ in hits],
    )


def _d_known_contact(s: Signals, _: dict) -> Detection | None:
    return ("You marked this sender as a known contact", []) if s.known_contact else None


def _d_trusted(s: Signals, ctx: dict) -> Detection | None:
    return ("Sender is on your trusted list", []) if ctx["trusted_sender"] else None


DETECTORS: dict[str, Callable[[Signals, dict], Detection | None]] = {
    "URGENCY": _d_urgency,
    "THREAT": _d_threat,
    "CREDENTIAL_REQUEST": _d_credential,
    "PAYMENT_METHOD": _d_payment,
    "P2P_TRANSFER_REQUEST": _d_p2p,
    "LOOKALIKE_DOMAIN": _d_lookalike,
    "SENDER_MISMATCH": _d_sender_mismatch,
    "SHORTENED_URL": _d_shortener,
    "IP_LITERAL_URL": _d_ip_url,
    "NEW_NUMBER_FAMILY": _d_new_number,
    "TOO_GOOD_TO_BE_TRUE": _simple(_TOO_GOOD, "Offer that is too good to be true (prize, guaranteed profit, easy money)"),
    "OFF_PLATFORM": _simple(_OFF_PLATFORM, "Tries to move you to another messaging platform"),
    "SECRECY": _simple(_SECRECY, "Asks for secrecy or discourages you from verifying"),
    "OBFUSCATION": _d_obfuscation,
    "PROMPT_INJECTION": _simple(_INJECTION, "Contains instructions aimed at AI filters (prompt injection)"),
    "REMOTE_ACCESS": _simple(_REMOTE, "Tech-support scam pattern (fake infection / remote-access tool)"),
    "PAYMENT_REDIRECTION": _simple(_REDIRECTION, "Claims payment/bank details changed - classic invoice redirection"),
    "UPFRONT_FEE": _simple(_UPFRONT_FEE, "Asks for a fee up front to release a package, prize, job or funds"),
    "CALLBACK_LURE": _d_callback,
    "AUTHORITY_CLAIM": _d_authority,
    "POSSIBLE_LOOKALIKE_OCR": _d_possible_ocr_lookalike,
    "PROTECTIVE_LANGUAGE": _d_protective,
    "OFFICIAL_LINKS_ONLY": _d_official_links,
    "KNOWN_CONTACT": _d_known_contact,
    "TRUSTED_SENDER": _d_trusted,
}


def run_rules(signals: Signals, config: Config, *, trusted_sender: bool = False) -> RuleResult:
    if not signals.ok:
        return RuleResult((), 0, 0, False, None, RULESET_VERSION)

    ctx: dict = {"trusted_sender": trusted_sender, "claimed_brand": _claimed_brand(signals)}
    hits: dict[str, RuleHit] = {}

    def _run(name: str) -> None:
        det = DETECTORS[name](signals, ctx)
        if det is None:
            return
        reason, spans = det
        spec = SPEC_BY_NAME[name]
        text = signals.analysis_text
        snippets = tuple(dict.fromkeys(text[a:b] for a, b in spans if b > a))[:5]
        hits[name] = RuleHit(spec.rule_id, name, spec.category, config.weight(name), reason, tuple(spans), snippets)

    # Order matters only for context-dependent rules (callback needs authority + pressure).
    for name in ("URGENCY", "THREAT", "SECRECY", "AUTHORITY_CLAIM"):
        _run(name)
    ctx["authority_claimed"] = "AUTHORITY_CLAIM" in hits
    ctx["pressure"] = bool({"URGENCY", "THREAT"} & hits.keys())
    for name in DETECTORS:
        if name not in hits and name not in {"URGENCY", "THREAT", "SECRECY", "AUTHORITY_CLAIM"}:
            _run(name)

    suspicious = [
        h for h in hits.values() if h.category in {"request", "obfuscation", "link"} or h.name in IMPERSONATION_RULES
    ]
    if suspicious:
        for name in ATTACKER_CONTROLLED_BENIGN:
            hits.pop(name, None)

    verified = signals.known_contact or trusted_sender
    impersonation = bool(IMPERSONATION_RULES & hits.keys()) or ("AUTHORITY_CLAIM" in hits and not verified)
    request = REQUEST_RULES & hits.keys()
    combo = bool(request) and impersonation
    combo_reason = None
    if combo:
        imp = sorted(IMPERSONATION_RULES & hits.keys()) or ["AUTHORITY_CLAIM (unverified)"]
        combo_reason = f"{' + '.join(sorted(request))} combined with {' + '.join(imp)}"

    ordered = tuple(sorted(hits.values(), key=lambda h: (h.weight < 0, -abs(h.weight), h.rule_id)))
    raw = sum(h.weight for h in ordered)
    return RuleResult(ordered, raw, max(0, min(100, raw)), combo, combo_reason, RULESET_VERSION)
