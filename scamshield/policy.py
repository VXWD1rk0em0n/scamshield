"""Stage 5 - intervention policy. Maps the tier to a user-facing action.

Actions are never destructive: nothing is deleted or auto-reported. Every
action is logged, and the user can always override (appeal) it.
"""

from __future__ import annotations

from scamshield.models import Action, Intervention, RiskScore, RuleResult, Signals, Tier

_TIPS_BY_RULE = {
    "CREDENTIAL_REQUEST": "No real bank, company or government agency will ask you to send a password, PIN or one-time code.",
    "PAYMENT_METHOD": "Gift cards, crypto and wire transfers can't be reversed - legitimate organisations don't demand them.",
    "P2P_TRANSFER_REQUEST": "Treat app payments (Zelle, Venmo, Cash App) like cash: only send to people you have verified.",
    "LOOKALIKE_DOMAIN": "Check the link's real domain carefully - it imitates a brand you know. Type the official address yourself.",
    "SENDER_MISMATCH": "The sender doesn't match who the message claims to be. Contact the organisation through its official app or website.",
    "SHORTENED_URL": "Short links hide where they go. Don't open them from unexpected messages.",
    "IP_LITERAL_URL": "Real companies don't send links to bare IP addresses.",
    "NEW_NUMBER_FAMILY": "Call your family member on the number you already have saved before sending anything.",
    "TOO_GOOD_TO_BE_TRUE": "Unexpected prizes, guaranteed profits and easy high pay are classic lures.",
    "OFF_PLATFORM": "Moving you to WhatsApp/Telegram removes platform protections - be cautious.",
    "SECRECY": "Requests to keep something secret are a red flag. Talk to someone you trust first.",
    "OBFUSCATION": "The message uses hidden or disguised characters to slip past filters.",
    "PROMPT_INJECTION": "The message tries to trick AI filters into calling it safe.",
    "REMOTE_ACCESS": "Never install remote-access apps (AnyDesk, TeamViewer) for someone who contacted you.",
    "PAYMENT_REDIRECTION": "Confirm any change of bank details by phone using a number from a previous invoice, not this message.",
    "UPFRONT_FEE": "Paying a fee to release a package, prize, loan or job is a common scam.",
    "CALLBACK_LURE": "Don't call numbers from the message; use the number on your card or the official website.",
    "THREAT": "Threats of arrest or account closure are designed to rush you. Pause and verify independently.",
    "URGENCY": "Scammers create time pressure. Legitimate issues can wait for you to verify.",
}

_MEDIUM_BASE = (
    "Verify the sender through a channel you already trust (official app, website, saved number).",
    "Don't share codes, passwords or card details in reply to a message.",
)
_CRITICAL_CHECKLIST = (
    "Do not click links, reply, or call numbers in this message.",
    "Contact the sender through a number or app you already know (back of your card, official website, saved contact).",
    "If you already shared a code or password: change it now and contact your bank/provider's official fraud line.",
    "If you sent money: contact your bank immediately and ask about a recall or chargeback.",
    "Report the message (button below). You can also forward SMS scams to 7726 (SPAM) in the US/UK.",
)


def _tips(rules: RuleResult | None, limit: int = 4) -> tuple[str, ...]:
    if not rules:
        return ()
    tips = [_TIPS_BY_RULE[h.name] for h in rules.hits if h.name in _TIPS_BY_RULE]
    return tuple(dict.fromkeys(tips))[:limit]


def decide(signals: Signals, risk: RiskScore | None, rules: RuleResult | None) -> Intervention:
    if not signals.ok or risk is None:
        reason = ", ".join(signals.quality_flags) or "insufficient data"
        return Intervention(
            action=Action.UNABLE_TO_ANALYZE,
            tier=None,
            headline="We couldn't analyse this message",
            message=(
                f"Reason: {reason}. This is not a 'safe' verdict - if the message asks for money, codes or "
                "personal details, verify the sender through a channel you already trust."
            ),
            tips=_MEDIUM_BASE,
        )

    review = (
        "Our checks disagreed on this one, so a human analyst will review it. Treat it with caution meanwhile."
        if risk.needs_review
        else None
    )
    tips = _tips(rules)

    if risk.tier is Tier.LOW:
        return Intervention(
            action=Action.ALLOW,
            tier=risk.tier,
            headline="No scam indicators found",
            message="Nothing suspicious stood out. Stay alert if anything asks for money or codes later.",
            review_note=review,
        )
    if risk.tier is Tier.MEDIUM:
        return Intervention(
            action=Action.SOFT_WARN,
            tier=risk.tier,
            headline="Be careful - some warning signs",
            message="This message has some features common in scams. Check before acting on it.",
            tips=tips + _MEDIUM_BASE,
            review_note=review,
        )
    if risk.tier is Tier.HIGH:
        return Intervention(
            action=Action.INTERSTITIAL,
            tier=risk.tier,
            headline="Likely scam - links disabled",
            message=(
                "Links in this message are disabled until you confirm you understand the risk. "
                "Verify through the organisation's official app, website, or a number you already have."
            ),
            tips=tips,
            links_disabled=True,
            requires_confirmation=True,
            review_note=review,
        )
    return Intervention(
        action=Action.BLOCK_LINKS,
        tier=risk.tier,
        headline="Scam detected - do not respond",
        message=(
            "This message asks for a code, password or payment while impersonating someone. "
            "Links are blocked. Nothing has been deleted - you stay in control."
        ),
        tips=tips,
        checklist=_CRITICAL_CHECKLIST,
        links_disabled=True,
        requires_confirmation=True,
        recommend_report=True,
        review_note=review,
    )
