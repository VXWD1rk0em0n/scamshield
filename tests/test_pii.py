from __future__ import annotations

import pytest

from scamshield.pii import iban_valid, luhn_valid, mask_sender, mask_text


@pytest.mark.parametrize(
    "text, expected, kind",
    [
        ("Your code is 482913. Don't share it.", "Your code is [OTP].", "otp"),
        ("G-482913 is your Google verification code.", "[OTP] is your Google verification code.", "otp"),
        ("Call (415) 555-0132 today", "Call [PHONE] today", "phone"),
        ("or +44 7700 900123 please", "or [PHONE] please", "phone"),
        ("Mail john.doe@gmail.com now", "Mail [EMAIL]@gmail.com now", "email"),
        ("Card 4111 1111 1111 1111 exp", "Card [CARD] exp", "card"),
        ("SSN 123-45-6789 on file", "SSN [SSN] on file", "ssn"),
        ("IBAN GB82 WEST 1234 5698 7654 32 please", "IBAN [IBAN] please", "iban"),
        ("Go https://evil.com/login?user=bob&t=abc", "Go https://evil.com/login?[QUERY]", "query"),
        ("Go https://bob:hunter2@evil.com/x", "Go https://[CREDENTIALS]@evil.com/x", "credentials"),
    ],
)
def test_mask_types(text, expected, kind):
    res = mask_text(text)
    assert expected in res.text
    assert res.counts.get(kind, 0) >= 1


def test_luhn_invalid_number_is_not_labelled_card():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert "[CARD]" not in mask_text("ref 4111 1111 1111 1112").text


def test_iban_checksum():
    assert iban_valid("GB82 WEST 1234 5698 7654 32")
    assert not iban_valid("GB00 WEST 1234 5698 7654 32")


def test_zero_width_cannot_split_digits_past_masking():
    res = mask_text("card 4111​1111 1111 1111 now")
    assert "[CARD]" in res.text and "4111" not in res.text


def test_amounts_years_and_tracking_ids_are_kept():
    text = "Balance $100.00 in 2026, tracking 1Z999AA10123456784"
    assert mask_text(text).text == text


def test_masking_is_idempotent():
    once = mask_text("Code 123456, call (415) 555-0132, mail a@b.com").text
    assert mask_text(once).text == once


def test_mask_sender():
    assert mask_sender("+1 (415) 555-0132") == "[PHONE …32]"
    assert mask_sender("24273") == "24273"  # short code = organisation
    assert mask_sender("alerts@chase.com") == "[EMAIL]@chase.com"
    assert mask_sender("@lily_rose88") == "[HANDLE]"
    assert mask_sender(None) is None
