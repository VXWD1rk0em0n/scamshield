from __future__ import annotations

from conftest import ZW, signals_for
from scamshield.models import IngestStatus


def test_nfkc_and_math_letters_are_normalised(config):
    s = signals_for(config, "\U0001D414\U0001D412\U0001D40F\U0001D412: your parcel is on hold, pay the fee today")
    assert s.analysis_text.startswith("USPS:")
    assert s.obfuscation.compat_chars == 4


def test_zero_width_is_stripped_and_counted_but_emoji_joiners_are_not_obfuscation(config):
    s = signals_for(config, f"Confirm your pass{ZW}word now at the portal please")
    assert "password" in s.analysis_text
    assert s.obfuscation.in_word_zero_width == 1 and s.obfuscation.detected
    family = signals_for(config, "Hi mom \U0001F468‍\U0001F469‍\U0001F467 landed safely, call you later")
    assert family.obfuscation.in_word_zero_width == 0 and not family.obfuscation.detected


def test_offset_map_points_back_to_display_text(config):
    s = signals_for(config, f"Enter your pass{ZW}word here at once please")
    start = s.analysis_text.index("password")
    d0, d1 = s.to_display(start, start + len("password"))
    assert s.display_text[d0:d1] == f"pass{ZW}word"


def test_homoglyphs_are_folded_and_reported(config):
    s = signals_for(config, "Log in to pаypаl now to keep your account open")
    assert "paypal" in s.analysis_text
    assert s.obfuscation.mixed_script_words == ("pаypаl",)


def test_url_extraction_flags_shortener_ip_punycode_and_homoglyph_hosts(config):
    s = signals_for(
        config,
        "See bit.ly/abc and http://192.168.1.20/login and https://xn--pypal-4ve.com/x and https://pаypal.com/y",
    )
    by_host = {u.host: u for u in s.urls}
    assert by_host["bit.ly"].is_shortener
    assert by_host["192.168.1.20"].is_ip_literal
    assert any(u.is_punycode for u in s.urls)
    assert by_host["paypal.com"].has_homoglyphs


def test_bare_domain_with_hyphenated_tld_trick_is_extracted_whole(config):
    s = signals_for(config, "Restore access at paypal.com-secure.info/restore right now")
    assert s.urls[0].host == "paypal.com-secure.info"
    assert s.urls[0].registrable_domain == "com-secure.info"


def test_brand_owned_shortener_is_not_flagged(config):
    s = signals_for(config, "Your order shipped, details: https://amzn.to/3abc and thanks")
    assert not s.urls[0].is_shortener


def test_entities_phone_amount_crypto(config):
    s = signals_for(config, "Send $1,200 or 0.5 BTC to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh then call (415) 555-0132")
    assert [a.value for a in s.amounts] == ["$1,200", "0.5 BTC"]
    assert s.crypto_addresses[0].value.startswith("bc1q")
    assert s.phones[0].value == "(415) 555-0132"


def test_email_domains_are_not_treated_as_links(config):
    s = signals_for(config, "Write to support@paypa1-help.com if you have any questions today")
    assert s.urls == ()
    assert s.emails[0].value == "support@paypa1-help.com"


def test_truncation_between_limits(config):
    text = "This is an ordinary sentence about the weather. " * 125  # ~6k chars
    s = signals_for(config, text)
    assert s.status is IngestStatus.OK and s.truncated and "truncated" in s.quality_flags
    assert len(s.display_text) == config.limits.truncate_at


def test_unsupported_language_non_latin_and_latin_foreign(config):
    assert signals_for(config, "Привет, это твой банк, срочно позвони нам сегодня").quality_flags == ("unsupported_language",)
    assert signals_for(config, "Hola, su cuenta está bloqueada, por favor llame para verificar los datos").quality_flags == (
        "unsupported_language",
    )


def test_english_with_one_homoglyph_word_is_still_supported(config):
    assert signals_for(config, "Your аccount is locked, verify it today").status is IngestStatus.OK


def test_bytes_input_utf8_is_decoded(config):
    assert signals_for(config, "Your package is out for delivery today".encode()).status is IngestStatus.OK
