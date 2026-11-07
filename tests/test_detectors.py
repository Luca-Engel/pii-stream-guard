import pytest

from pii_stream_guard import (
    DEFAULT_DETECTORS,
    Detector,
    compile_detectors,
    redact,
)

EMAIL_TOKEN = "[REDACTED_EMAIL]"
AHV_TOKEN = "[REDACTED_AHV]"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # --- Email: common formats are redacted ---
        ("max.muster@example.ch", EMAIL_TOKEN),
        ("MAX.Muster@Example.CH", EMAIL_TOKEN),
        ("jürg.müller@zürich.ch", EMAIL_TOKEN),  # non-ASCII letters
        ("first+tag_1%x-y@sub.mail.example.com", EMAIL_TOKEN),
        # --- Email: surrounding punctuation is kept ---
        ("Mail an max@example.ch.", f"Mail an {EMAIL_TOKEN}."),
        ("(max@example.ch)", f"({EMAIL_TOKEN})"),
        (
            "<max@example.ch>, <eva@example.org>",
            f"<{EMAIL_TOKEN}>, <{EMAIL_TOKEN}>",
        ),
        ("mailto:max@example.ch", f"mailto:{EMAIL_TOKEN}"),
        ("Kontakt:max@example.ch", f"Kontakt:{EMAIL_TOKEN}"),
        # --- Email: over-redact rather than leak ---
        ("Kontaktmax@example.ch", EMAIL_TOKEN),  # no space before the address
        ("max@example.ch1", f"{EMAIL_TOKEN}1"),
        ("a@b@example.ch", f"a@{EMAIL_TOKEN}"),
        # --- Email: not an address, left unchanged ---
        ("max@localhost", "max@localhost"),  # no TLD
        ("max@example.c", "max@example.c"),  # TLD needs >= 2 letters
        ("@example.ch", "@example.ch"),
        ("max@", "max@"),
        ("no email here.", "no email here."),
        # --- AHV: redacted ---
        ("756.1234.5678.97", AHV_TOKEN),
        ("AHV: 756.1234.5678.97.", f"AHV: {AHV_TOKEN}."),
        ("AHV756.1234.5678.97x", f"AHV{AHV_TOKEN}x"),
        # --- AHV: over-redact rather than leak ---
        ("756.1234.5678.98", AHV_TOKEN),  # wrong check digit
        ("1756.1234.5678.97", f"1{AHV_TOKEN}"),  # digit touching on the left
        ("756.1234.5678.971", f"{AHV_TOKEN}1"),  # digit touching on the right
        ("756.1234.5678.9712.03.1980", f"{AHV_TOKEN}12.03.1980"),
        # --- AHV: not the AHV format, left unchanged ---
        ("756.1234.5678.9", "756.1234.5678.9"),  # too short
        ("757.1234.5678.97", "757.1234.5678.97"),  # wrong prefix
        ("7561234567897", "7561234567897"),  # no dots: other formats out of scope
        # --- Both detectors ---
        ("756.1234.5678.97@example.ch", EMAIL_TOKEN),  # overlap: email wins
        ("756.1234.5678.97 max@example.ch", f"{AHV_TOKEN} {EMAIL_TOKEN}"),
        (
            "Kontakt: max.muster@example.ch, AHV 756.1234.5678.97 ok",
            f"Kontakt: {EMAIL_TOKEN}, AHV {AHV_TOKEN} ok",
        ),
        # --- Empty input ---
        ("", ""),
    ],
)
def test_redact(text: str, expected: str) -> None:
    assert redact(text) == expected


def test_long_local_part_is_redacted_up_to_the_limit() -> None:
    # Only the last 64 local-part characters can belong to the address.
    assert redact("a" * 100 + "@example.ch") == "a" * 36 + EMAIL_TOKEN


def test_custom_detector_extends_redaction() -> None:
    phone_detector = Detector(
        "PHONE",
        r"(?<![\d+])(\+41|0041|0)[ ]?[1-9]\d(?:[ ]?\d{3})(?:[ ]?\d{2}){2}(?!\d)",
        lookbehind=1,
    )
    detectors = (*DEFAULT_DETECTORS, phone_detector)
    text = "Call +41 44 421 62 89 or 044 421 62 89, mail max@example.ch"
    assert redact(text, detectors) == (
        f"Call {phone_detector.token} or {phone_detector.token}, mail {EMAIL_TOKEN}"
    )


def test_detector_order_sets_priority_at_same_position() -> None:
    digits_detector = Detector("DIGITS", r"\d{3}")
    zip_detector = Detector("ZIP", r"\d{4}")
    assert redact("8000", (digits_detector, zip_detector)) == "[REDACTED_DIGITS]0"
    assert redact("8000", (zip_detector, digits_detector)) == "[REDACTED_ZIP]"


@pytest.mark.parametrize(
    ("detectors", "message"),
    [
        ((), "at least one detector"),
        ((Detector("X", r"\d{0,3}"),), "empty string"),
        ((Detector("X", r"(?<!\d)\d{3}"),), "lookbehind"),
    ],
)
def test_invalid_detector_sets_are_rejected(
    detectors: tuple[Detector, ...], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        compile_detectors(detectors)
