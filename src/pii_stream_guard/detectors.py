r"""Detectors for sensitive data and a non-streaming reference redactor.

A detector is a name plus one regular expression. To support a new kind of
sensitive data, define a new :class:`Detector` and add it to the tuple of
detectors in use. No other code needs to change.

Rules for detector patterns:

* Use bounded quantifiers only (``{1,64}``, never ``+`` or ``*``). This bounds
  how much text the streaming guard must hold back and keeps processing linear.
* If a boundary is needed, express it with lookarounds, e.g. ``(?<!\d)...(?!\d)``.
* The pattern must not match the empty string.

Detectors are tried in order, so earlier detectors win when two patterns match
at the same position. Across positions, the leftmost match wins.
"""

from collections.abc import Sequence
from dataclasses import dataclass

import regex


@dataclass(frozen=True, slots=True)
class Detector:
    """A kind of sensitive data, recognised by one regular expression."""

    name: str
    pattern: str

    @property
    def token(self) -> str:
        """Replacement text for every match of this detector."""
        return f"[REDACTED_{self.name}]"


EMAIL_DETECTOR = Detector(
    name="EMAIL",
    # name@domain.tld. The length limits come from the email standard RFC 5321
    # (section 4.5.3.1): at most 64 characters before the "@" and 255 for the domain.
    # https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1
    pattern=r"[\w.%+-]{1,64}@[\w.-]{1,255}\.[A-Za-z]{2,63}",
)

AHV_DETECTOR = Detector(
    name="AHV",
    # 756.XXXX.XXXX.XX, also when digits touch it (redact rather than leak).
    # By design, the last digit of every AHV number is a check digit computed
    # from the other 12 (EAN-13 checksum). It is not verified here, so numbers
    # with a typo are redacted too.
    pattern=r"756\.\d{4}\.\d{4}\.\d{2}",
)

DEFAULT_DETECTORS: tuple[Detector, ...] = (EMAIL_DETECTOR, AHV_DETECTOR)


def compile_detectors(detectors: Sequence[Detector]) -> regex.Pattern[str]:
    """Compile detectors into one alternation of named groups, in priority order."""
    if not detectors:
        raise ValueError("at least one detector is required")
    for detector in detectors:
        # A pattern that matches empty text (e.g. \d{0,3} instead of \d{1,3})
        # would match between every two characters and insert tokens everywhere.
        if regex.compile(detector.pattern).match("") is not None:
            raise ValueError(
                f"detector {detector.name!r} must not match the empty string"
            )
    # One named group per detector, e.g. "(?P<EMAIL>...)|(?P<AHV>...)". The group
    # name tells which detector matched; earlier alternatives win at the same position.
    alternation = "|".join(f"(?P<{d.name}>{d.pattern})" for d in detectors)
    return regex.compile(alternation)


def redact(text: str, detectors: Sequence[Detector] = DEFAULT_DETECTORS) -> str:
    """Replace every match in ``text`` with its detector's token.

    This is the non-streaming reference: the streaming guard must produce
    exactly this output, however its input is chunked.
    """
    tokens = {d.name: d.token for d in detectors}

    def replace(match: regex.Match[str]) -> str:
        name = match.lastgroup
        assert name is not None  # every alternative is a named group
        return tokens[name]

    return compile_detectors(detectors).sub(replace, text)
