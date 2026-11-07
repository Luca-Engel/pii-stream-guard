import random

import pytest

from pii_stream_guard import Detector, StreamingGuard, redact

EMAIL_TOKEN = "[REDACTED_EMAIL]"
AHV_TOKEN = "[REDACTED_AHV]"


# --- Spec example ---


def test_spec_example() -> None:
    guard = StreamingGuard()
    assert guard.push("Kontakt: max.mus") == "Kontakt: "
    assert guard.push("ter@example.ch, AHV 756.12") == f"{EMAIL_TOKEN}, AHV "
    assert guard.push("34.5678.97 ok") == f"{AHV_TOKEN} "
    assert guard.finish() == "ok"  # "ok" could still have become an email


# --- Holding back: release only what can no longer change ---


def test_text_that_cannot_become_a_match_is_released_immediately() -> None:
    assert StreamingGuard().push("Hello, world! ") == "Hello, world! "


def test_complete_match_that_could_still_grow_is_held_back() -> None:
    guard = StreamingGuard()
    assert guard.push("max@example.ch") == ""  # could become max@example.ch.com
    assert guard.push(".com, ok") == f"{EMAIL_TOKEN}, "
    assert guard.finish() == "ok"


def test_complete_match_inside_a_possible_longer_match_is_held_back() -> None:
    # The AHV number could still be the end of an email's local part.
    guard = StreamingGuard()
    assert guard.push("756.756.1234.5678.97") == ""
    assert guard.push("max@example.ch") + guard.finish() == EMAIL_TOKEN


def test_open_match_inside_a_replaced_match_is_dropped() -> None:
    # "max@example.ch" is finished once "+" arrives, but "example.ch+" inside it
    # could still start a new email. Like redact(), the guard replaces the first
    # email, so only "+" stays held back and the domain is not released again.
    guard = StreamingGuard()
    assert guard.push("max@example.ch") == ""
    assert guard.push("+") == EMAIL_TOKEN
    assert guard.finish() == "+"


def test_hold_back_is_bounded_by_the_longest_possible_match() -> None:
    # Only the last 64 characters can still become the local part of an email.
    assert StreamingGuard().push("a" * 1000) == "a" * 936


# --- Chunk boundaries ---


@pytest.mark.parametrize(
    "detector",
    [
        Detector("X", r"(?<!x)foo\d", lookbehind=1),
        Detector("X", r"\bfoo\d"),
        Detector("X", r"^foo\d"),
        Detector("X", r"(?m)^foo\d"),
    ],
    ids=["lookbehind", "word-boundary", "text-start", "line-start"],
)
def test_text_before_a_match_is_seen_after_release(detector: Detector) -> None:
    # The text "xfoo1" is sent as "x" and then "foo1". Each pattern rejects "foo1"
    # when it comes right after "x", so the full text has no match. The guard
    # releases "x" right away. If it did not keep "x" as context, its buffer would
    # only hold "foo1" when that arrives, which would match and be redacted.
    # This test checks that "x" is kept as context to prevent this problem.
    guard = StreamingGuard(detectors=(detector,))
    assert guard.push("x") == "x"
    assert guard.push("foo1") + guard.finish() == "foo1"


def test_empty_chunks_are_allowed() -> None:
    guard = StreamingGuard()
    assert guard.push("") == ""
    assert guard.push("max@example.ch") == ""
    assert guard.push("") == ""
    assert guard.finish() == EMAIL_TOKEN


# --- Misuse ---


def test_push_after_finish_raises() -> None:
    guard = StreamingGuard()
    guard.finish()
    with pytest.raises(ValueError, match="after finish"):
        guard.push("text")


def test_finish_twice_raises() -> None:
    guard = StreamingGuard()
    guard.finish()
    with pytest.raises(ValueError, match="twice"):
        guard.finish()


# --- Properties: any text, any chunking ---

# Building blocks that often form, break or nearly form sensitive data.
FRAGMENTS = [
    "max.muster@example.ch",
    "756.1234.5678.97",
    "@example.ch",
    "756.",
    "1234.",
    "@",
    ".",
    " ",
    ",",
    "+",
    "-",
    "a",
    "ch",
    "1",
    "7",
    "0",
    "ü",
    "\n",
]
# 500 texts of up to 30 random fragments. The fixed seed makes every run test
# the same texts, so failures are reproducible.
_random = random.Random(0)
TEXTS = [
    "".join(_random.choices(FRAGMENTS, k=_random.randint(0, 30))) for _ in range(500)
]


@pytest.mark.parametrize("chunk_size", range(1, 11))
def test_output_matches_redact_for_any_chunking(chunk_size: int) -> None:
    for text in TEXTS:
        chunks = [text[i : i + chunk_size] for i in range(0, len(text), chunk_size)]
        expected = redact(text)
        guard = StreamingGuard()
        released = ""
        for chunk in chunks:
            released += guard.push(chunk)
            # Never release anything the final output does not start with: no
            # partial leaks, and nothing that later chunks could change.
            assert expected.startswith(released), text
        assert released + guard.finish() == expected, text


# --- Bounded hold-back: constant memory and linear time ---


@pytest.mark.parametrize(
    ("start", "unit"),
    [("", "a."), ("a@", "b."), ("756.", "1")],
    ids=["email-local-part", "email-domain", "ahv"],
)
def test_held_back_text_does_not_grow_with_the_input(start: str, unit: str) -> None:
    # Bounded patterns can only hold back a bounded amount of text. Each push then
    # only searches that text plus the new chunk, which keeps processing linear.
    # An unbounded pattern (e.g. + instead of {1,64}) would hold back everything.
    def held_back(repeats: int) -> int:
        text = start + unit * repeats
        return len(text) - len(StreamingGuard().push(text))

    assert held_back(1000) == held_back(250)
