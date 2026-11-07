import random

import pytest

from pii_stream_guard import Detector, StreamingGuard, redact

EMAIL_TOKEN = "[REDACTED_EMAIL]"
AHV_TOKEN = "[REDACTED_AHV]"
MARKER = "[TRUNCATED]"


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


# --- Output budget ---


def test_output_that_fits_exactly_is_not_truncated() -> None:
    guard = StreamingGuard(max_output_chars=12)
    assert guard.push("Hello world!") + guard.finish() == "Hello world!"


def test_output_that_does_not_fit_is_cut_and_marked() -> None:
    # 9 characters of text plus the 11-character marker fill the budget of 20.
    guard = StreamingGuard(max_output_chars=20)
    output = guard.push("Hello world, how are you?") + guard.finish()
    assert output == f"Hello wor{MARKER}"


def test_token_that_does_not_fit_is_left_out() -> None:
    guard = StreamingGuard(max_output_chars=20)
    output = guard.push("Mail: max@example.ch, thanks") + guard.finish()
    assert output == f"Mail: {MARKER}"


def test_text_that_only_looks_like_a_token_is_cut_as_plain_text() -> None:
    # The LLM wrote the token text itself. It is not a redaction, so it can be cut.
    guard = StreamingGuard(max_output_chars=20)
    output = guard.push("Mail: [REDACTED_EMAIL], thanks") + guard.finish()
    assert output == f"Mail: [RE{MARKER}"


def test_long_sensitive_data_can_fit_once_redacted() -> None:
    # The 51-character email is longer than the budget, but its token is not.
    guard = StreamingGuard(max_output_chars=30)
    assert guard.push("a" * 40 + "@example.ch") + guard.finish() == EMAIL_TOKEN


def test_marker_is_sent_as_soon_as_the_output_cannot_fit() -> None:
    guard = StreamingGuard(max_output_chars=12)
    assert guard.push("Hello world!") == "H"  # the rest may still fit exactly
    assert guard.push("x") == MARKER  # now the output is too long
    assert guard.push("ignored") == ""
    assert guard.finish() == ""


@pytest.mark.parametrize("max_output_chars", [10, 0, -1])
def test_budget_shorter_than_marker_is_rejected(max_output_chars: int) -> None:
    with pytest.raises(ValueError, match="at least 11"):
        StreamingGuard(max_output_chars=max_output_chars)


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


def assert_streams_as(
    expected: str, guard: StreamingGuard, text: str, chunk_size: int
) -> None:
    released = ""
    for i in range(0, len(text), chunk_size):
        released += guard.push(text[i : i + chunk_size])
        # Never release anything the final output does not start with: no
        # partial leaks, and nothing that later chunks could change.
        assert expected.startswith(released), text
    assert released + guard.finish() == expected, text


@pytest.mark.parametrize("chunk_size", range(1, 11))
def test_output_matches_redact_for_any_chunking(chunk_size: int) -> None:
    for text in TEXTS:
        assert_streams_as(redact(text), StreamingGuard(), text, chunk_size)


def truncate(redacted: str, max_output_chars: int) -> str:
    """Expected guard output: redacted text cut to fit the budget with the marker."""
    if len(redacted) <= max_output_chars:
        return redacted

    kept = redacted[: max_output_chars - len(MARKER)]
    # The test texts contain no brackets, so an unclosed "[" starts a cut token.
    if kept.count("[") > kept.count("]"):
        kept = kept[: kept.rindex("[")]
    return kept + MARKER


@pytest.mark.parametrize("max_output_chars", [11, 30, 100])
@pytest.mark.parametrize("chunk_size", range(1, 11))
def test_truncated_output_matches_truncated_redact_for_any_chunking(
    max_output_chars: int, chunk_size: int
) -> None:
    for text in TEXTS:
        expected = truncate(redact(text), max_output_chars)
        assert_streams_as(expected, StreamingGuard(max_output_chars), text, chunk_size)


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
