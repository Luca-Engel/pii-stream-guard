# pii-stream-guard

Redacts sensitive data from a text stream, chunk by chunk, such as LLM output
while it is generated. Swiss AHV numbers become `[REDACTED_AHV]` and email
addresses become `[REDACTED_EMAIL]`. An optional output budget ends the stream
with `[TRUNCATED]`.

```python
from pii_stream_guard import StreamingGuard

guard = StreamingGuard()
guard.push("Kontakt: max.mus")  # 'Kontakt: '
guard.push("ter@example.ch, AHV 756.12")  # '[REDACTED_EMAIL], AHV '
guard.push("34.5678.97 ok")  # '[REDACTED_AHV] '
guard.finish()  # 'ok'
```

Use one guard per stream. Forward the result of every `push()` and call
`finish()` once at the end.

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest        # tests
uv run mypy          # type checking
uv run ruff check    # lint
uv run ruff format   # format
```

The only runtime dependency is [`regex`](https://pypi.org/project/regex/), which
supports partial matching.

## Adding a detector

A detector is a name and one regex. The token comes from the name. For example,
to also redact Swiss phone numbers:

```python
from pii_stream_guard import DEFAULT_DETECTORS, Detector, StreamingGuard

PHONE_DETECTOR = Detector(
    "PHONE",
    r"(?<![\d+])(\+41|0041|0)[ ]?[1-9]\d(?:[ ]?\d{3})(?:[ ]?\d{2}){2}(?!\d)",
    lookbehind=1,  # (?<![\d+]) looks at one character before the match
)

guard = StreamingGuard(detectors=(*DEFAULT_DETECTORS, PHONE_DETECTOR))
guard.push("Call 044 421 62 89 or max@example.ch")  # 'Call [REDACTED_PHONE] or '
guard.finish()  # '[REDACTED_EMAIL]'
```

No other code changes. A pattern must follow three rules:

1. **Bounded quantifiers only**, like `{1,64}` instead of `+` or `*`. This limits
   how much text the guard holds back.
2. **Declare lookbehinds.** `(?<!\d)` needs `lookbehind=1`. Anchors like `\b` and
   `^` need nothing.
3. **No empty matches.**

Rules 2 and 3 are checked when the guard is created.

## Assumptions

**Emails** have the form `local@domain.tld`. The local part allows `[\w.%+-]`, the
domain `[\w.-]`, and the top-level domain 2 to 63 letters. The length limits come
from [RFC 5321](https://datatracker.ietf.org/doc/html/rfc5321#section-4.5.3.1): at
most 64 characters before the `@` and 255 after it. If the local part is longer,
only its last 64 characters are redacted.

**AHV numbers** have the form `756.XXXX.XXXX.XX`. They are redacted even when
digits touch them, as in `1756.1234.5678.970`, because a leak is worse than
redacting too much. The check digit is not verified.

**Overlapping matches.** The leftmost match wins. If two detectors match at the
same position, the one listed first wins. By default, email is listed first, so
`756.1234.5678.97@example.ch` becomes one `[REDACTED_EMAIL]`.

**Chunks** can be split anywhere and can be empty. The output does not depend on
how the text is chunked. It is always the same as redacting the full text at once.

**Output budget.** `StreamingGuard(max_output_chars=n)` forwards at most `n`
characters in total.

- The truncation marker `[TRUNCATED]` counts towards `n`, so `n` must be at least 11.
- Output that fits exactly is not truncated.
- Plain text is cut at the exact character. A token is never cut: if it does not
  fit, it is left out.
- Text that only looks like a token but has not been redacted by the system is treated as plain text.
- After truncation, further input is ignored.
- Lengths are Python characters, not bytes or LLM tokens.

## Design

The guard buffers text that it has not released yet. On every `push()`, it
releases everything that can no longer become part of a match.

**Two searches.** All detectors are combined into one regex. On every `push()`,
the guard searches the buffer twice:

1. **Where to stop.** A partial search finds the leftmost match that runs into the
   end of the buffer and could still grow when more text arrives. With
   `partial=True`, `regex` reports such matches, so no detector needs extra logic
   for this. Everything from there on is held back.
2. **What to replace.** A normal search finds the complete matches before that
   point. They are replaced by tokens, and the text up to that point is released.

Search 1 can find a match in progress inside a complete match. In
`max@example.ch+`, `example.ch+` could still become the start of a new email.
Search 2 replaces the complete email first, which removes that match in progress.
So the guard repeats search 1 from the end of the replaced email.

**Why search 1 uses `\Z.`.** A plain partial search prefers a later complete match
over an earlier partial one. In `AHV a.756.1234.5678.97`, it reports the complete
AHV number, so `a.` would be released. If `@example.ch` follows, `a.` was part of
an email and has leaked. So search 1 uses `(?:detectors)\Z.` instead. "End of
text, then one more character" can never match completely, so the search only
reports matches still in progress, and the leftmost one first.

**Context.** The guard keeps the last released character, or more if a detector
declares a longer lookbehind. Without it, `\b`, `^` and lookbehinds would not see
the text before a match that starts in a later chunk.

**Budget.** The last 11 characters of the budget are reserved for the marker.
Output that falls into them waits until the stream ends or the output can no
longer fit. Waiting output keeps text and tokens apart, so a cut never splits a
token.

## Complexity

Every quantifier is bounded, so every match is too. The longest default match is
an email of 384 characters. The guard never holds back more than that plus the
context.

- **Time:** each `push()` searches only the held-back text and the new chunk. So
  each character is searched at most about 384 times, which is `O(n)` for a
  stream of `n` characters. Doubling the input doubles the run time.
- **Memory:** constant per stream.
- **Latency:** text is released as soon as it cannot be part of a match. Text like
  `Hello, world! ` is released immediately.

`uv run python examples/benchmark.py` runs on a dataset with about 68,000 characters.
It does 10 runs for each chunk size and measures each `push()`. The statistics are over all pushes of the
10 runs. Here are the results when run on my laptop (Intel Core i7-1260P, 32 GB
RAM, Windows 11):

| Chunk size | Runs | Pushes per run | Mean `push()` latency | p50 | p95 | Characters/s |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 10 | 68,000 | 6 µs | 4 µs | 15 µs | 164,000 |
| 20 | 10 | 3,400 | 32 µs | 31 µs | 49 µs | 617,000 |
| 1000 | 10 | 68 | 1.4 ms | 1.3 ms | 2.0 ms | 699,000 |

At about 4 characters per token
([OpenAI](https://help.openai.com/en/articles/4936856-what-are-tokens-and-how-to-count-them)),
a 20-character chunk is about 5 tokens. Even at p95, the guard would only slow
down an LLM that generates more than about 100,000 tokens per second. For
comparison, the APIs of OpenAI, Anthropic and Google generate about 50 to 240
tokens per second ([Artificial Analysis](https://artificialanalysis.ai/models#speed-tabs),
November 2026).

## Testing

`tests/test_detectors.py` lists formats that must and must not be redacted.
`tests/test_guard.py` covers streaming:

- **Specific cases:** the spec example, held-back matches, chunk boundaries for
  each kind of lookbehind and anchor, the budget rules, and wrong usage like
  `push()` after `finish()`.
- **Any chunking:** 500 texts are built from a fixed list of fragments in random
  order. The fragments include complete emails and AHV numbers, parts of them
  like `756.` or `@example.ch`, and separators like spaces and dots. So the texts
  contain real matches, cut-off matches and near misses. Each text is streamed
  with chunk sizes 1 to 10. The
  output must equal redacting the full text at once, also with a budget. Every
  partial output must be a start of the final output, so nothing is released
  that a later chunk could change.
- **Bounded hold-back:** the held-back text does not grow with the input.

The random texts use a fixed seed, so failures are reproducible. The downside is
that each run tests the same texts.

## AI tool usage

I used Claude Code for:

- **Planning:** discussing the spec, design options and trade-offs.
- **Implementation:** drafting code, tests and docs, which I reviewed and often
  changed or simplified.
- **Review:** reviewing each pull request and breaking the code on purpose to
  check the tests.

I made the decisions, for example one regex per detector, counting the marker
towards the budget, never cutting tokens and which libraries to use or not to use.

## Production integration

The guard sits between the LLM and the client, for example in the server that
streams the response:

```python
guard = StreamingGuard(max_output_chars=4000)
async for chunk in llm.stream(prompt):
    if text := guard.push(chunk):
        await client.send(text)
if text := guard.finish():
    await client.send(text)
```

- Create one guard per response.
- Call `finish()` when the LLM stream ends, or the held-back end of the answer is
  lost. If the stream fails, dropping the guard is safe because held-back text is
  never sent.
- When the output ends with `[TRUNCATED]`, stop the LLM stream to save tokens.

## Limits

- **Regexes only find what they describe.** `max at example dot ch`, numbers
  written as words, or AHV numbers without dots are not found. Names and
  addresses would need a separate step, such as an NER model.
- **Over-redaction.** Mistyped AHV numbers (that still match the format) and text like `version@1.2.ch` are
  redacted too.
- **Latency.** Text that could still become an email, like a long word, is held
  back until it is clear. That is at most 384 characters.
- **Characters, not tokens.** The budget counts characters, not bytes or LLM
  tokens.

## Possible extensions

- Cut at a word boundary instead of the exact character when truncating.
- Verify the AHV check digit to redact less.
- Add more detectors, such as IBANs.
- Log which detectors matched, without the matched text, to see how often
  sensitive data appears.
