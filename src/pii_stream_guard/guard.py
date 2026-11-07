"""Streaming guard that redacts sensitive data from chunked text.

The guard releases text as early as possible and holds back only text that could
still become (part of) a match. Its total output is always identical to
``redact()`` on the full text, however the input is chunked.
"""

from collections.abc import Sequence

import regex

from pii_stream_guard.detectors import DEFAULT_DETECTORS, Detector, compile_detectors


class StreamingGuard:
    """Redacts a text stream chunk by chunk.

    Use one guard per stream. Call ``push()`` for each chunk and forward the
    result. Call ``finish()`` once at the end.

    Example:
        >>> guard = StreamingGuard()
        >>> guard.push("Kontakt: max.mus")
        'Kontakt: '
        >>> guard.push("ter@example.ch, ok")
        '[REDACTED_EMAIL], '
        >>> guard.finish()
        'ok'
    """

    def __init__(
        self,
        max_output_chars: int | None = None,
        *,
        detectors: Sequence[Detector] = DEFAULT_DETECTORS,
    ) -> None:
        """Create a guard for one stream.

        Args:
            max_output_chars: Not supported yet. Must be ``None``.
            detectors: Detectors in priority order.

        Raises:
            ValueError: If the detectors are invalid.
            NotImplementedError: If ``max_output_chars`` is set.
        """
        if max_output_chars is not None:
            raise NotImplementedError("the output budget is not implemented yet")
        self._pattern = compile_detectors(detectors)
        # Finds where a match may still be in progress at the end of the buffer,
        # e.g. "max.mus" in "Kontakt: max.mus". "\Z." means "end of the text, then
        # one more character", which can never match. So with partial=True, the
        # search only reports places where a detector pattern runs into the end of
        # the buffer. Plain partial search is not enough, because regex prefers a
        # later complete match over an earlier partial one.
        self._open_pattern = regex.compile(rf"(?:{self._pattern.pattern})\Z.")
        self._tokens = {d.name: d.token for d in detectors}
        # How many released characters to keep, so that lookbehinds and anchors
        # like \b and ^ still see the text before a match. Always at least one.
        self._context_size = max(1, *(d.lookbehind for d in detectors))
        # The buffer holds the kept context, then the held-back text, which starts
        # at index _held_from.
        self._buffer = ""
        self._held_from = 0
        self._finished = False

    def push(self, chunk: str) -> str:
        """Add the next chunk.

        Args:
            chunk: Next part of the text. Can be split anywhere.

        Returns:
            The text that is safe to forward now. Text that could still turn into
            sensitive data is held back.

        Raises:
            ValueError: If called after ``finish()``.
        """
        if self._finished:
            raise ValueError("push() called after finish()")
        self._buffer += chunk
        return self._release(final=False)

    def finish(self) -> str:
        """End the stream.

        Returns:
            The remaining held-back text, redacted.

        Raises:
            ValueError: If called twice.
        """
        if self._finished:
            raise ValueError("finish() called twice")
        self._finished = True
        return self._release(final=True)

    def _release(self, final: bool) -> str:
        """Redact and return the held-back text up to where a match may be open."""
        buffer = self._buffer

        # Everything before this index is already in the output.
        released_to = self._held_from

        # Everything from this index on must wait, as a match may still be open there.
        hold_from = len(buffer) if final else self._open_from(released_to)
        if hold_from == released_to:
            return ""  # nothing can be released yet

        output: list[str] = []
        for match in self._pattern.finditer(buffer, released_to):
            if match.start() >= hold_from:
                # This match starts at or after a potential (currently cut-off)
                # match and therefore needs to be held back until the subsequent
                # chunks arrive.
                break

            # A complete match starting before hold_from can be added to the output.
            output += [buffer[released_to : match.start()], self._token(match)]
            released_to = match.end()
            if released_to > hold_from:
                # The open match started inside this one, so it becomes invalid.
                # Look for the next one.
                hold_from = self._open_from(released_to)

        output.append(buffer[released_to:hold_from])

        # Drop released text, except the context that lookbehinds may still need.
        keep_from = max(0, hold_from - self._context_size)
        self._buffer = buffer[keep_from:]
        self._held_from = hold_from - keep_from
        return "".join(output)

    def _open_from(self, pos: int) -> int:
        """Start of the earliest possibly unfinished match at or after ``pos``."""
        match = self._open_pattern.search(self._buffer, pos, partial=True)
        return len(self._buffer) if match is None else match.start()

    def _token(self, match: regex.Match[str]) -> str:
        """Replacement token for a complete match, e.g. "[REDACTED_EMAIL]"."""
        name = match.lastgroup
        assert name is not None  # every alternative is a named group
        return self._tokens[name]
