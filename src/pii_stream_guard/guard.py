"""Streaming guard that redacts sensitive data from chunked text.

The guard releases text as early as possible and holds back only text that could
still become (part of) a match. Its total output is always identical to
``redact()`` on the full text, however the input is chunked.

With an output budget, the guard forwards at most ``max_output_chars`` characters
in total. If the redacted output does not fit, it ends with ``[TRUNCATED]``.
"""

from collections.abc import Sequence

import regex

from pii_stream_guard.detectors import DEFAULT_DETECTORS, Detector, compile_detectors

TRUNCATION_MARKER = "[TRUNCATED]"

# A piece of output: (text, is_token). Plain text can be cut anywhere, a token
# only as a whole.
_Piece = tuple[str, bool]


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
            max_output_chars: Maximum number of characters to forward in total,
                including the ``[TRUNCATED]`` marker. ``None`` means no limit.
            detectors: Detectors in priority order.

        Raises:
            ValueError: If ``max_output_chars`` is shorter than ``[TRUNCATED]``
                or the detectors are invalid.
        """
        if max_output_chars is not None and max_output_chars < len(TRUNCATION_MARKER):
            raise ValueError(
                f"max_output_chars must be at least {len(TRUNCATION_MARKER)}, "
                f"the length of {TRUNCATION_MARKER}"
            )
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

        self._max_output_chars = max_output_chars
        # Number of characters forwarded so far.
        self._forwarded = 0
        # Released output that is not sent yet. It only fits if no more output
        # follows, because it uses the space reserved for the marker.
        self._waiting: list[_Piece] = []
        self._truncated = False

    def push(self, chunk: str) -> str:
        """Add the next chunk.

        Args:
            chunk: Next part of the text. Can be split anywhere.

        Returns:
            The text that is safe to forward now. Text that could still turn into
            sensitive data is held back. After truncation, always ``""``.

        Raises:
            ValueError: If called after ``finish()``.
        """
        if self._finished:
            raise ValueError("push() called after finish()")
        if self._truncated:
            return ""  # input after truncation is ignored

        self._buffer += chunk
        return self._apply_budget(self._release(final=False), final=False)

    def finish(self) -> str:
        """End the stream.

        Returns:
            The remaining held-back text, redacted. After truncation, ``""``.

        Raises:
            ValueError: If called twice.
        """
        if self._finished:
            raise ValueError("finish() called twice")
        self._finished = True
        if self._truncated:
            return ""

        return self._apply_budget(self._release(final=True), final=True)

    def _release(self, final: bool) -> list[_Piece]:
        """Redact and release the held-back text up to where a match may be open.

        Released text is removed from the buffer, except the context that
        lookbehinds still need.

        Args:
            final: Whether the stream has ended. If so, no match can still be
                open, and all held-back text is released.

        Returns:
            The released output as pieces, in order. Empty if nothing can be
            released yet.
        """
        buffer = self._buffer

        # Everything before this index is already in the output.
        released_to = self._held_from

        # Everything from this index on must wait, as a match may still be open there.
        hold_from = len(buffer) if final else self._open_from(released_to)
        if hold_from == released_to:
            return []  # nothing can be released yet

        output: list[_Piece] = []
        for match in self._pattern.finditer(buffer, released_to):
            if match.start() >= hold_from:
                # This match starts at or after a potential (currently cut-off)
                # match and therefore needs to be held back until the subsequent
                # chunks arrive.
                break

            # A complete match starting before hold_from can be added to the output.
            output += [
                (buffer[released_to : match.start()], False),
                (self._token(match), True),
            ]
            released_to = match.end()
            if released_to > hold_from:
                # The open match started inside this one, so it becomes invalid.
                # Look for the next one.
                hold_from = self._open_from(released_to)

        output.append((buffer[released_to:hold_from], False))

        # Drop released text, except the context that lookbehinds may still need.
        keep_from = max(0, hold_from - self._context_size)
        self._buffer = buffer[keep_from:]
        self._held_from = hold_from - keep_from
        return output

    def _apply_budget(self, pieces: list[_Piece], final: bool) -> str:
        """Return what can be sent now within the budget. The rest keeps waiting.

        On overflow, return what fits followed by the marker, and end the stream.

        Args:
            pieces: Newly released output from ``_release()``.
            final: Whether the stream has ended. If so, nothing more will be
                released, so the waiting output may use the marker's space.

        Returns:
            The text to forward now. Without a budget, all of ``pieces``.
        """
        if self._max_output_chars is None:
            return "".join(text for text, _ in pieces)

        self._waiting += pieces
        waiting_len = sum(len(text) for text, _ in self._waiting)
        # Minimum output still to come from held-back input. Held-back text never
        # disappears: it is released as itself or replaced by a token, so it adds
        # at least one character. This lets us detect overflow as soon as it is certain.
        min_still_to_come = 1 if self._held_from < len(self._buffer) else 0
        # Characters that still fit next to the marker if the output is truncated.
        room = self._max_output_chars - len(TRUNCATION_MARKER) - self._forwarded

        if self._forwarded + waiting_len + min_still_to_come > self._max_output_chars:
            # The output can no longer fit: cut it and end the stream.
            self._truncated = True
            sent, _ = self._split_waiting(room)
            return sent + TRUNCATION_MARKER

        if final:
            # Nothing more will come, so the waiting output may use the marker's space.
            return "".join(text for text, _ in self._waiting)

        # Send what fits next to the truncation marker. The rest keeps waiting.
        sent, self._waiting = self._split_waiting(room)
        self._forwarded += len(sent)
        return sent

    def _split_waiting(self, room: int) -> tuple[str, list[_Piece]]:
        """Split the waiting output into at most ``room`` characters and the rest.

        Plain text is cut at the exact character. A token that does not fit is
        left out completely.

        Args:
            room: Maximum number of characters to take from the waiting output.

        Returns:
            The text that fits, and the pieces left over. The waiting output
            itself is not changed.
        """
        sent: list[str] = []
        for i, (text, is_token) in enumerate(self._waiting):
            if len(text) > room:
                if is_token:
                    return "".join(sent), self._waiting[i:]
                rest = [(text[room:], False), *self._waiting[i + 1 :]]
                return "".join(sent) + text[:room], rest
            sent.append(text)
            room -= len(text)
        return "".join(sent), []

    def _open_from(self, pos: int) -> int:
        """Find where a match may still be in progress at the end of the buffer.

        Args:
            pos: Buffer index to start searching from.

        Returns:
            Start of the earliest possibly unfinished match at or after ``pos``,
            or ``len(self._buffer)`` if there is none.
        """
        match = self._open_pattern.search(self._buffer, pos, partial=True)
        return len(self._buffer) if match is None else match.start()

    def _token(self, match: regex.Match[str]) -> str:
        """Look up the replacement token for a complete match.

        Args:
            match: A match of the combined detector pattern.

        Returns:
            The token of the detector that matched, e.g. ``"[REDACTED_EMAIL]"``.
        """
        name = match.lastgroup
        assert name is not None  # every alternative is a named group
        return self._tokens[name]
