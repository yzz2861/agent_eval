"""
Policy-based decoding entry point for signed evidence messages.

Cooperating partners may attach their own meanings to the same CBOR
extension tag.  This module lets the caller pick a *tag interpretation
policy* based on an input type that has already been identified
out-of-band (for example from a signature envelope).  Every message is
decoded with a fresh :class:`MessageDecodeContext`, so any state that a
tag handler stores while interpreting one message, as well as any error
raised during that interpretation, is confined to that message and can
never leak into the next one.

Tags that the selected policy has no handler for are left untouched as
:class:`CBORTag` instances, preserving the original extension payload for
forensics.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from io import BytesIO
from typing import IO, Any, TypeAlias

from . import CBORDecoder, CBORTag

__all__ = [
    "EvidenceImportError",
    "UnknownPolicyError",
    "TagHandler",
    "TagInterpretationPolicy",
    "MessageDecodeContext",
    "EvidenceDecoder",
]


class EvidenceImportError(Exception):
    """Base class for errors raised by the evidence import entry point."""


class UnknownPolicyError(EvidenceImportError):
    """Raised when no tag interpretation policy is registered for an input type."""


TagHandler: TypeAlias = Callable[["MessageDecodeContext", CBORTag, bool], Any]
"""
Interprets a single tagged value within a message.

The handler receives the per-message :class:`MessageDecodeContext`, the
:class:`CBORTag` being interpreted and the decoder ``immutable`` flag.
Whatever it returns replaces the tag in the decoded message.  Any exception
it raises aborts the current message only.
"""


@dataclass(frozen=True)
class TagInterpretationPolicy:
    """
    A named strategy describing how extension tags are interpreted for one
    kind of input.

    :param name: human-readable name of the strategy (for diagnostics)
    :param tag_handlers: mapping of CBOR tag numbers to the handlers that
        give them a business meaning under this strategy
    """

    name: str
    tag_handlers: Mapping[int, TagHandler] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for tag_number, handler in self.tag_handlers.items():
            if not isinstance(tag_number, int):
                raise TypeError(f"tag numbers must be integers, got {type(tag_number)!r}")
            if not callable(handler):
                raise TypeError(f"handler for tag {tag_number} must be callable")


@dataclass
class MessageDecodeContext:
    """
    Per-message state handed to every tag handler during one decode.

    A new instance is created for each decoded message and never reused, so
    state accumulated here cannot bleed into another message.

    :param input_type: the caller-identified input type of the current message
    :param policy: the tag interpretation policy selected for this message
    :param state: free-form scratch space shared by the tag handlers of one
        message; starts empty for every message
    :param interpreted_tags: tag numbers that have been handed to a handler
        while decoding the current message, in encounter order
    :param preserved_tags: unrecognized tags kept verbatim for forensics,
        in encounter order
    """

    input_type: str
    policy: TagInterpretationPolicy
    state: dict[str, Any] = field(default_factory=dict)
    interpreted_tags: list[int] = field(default_factory=list)
    preserved_tags: list[int] = field(default_factory=list)


class EvidenceDecoder:
    """
    Optional decoding entry point for signed evidence messages.

    Input types are bound to :class:`TagInterpretationPolicy` instances up
    front.  Decoding a message requires the caller to state the already
    identified input type, which selects the strategy used to interpret
    extension tags.  Requesting an unregistered input type fails fast instead
    of silently decoding with a stale or default strategy.
    """

    def __init__(self, policies: Mapping[str, TagInterpretationPolicy] | None = None) -> None:
        self._policies: dict[str, TagInterpretationPolicy] = dict(policies or {})

    def register_policy(self, input_type: str, policy: TagInterpretationPolicy) -> None:
        """Bind an input type to a tag interpretation policy."""
        if not isinstance(policy, TagInterpretationPolicy):
            raise TypeError("policy must be a TagInterpretationPolicy instance")

        self._policies[input_type] = policy

    def get_policy(self, input_type: str) -> TagInterpretationPolicy:
        """
        Return the policy registered for ``input_type``.

        :raises UnknownPolicyError: if no policy is registered for the input type
        """
        try:
            return self._policies[input_type]
        except KeyError:
            raise UnknownPolicyError(
                f"no tag interpretation policy registered for input type {input_type!r}"
            ) from None

    def _decode(
        self,
        source: Any,
        input_type: str,
        immutable: bool,
        decoder_options: dict[str, Any],
    ) -> Any:
        policy = self.get_policy(input_type)
        if "tag_hook" in decoder_options:
            raise ValueError("tag_hook is managed by the evidence decoder")

        context = MessageDecodeContext(input_type=input_type, policy=policy)

        def tag_hook(tag: CBORTag, immutable_flag: bool) -> Any:
            handler = policy.tag_handlers.get(tag.tag)
            if handler is None:
                # Preserve the unrecognized extension verbatim for forensics.
                context.preserved_tags.append(tag.tag)
                return tag

            context.interpreted_tags.append(tag.tag)
            return handler(context, tag, immutable_flag)

        decoder = CBORDecoder(source, tag_hook=tag_hook, **decoder_options)
        return decoder.decode(immutable=immutable)

    def decode_message(
        self, data: bytes, input_type: str, *, immutable: bool = False, **decoder_options: Any
    ) -> Any:
        """
        Decode one signed evidence message.

        The caller-supplied ``input_type`` selects the tag interpretation
        policy.  A fresh :class:`MessageDecodeContext` is created for this
        call, isolating handler state and errors from every other message.

        :param data: the CBOR bytes of the message
        :param input_type: the caller-identified input type of the message
        :param immutable: decode immutable container types where possible
        :param decoder_options: extra keyword arguments forwarded to
            :class:`cbor2.CBORDecoder` (``tag_hook`` is not allowed as it is
            managed internally)
        :raises UnknownPolicyError: if no policy is registered for the input type
        """
        return self._decode(BytesIO(data), input_type, immutable, decoder_options)

    def decode_stream(
        self,
        fp: IO[bytes],
        input_type: str,
        *,
        immutable: bool = False,
        **decoder_options: Any,
    ) -> Any:
        """
        Decode one signed evidence message from an open binary stream.

        Behaves like :meth:`decode_message` but reads from ``fp`` instead of
        an in-memory buffer.  Each call still gets its own
        :class:`MessageDecodeContext`, so consecutive messages decoded from
        the same stream never share interpretation state.
        """
        return self._decode(fp, input_type, immutable, decoder_options)
