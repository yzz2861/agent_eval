from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import IO, Any, TypeAlias

from . import CBORTag

TagHandler: TypeAlias = Callable[[MessageDecodeContext, CBORTag, bool], Any]

class EvidenceImportError(Exception): ...
class UnknownPolicyError(EvidenceImportError): ...

@dataclass(frozen=True)
class TagInterpretationPolicy:
    name: str
    tag_handlers: Mapping[int, TagHandler] = field(default_factory=dict)

@dataclass
class MessageDecodeContext:
    input_type: str
    policy: TagInterpretationPolicy
    state: dict[str, Any] = field(default_factory=dict)
    interpreted_tags: list[int] = field(default_factory=list)
    preserved_tags: list[int] = field(default_factory=list)

class EvidenceDecoder:
    def __init__(self, policies: Mapping[str, TagInterpretationPolicy] | None = None) -> None: ...
    def register_policy(self, input_type: str, policy: TagInterpretationPolicy) -> None: ...
    def get_policy(self, input_type: str) -> TagInterpretationPolicy: ...
    def decode_message(
        self, data: bytes, input_type: str, *, immutable: bool = ..., **decoder_options: Any
    ) -> Any: ...
    def decode_stream(
        self,
        fp: IO[bytes],
        input_type: str,
        *,
        immutable: bool = ...,
        **decoder_options: Any,
    ) -> Any: ...
