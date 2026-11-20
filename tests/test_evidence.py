from __future__ import annotations

from binascii import unhexlify
from io import BytesIO
from typing import Any

import pytest

from cbor2 import CBORDecodeError, CBORTag, dumps
from cbor2.evidence import (
    EvidenceDecoder,
    MessageDecodeContext,
    TagInterpretationPolicy,
    UnknownPolicyError,
)

PARTNER_TAG = 4001
OTHER_TAG = 4002
UNKNOWN_TAG = 9999


class TrackingHandler:
    def __init__(self) -> None:
        self.seen: list[MessageDecodeContext] = []

    def __call__(self, context: MessageDecodeContext, tag: CBORTag, immutable: bool) -> str:
        self.seen.append(context)
        context.state.setdefault("hits", 0)
        context.state["hits"] += 1
        return f"partner-a::{tag.value}"


def partner_b_handler(
    context: MessageDecodeContext, tag: CBORTag, immutable: bool
) -> dict[str, Any]:
    return {"source": "partner-b", "raw": tag.value}


@pytest.fixture
def decoder() -> EvidenceDecoder:
    decoder = EvidenceDecoder()
    decoder.register_policy(
        "partner-a",
        TagInterpretationPolicy(
            name="partner A strategy",
            tag_handlers={PARTNER_TAG: TrackingHandler()},
        ),
    )
    decoder.register_policy(
        "partner-b",
        TagInterpretationPolicy(
            name="partner B strategy",
            tag_handlers={PARTNER_TAG: partner_b_handler},
        ),
    )
    return decoder


def test_same_tag_gets_different_meaning_per_policy(decoder: EvidenceDecoder) -> None:
    payload = dumps(CBORTag(PARTNER_TAG, "payload"))

    result_a = decoder.decode_message(payload, "partner-a")
    result_b = decoder.decode_message(payload, "partner-b")

    assert result_a == "partner-a::payload"
    assert result_b == {"source": "partner-b", "raw": "payload"}


def test_policy_is_selected_from_caller_identified_input_type(
    decoder: EvidenceDecoder,
) -> None:
    payload = dumps([CBORTag(PARTNER_TAG, "a"), CBORTag(PARTNER_TAG, "b")])

    result = decoder.decode_message(payload, "partner-a")

    assert result == ["partner-a::a", "partner-a::b"]


def test_unknown_input_type_fails_without_decoding(decoder: EvidenceDecoder) -> None:
    payload = dumps(CBORTag(PARTNER_TAG, "payload"))

    with pytest.raises(UnknownPolicyError, match="partner-unknown"):
        decoder.decode_message(payload, "partner-unknown")

    # The message bytes are untouched and still decodable afterwards.
    assert payload == dumps(CBORTag(PARTNER_TAG, "payload"))


def test_get_policy_unknown(decoder: EvidenceDecoder) -> None:
    with pytest.raises(UnknownPolicyError):
        decoder.get_policy("missing")


def test_unrecognized_tag_is_preserved_verbatim(decoder: EvidenceDecoder) -> None:
    original = CBORTag(UNKNOWN_TAG, {"keep": "me"})
    payload = dumps(original)

    result = decoder.decode_message(payload, "partner-a")

    assert result == original
    assert isinstance(result, CBORTag)
    assert result.tag == UNKNOWN_TAG


def test_known_and_unknown_tags_coexist(decoder: EvidenceDecoder) -> None:
    payload = dumps([CBORTag(PARTNER_TAG, "x"), CBORTag(UNKNOWN_TAG, 7)])

    result = decoder.decode_message(payload, "partner-a")

    assert result[0] == "partner-a::x"
    assert result[1] == CBORTag(UNKNOWN_TAG, 7)


def test_handler_state_does_not_leak_between_messages(decoder: EvidenceDecoder) -> None:
    payload = dumps([CBORTag(PARTNER_TAG, "first"), CBORTag(PARTNER_TAG, "second")])

    first = decoder.decode_message(payload, "partner-a")
    second = decoder.decode_message(payload, "partner-a")

    assert first == second == ["partner-a::first", "partner-a::second"]
    handler = decoder.get_policy("partner-a").tag_handlers[PARTNER_TAG]
    assert isinstance(handler, TrackingHandler)
    contexts = list({id(ctx): ctx for ctx in handler.seen}.values())
    assert len(contexts) == 2
    assert contexts[0] is not contexts[1]
    assert all(ctx.state == {"hits": 2} for ctx in contexts)
    assert all(ctx.interpreted_tags == [PARTNER_TAG, PARTNER_TAG] for ctx in contexts)
    assert all(ctx.preserved_tags == [] for ctx in contexts)


def test_handler_error_is_confined_to_current_message(decoder: EvidenceDecoder) -> None:
    def failing_handler(context: MessageDecodeContext, tag: CBORTag, immutable: bool) -> None:
        raise RuntimeError("boom")

    decoder.register_policy(
        "failing",
        TagInterpretationPolicy(name="failing", tag_handlers={PARTNER_TAG: failing_handler}),
    )

    with pytest.raises(CBORDecodeError) as exc_info:
        decoder.decode_message(dumps(CBORTag(PARTNER_TAG, 1)), "failing")

    assert isinstance(exc_info.value.__cause__, RuntimeError)

    # The next message under a healthy policy decodes normally.
    result = decoder.decode_message(dumps(CBORTag(PARTNER_TAG, "ok")), "partner-a")
    assert result == "partner-a::ok"


def test_decode_stream_keeps_messages_isolated(decoder: EvidenceDecoder) -> None:
    stream = BytesIO(dumps(CBORTag(PARTNER_TAG, "one")) + dumps(CBORTag(UNKNOWN_TAG, 2)))

    first = decoder.decode_stream(stream, "partner-a")
    second = decoder.decode_stream(stream, "partner-a")

    assert first == "partner-a::one"
    assert second == CBORTag(UNKNOWN_TAG, 2)


def test_immutable_flag_is_forwarded_to_handlers(decoder: EvidenceDecoder) -> None:
    observed: list[bool] = []

    def observe(context: MessageDecodeContext, tag: CBORTag, immutable: bool) -> bool:
        observed.append(immutable)
        return immutable

    decoder.register_policy(
        "observe",
        TagInterpretationPolicy(name="observe", tag_handlers={OTHER_TAG: observe}),
    )
    payload = dumps(CBORTag(OTHER_TAG, 0))

    assert decoder.decode_message(payload, "observe", immutable=True) is True
    assert decoder.decode_message(payload, "observe") is False
    assert observed == [True, False]


def test_passthrough_decoder_options_are_forwarded(decoder: EvidenceDecoder) -> None:
    payload = unhexlify("d90fa161ff")  # tag 4001 containing 0xff (invalid UTF-8)

    with pytest.raises(CBORDecodeError):
        decoder.decode_message(payload, "partner-a")

    result = decoder.decode_message(payload, "partner-a", str_errors="replace")
    assert result == "partner-a::�"


def test_tag_hook_option_is_rejected(decoder: EvidenceDecoder) -> None:
    def forbidden_hook(tag: CBORTag, immutable: bool) -> CBORTag:
        return tag

    with pytest.raises(ValueError, match="tag_hook"):
        decoder.decode_message(
            dumps(CBORTag(PARTNER_TAG, 1)), "partner-a", tag_hook=forbidden_hook
        )


def test_policy_and_handler_validation() -> None:
    def typed_handler(context: MessageDecodeContext, tag: CBORTag, immutable: bool) -> object:
        return tag

    with pytest.raises(TypeError, match="integers"):
        TagInterpretationPolicy(
            name="bad",
            tag_handlers={"4001": typed_handler},  # type: ignore[dict-item]
        )

    with pytest.raises(TypeError, match="callable"):
        TagInterpretationPolicy(name="bad", tag_handlers={4001: "not callable"})

    decoder = EvidenceDecoder()
    with pytest.raises(TypeError, match="TagInterpretationPolicy"):
        decoder.register_policy("bad", {})  # type: ignore[arg-type]


def test_policies_can_be_supplied_via_constructor() -> None:
    def value_handler(context: MessageDecodeContext, tag: CBORTag, immutable: bool) -> Any:
        return tag.value

    policy = TagInterpretationPolicy(name="constructor", tag_handlers={PARTNER_TAG: value_handler})
    decoder = EvidenceDecoder({"ctor": policy})

    assert decoder.get_policy("ctor") is policy
    assert decoder.decode_message(dumps(CBORTag(PARTNER_TAG, 5)), "ctor") == 5
