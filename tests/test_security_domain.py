"""
Tests for binding an HPACK encoder's compression state to a security domain.
"""
import asyncio

import pytest

from hpack import Decoder, Encoder, SecurityDomainMismatchError


class EncoderSessionPool:
    """
    A tiny session pool that hands an encoder from one security domain to
    another. The handoff is where the pool explicitly resets the compression
    context for the new domain.
    """

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.encoder = Encoder(security_domain=domain)

    def handoff(self, domain: str) -> None:
        self.encoder.reset(security_domain=domain)
        self.domain = domain

    def encode(self, headers: list[tuple[str, str]]) -> bytes:
        return self.encoder.encode(headers, huffman=False)


def test_same_domain_reuses_compression_state() -> None:
    encoder = Encoder(security_domain="A")
    headers = [(":method", "GET"), ("x-domain-a", "one")]

    first = encoder.encode(headers, huffman=False)
    second = encoder.encode(headers, huffman=False)

    assert first != second
    assert second == b"\x82\xbe"
    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-a", b"one")]


def test_existing_state_requires_explicit_reset_before_domain_switch() -> None:
    encoder = Encoder(security_domain="A")
    encoder.encode([(":method", "GET"), ("x-domain-a", "one")], huffman=False)

    with pytest.raises(SecurityDomainMismatchError) as exc_info:
        encoder.encode(
            [(":method", "GET"), ("x-domain-b", "two")],
            huffman=False,
            security_domain="B",
        )

    assert exc_info.value.current_domain == "A"
    assert exc_info.value.requested_domain == "B"
    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-a", b"one")]

    encoder.reset(security_domain="B")
    block = encoder.encode([(":method", "GET"), ("x-domain-b", "two")], huffman=False)

    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-b", b"two")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-b", "two")]


def test_session_pool_handoff_only_leaves_the_new_domain_context() -> None:
    pool = EncoderSessionPool("A")
    pool.encode([(":method", "GET"), ("x-domain-a", "one")])

    pool.handoff("B")
    block = pool.encode([(":method", "GET"), ("x-domain-b", "two")])

    # Only the context that B ultimately receives matters at the handoff.
    assert list(pool.encoder.header_table.dynamic_entries) == [(b"x-domain-b", b"two")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-b", "two")]


def test_cancelled_encode_restores_state_and_can_be_retried() -> None:
    encoder = Encoder(security_domain="A")

    def cancelled_headers():
        yield (":method", "GET")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        encoder.encode(cancelled_headers(), huffman=False)

    assert list(encoder.header_table.dynamic_entries) == []
    assert encoder.security_domain == "A"

    block = encoder.encode([(":method", "GET"), ("x-domain-a", "one")], huffman=False)

    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-a", b"one")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-a", "one")]


def test_cancelled_after_encoding_can_discard_before_retry() -> None:
    encoder = Encoder(security_domain="A")
    headers = [(":method", "GET"), ("x-domain-a", "one")]
    encoder.encode(headers, huffman=False)

    # The caller cancelled before the block was written to the connection.
    encoder.discard()

    assert list(encoder.header_table.dynamic_entries) == []
    assert encoder.security_domain == "A"
    block = encoder.encode(headers, huffman=False)
    assert Decoder().decode(block) == headers


def test_legacy_unmarked_calls_keep_their_existing_behaviour() -> None:
    headers = [(":method", "GET"), ("x-legacy", "value")]
    legacy_encoder = Encoder()
    baseline_encoder = Encoder()

    assert legacy_encoder.encode(headers, huffman=False) == baseline_encoder.encode(headers, huffman=False)
    assert legacy_encoder.encode(headers, huffman=False) == baseline_encoder.encode(headers, huffman=False)
    assert legacy_encoder.security_domain is None
    assert list(legacy_encoder.header_table.dynamic_entries) == [(b"x-legacy", b"value")]


def test_legacy_state_is_not_assumed_safe_for_a_marked_call() -> None:
    encoder = Encoder()
    encoder.encode([(":method", "GET"), ("x-legacy", "value")], huffman=False)

    with pytest.raises(SecurityDomainMismatchError):
        encoder.encode([(":method", "GET"), ("x-domain-b", "two")], huffman=False, domain="B")

    encoder.reset(domain="B")
    block = encoder.encode([(":method", "GET"), ("x-domain-b", "two")], huffman=False)

    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-b", b"two")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-b", "two")]


def test_reset_can_precede_a_new_domain_marker() -> None:
    encoder = Encoder(security_domain="A")
    encoder.encode([(":method", "GET"), ("x-domain-a", "one")], huffman=False)

    encoder.reset()
    block = encoder.encode(
        [(":method", "GET"), ("x-domain-b", "two")],
        huffman=False,
        security_domain="B",
    )

    assert encoder.security_domain == "B"
    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-b", b"two")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-b", "two")]


def test_a_domain_can_be_chosen_before_the_first_encoded_block() -> None:
    encoder = Encoder(security_domain="A")

    block = encoder.encode(
        [(":method", "GET"), ("x-domain-b", "two")],
        huffman=False,
        security_domain="B",
    )

    assert encoder.security_domain == "B"
    assert list(encoder.header_table.dynamic_entries) == [(b"x-domain-b", b"two")]
    assert Decoder().decode(block) == [(":method", "GET"), ("x-domain-b", "two")]


def test_assigning_a_domain_starts_a_fresh_context() -> None:
    encoder = Encoder(security_domain="A")
    encoder.encode([(":method", "GET"), ("x-domain-a", "one")], huffman=False)

    encoder.security_domain = "B"

    assert encoder.domain == "B"
    assert encoder.compression_domain == "B"
    assert list(encoder.header_table.dynamic_entries) == []
