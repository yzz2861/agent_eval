from functools import partial

import pytest

from itsdangerous.exc import ScopeMismatch
from itsdangerous.url_safe import URLSafeSerializer
from itsdangerous.url_safe import URLSafeTimedSerializer
from test_itsdangerous.test_serializer import TestSerializer
from test_itsdangerous.test_timed import TestTimedSerializer


class TestURLSafeSerializer(TestSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeSerializer, secret_key="secret-key")

    @pytest.fixture(params=({"id": 42}, pytest.param("a" * 1000, id="zlib")))
    def value(self, request):
        return request.param


class TestURLSafeTimedSerializer(TestURLSafeSerializer, TestTimedSerializer):
    @pytest.fixture()
    def serializer_factory(self):
        return partial(URLSafeTimedSerializer, secret_key="secret-key")


class TestURLSafeScope:
    @pytest.fixture(params=(URLSafeSerializer, URLSafeTimedSerializer))
    def serializer(self, request):
        return request.param(secret_key="secret-key")

    def test_round_trip_with_compression(self, serializer):
        value = "a" * 1000
        signed = serializer.dumps(
            value, action="refund.preview", tenant="tenant-1", version=1
        )
        assert serializer.loads(
            signed, action="refund.preview", tenant="tenant-1", version=1
        ) == value

        with pytest.raises(ScopeMismatch):
            serializer.loads(
                signed, action="refund.submit", tenant="tenant-1", version=1
            )
