import json
import struct
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from jinja2 import Environment
from jinja2 import FileSystemBytecodeCache
from jinja2 import IntegrityBytecodeCache
from jinja2 import IntegrityCacheStatus
from jinja2.bccache import Bucket
from jinja2.bccache import MemcachedBytecodeCache
from jinja2.exceptions import TemplateNotFound
from jinja2.loaders import DictLoader


@pytest.fixture
def env(package_loader, tmp_path):
    bytecode_cache = FileSystemBytecodeCache(str(tmp_path))
    return Environment(loader=package_loader, bytecode_cache=bytecode_cache)


class TestByteCodeCache:
    def test_simple(self, env):
        tmpl = env.get_template("test.html")
        assert tmpl.render().strip() == "BAR"
        pytest.raises(TemplateNotFound, env.get_template, "missing.html")


class MockMemcached:
    class Error(Exception):
        pass

    key = None
    value = None
    timeout = None

    def get(self, key):
        return self.value

    def set(self, key, value, timeout=None):
        self.key = key
        self.value = value
        self.timeout = timeout

    def get_side_effect(self, key):
        raise self.Error()

    def set_side_effect(self, *args):
        raise self.Error()


class TestMemcachedBytecodeCache:
    def test_dump_load(self):
        memcached = MockMemcached()
        m = MemcachedBytecodeCache(memcached)

        b = Bucket(None, "key", "")
        b.code = "code"
        m.dump_bytecode(b)
        assert memcached.key == "jinja2/bytecode/key"

        b = Bucket(None, "key", "")
        m.load_bytecode(b)
        assert b.code == "code"

    def test_exception(self):
        memcached = MockMemcached()
        memcached.get = memcached.get_side_effect
        memcached.set = memcached.set_side_effect
        m = MemcachedBytecodeCache(memcached)
        b = Bucket(None, "key", "")
        b.code = "code"

        m.dump_bytecode(b)
        m.load_bytecode(b)

        m.ignore_memcache_errors = False

        with pytest.raises(MockMemcached.Error):
            m.dump_bytecode(b)

        with pytest.raises(MockMemcached.Error):
            m.load_bytecode(b)


INTEGRITY_MAGIC = IntegrityBytecodeCache._magic


def _cache_path(tmp_path, name="page.html"):
    key = FileSystemBytecodeCache(str(tmp_path)).get_cache_key(name)
    return tmp_path / (f"__jinja2_{key}.cache")


def _make_integrity_env(
    tmp_path,
    source,
    *,
    name="page.html",
    key=b"test-secret",
    namespace="tenant-a",
    **kwargs,
):
    cache = IntegrityBytecodeCache(str(tmp_path), key=key, **kwargs)
    env = Environment(
        loader=DictLoader({name: source}),
        bytecode_cache=cache,
        cache_namespace=namespace,
    )
    return env, cache


def _read_envelope(path):
    data = path.read_bytes()
    assert data.startswith(INTEGRITY_MAGIC)
    header_start = len(INTEGRITY_MAGIC) + 4
    (header_size,) = struct.unpack(">I", data[len(INTEGRITY_MAGIC) : header_start])
    header_end = header_start + header_size
    mac_end = header_end + IntegrityBytecodeCache._mac_size
    header = json.loads(data[header_start:header_end])
    return data, header, header_start, header_end, mac_end


def _rewrite_header(data, **updates):
    _, header, header_start, header_end, _ = _read_envelope_from_bytes(data)
    header.update(updates)
    header_raw = json.dumps(
        header, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return (
        data[: len(INTEGRITY_MAGIC)]
        + struct.pack(">I", len(header_raw))
        + header_raw
        + data[header_end:]
    )


def _read_envelope_from_bytes(data):
    assert data.startswith(INTEGRITY_MAGIC)
    header_start = len(INTEGRITY_MAGIC) + 4
    (header_size,) = struct.unpack(">I", data[len(INTEGRITY_MAGIC) : header_start])
    header_end = header_start + header_size
    mac_end = header_end + IntegrityBytecodeCache._mac_size
    header = json.loads(data[header_start:header_end])
    return data, header, header_start, header_end, mac_end


def _tamper_payload(data):
    _, _, _, _, mac_end = _read_envelope_from_bytes(data)
    return data[:mac_end] + bytes([data[mac_end] ^ 1]) + data[mac_end + 1 :]


class TestIntegrityBytecodeCache:
    def test_authenticated_hit_binds_identity(self, tmp_path):
        source = "Hello {{ name }}"
        env, cache = _make_integrity_env(tmp_path, source)
        assert env.get_template("page.html").render(name="A") == "Hello A"

        path = _cache_path(tmp_path)
        _, header, _, _, _ = _read_envelope(path)
        assert header["format_version"] == IntegrityBytecodeCache.format_version
        assert header["cache_domain"] == "tenant-a"
        assert header["template_name"] == "page.html"
        assert header["source_checksum"] == cache.get_source_checksum(source)
        assert "expires_at" in header
        assert header["key_id"] == cache.key_id

        env2, cache2 = _make_integrity_env(tmp_path, source)
        bucket = cache2.get_bucket(env2, "page.html", None, source)
        assert bucket.code is not None
        assert bucket.integrity_status == IntegrityCacheStatus.HIT
        assert env2.get_template("page.html").render(name="B") == "Hello B"

    def test_tampered_payload_recompiles_and_is_not_rewritten(self, tmp_path):
        source = "safe {{ value }}"
        env, _ = _make_integrity_env(tmp_path, source)
        assert env.get_template("page.html").render(value=1) == "safe 1"

        path = _cache_path(tmp_path)
        data, _, _, _, _ = _read_envelope(path)
        tampered = _tamper_payload(data)
        path.write_bytes(tampered)

        env2, cache2 = _make_integrity_env(tmp_path, source)
        bucket = cache2.get_bucket(env2, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.SIGNATURE_MISMATCH
        assert bucket.integrity_error == "signature_mismatch"

        assert env2.get_template("page.html").render(value="ok") == "safe ok"
        assert path.read_bytes() == tampered

    def test_tampered_checksum_is_rejected(self, tmp_path):
        source = "value={{ value }}"
        env, cache = _make_integrity_env(tmp_path, source)
        assert env.get_template("page.html").render(value=1) == "value=1"

        path = _cache_path(tmp_path)
        data, header, _, _, _ = _read_envelope(path)
        tampered = _rewrite_header(data, source_checksum="0" * 40)
        path.write_bytes(tampered)

        env2, cache2 = _make_integrity_env(tmp_path, source)
        bucket = cache2.get_bucket(env2, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.SIGNATURE_MISMATCH
        assert env2.get_template("page.html").render(value=2) == "value=2"

    def test_changed_source_is_reported_and_recompiled(self, tmp_path):
        env, _ = _make_integrity_env(tmp_path, "old")
        assert env.get_template("page.html").render() == "old"

        env2, cache2 = _make_integrity_env(tmp_path, "new")
        bucket = cache2.get_bucket(env2, "page.html", None, "new")
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.SOURCE_CHANGED
        assert env2.get_template("page.html").render() == "new"

        bucket = cache2.get_bucket(env2, "page.html", None, "new")
        assert bucket.integrity_status == IntegrityCacheStatus.HIT

    def test_cross_domain_copy_is_rejected(self, tmp_path):
        source = "tenant data"
        env_a, _ = _make_integrity_env(tmp_path, source, namespace="tenant-a")
        assert env_a.get_template("page.html").render() == "tenant data"

        env_b, cache_b = _make_integrity_env(tmp_path, source, namespace="tenant-b")
        bucket = cache_b.get_bucket(env_b, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.DOMAIN_MISMATCH
        assert env_b.get_template("page.html").render() == "tenant data"

    def test_environment_namespace_alias_sets_cache_domain(self, tmp_path):
        source = "namespace alias"
        cache = IntegrityBytecodeCache(str(tmp_path), key=b"test-secret")
        env = Environment(
            loader=DictLoader({"page.html": source}),
            bytecode_cache=cache,
            namespace="tenant-alias",
        )
        assert env.get_template("page.html").render() == "namespace alias"

        _, header, _, _, _ = _read_envelope(_cache_path(tmp_path))
        assert header["cache_domain"] == "tenant-alias"

    def test_wrong_key_and_missing_key_are_distinct_from_bad_signature(self, tmp_path):
        env, _ = _make_integrity_env(tmp_path, "source", key=b"right")
        assert env.get_template("page.html").render() == "source"

        env_wrong, cache_wrong = _make_integrity_env(
            tmp_path, "source", key=b"wrong"
        )
        bucket = cache_wrong.get_bucket(env_wrong, "page.html", None, "source")
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.MISSING_KEY
        assert env_wrong.get_template("page.html").render() == "source"

        env_none, cache_none = _make_integrity_env(tmp_path, "source", key=None)
        bucket = cache_none.get_bucket(env_none, "page.html", None, "source")
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.MISSING_KEY
        assert env_none.get_template("page.html").render() == "source"

    def test_wrong_secret_with_same_key_id_is_signature_mismatch(self, tmp_path):
        source = "source"
        env, _ = _make_integrity_env(
            tmp_path, source, key=b"right", key_id="shared-key-id"
        )
        assert env.get_template("page.html").render() == "source"

        env_wrong, cache_wrong = _make_integrity_env(
            tmp_path, source, key=b"wrong", key_id="shared-key-id"
        )
        bucket = cache_wrong.get_bucket(env_wrong, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.SIGNATURE_MISMATCH
        assert env_wrong.get_template("page.html").render() == "source"

    def test_legacy_format_is_rejected_without_rewrite(self, tmp_path):
        source = "legacy"
        old_cache = FileSystemBytecodeCache(str(tmp_path))
        old_env = Environment(
            loader=DictLoader({"page.html": source}), bytecode_cache=old_cache
        )
        assert old_env.get_template("page.html").render() == "legacy"
        path = _cache_path(tmp_path)
        before = path.read_bytes()

        env, cache = _make_integrity_env(tmp_path, source)
        bucket = cache.get_bucket(env, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.LEGACY_FORMAT
        assert env.get_template("page.html").render() == "legacy"
        assert path.read_bytes() == before

    def test_expired_entry_recompiles(self, tmp_path):
        now = [100.0]

        def clock():
            return now[0]

        env, cache = _make_integrity_env(tmp_path, "expiry", ttl=10, clock=clock)
        assert env.get_template("page.html").render() == "expiry"

        now[0] = 130.0
        env2, cache2 = _make_integrity_env(
            tmp_path, "expiry", ttl=10, clock=clock
        )
        bucket = cache2.get_bucket(env2, "page.html", None, "expiry")
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.EXPIRED
        assert env2.get_template("page.html").render() == "expiry"

        bucket = cache2.get_bucket(env2, "page.html", None, "expiry")
        assert bucket.integrity_status == IntegrityCacheStatus.HIT

    def test_explicit_rewrite_replaces_invalid_entry(self, tmp_path):
        source = "rewrite"
        env, _ = _make_integrity_env(tmp_path, source)
        assert env.get_template("page.html").render() == "rewrite"

        path = _cache_path(tmp_path)
        data, _, _, _, _ = _read_envelope(path)
        path.write_bytes(_tamper_payload(data))

        env2, cache2 = _make_integrity_env(
            tmp_path, source, rewrite_on_failure=True
        )
        assert env2.get_template("page.html").render() == "rewrite"
        assert path.read_bytes() != _tamper_payload(data)

        env3, cache3 = _make_integrity_env(tmp_path, source)
        bucket = cache3.get_bucket(env3, "page.html", None, source)
        assert bucket.integrity_status == IntegrityCacheStatus.HIT

    def test_key_rotation_reads_old_and_writes_only_new(self, tmp_path):
        source = "rotation"
        env_old, cache_old = _make_integrity_env(tmp_path, source, key=b"old-key")
        assert env_old.get_template("page.html").render() == "rotation"
        old_key_id = cache_old.key_id

        env_new, cache_new = _make_integrity_env(
            tmp_path, source, key=b"new-key", old_keys=[b"old-key"], max_old_keys=1
        )
        bucket = cache_new.get_bucket(env_new, "page.html", None, source)
        assert bucket.code is not None
        assert bucket.integrity_status == IntegrityCacheStatus.HIT
        assert cache_new.key_id != old_key_id
        assert cache_new.old_key_ids == (old_key_id,)

        cache_new.dump_bytecode(bucket)
        _, header, _, _, _ = _read_envelope(_cache_path(tmp_path))
        assert header["key_id"] == cache_new.key_id

        env_old_only, cache_old_only = _make_integrity_env(
            tmp_path, source, key=b"old-key"
        )
        bucket = cache_old_only.get_bucket(env_old_only, "page.html", None, source)
        assert bucket.code is None
        assert bucket.integrity_status == IntegrityCacheStatus.MISSING_KEY

        env_new_only, cache_new_only = _make_integrity_env(
            tmp_path, source, key=b"new-key"
        )
        bucket = cache_new_only.get_bucket(env_new_only, "page.html", None, source)
        assert bucket.integrity_status == IntegrityCacheStatus.HIT

    def test_old_key_retention_is_limited(self, tmp_path):
        with pytest.raises(ValueError, match="too many old keys"):
            IntegrityBytecodeCache(
                str(tmp_path),
                key=b"new-key",
                old_keys=[b"old-one", b"old-two"],
                max_old_keys=1,
            )

    def test_concurrent_writers_produce_complete_envelopes(self, tmp_path):
        source = "concurrent {{ value }}"
        barrier = threading.Barrier(2)

        def write_once():
            env, cache = _make_integrity_env(tmp_path, source)
            bucket = cache.get_bucket(env, "page.html", None, source)
            bucket.code = env.compile(source, "page.html", None)
            barrier.wait()
            cache.dump_bytecode(bucket)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(write_once) for _ in range(2)]
            for future in futures:
                future.result()

        path = _cache_path(tmp_path)
        data, header, _, _, mac_end = _read_envelope(path)
        assert len(data) > mac_end
        assert header["format_version"] == IntegrityBytecodeCache.format_version
        assert not list(tmp_path.glob("*.tmp"))

        env, cache = _make_integrity_env(tmp_path, source)
        bucket = cache.get_bucket(env, "page.html", None, source)
        assert bucket.code is not None
        assert bucket.integrity_status == IntegrityCacheStatus.HIT
        assert env.get_template("page.html").render(value=7) == "concurrent 7"
