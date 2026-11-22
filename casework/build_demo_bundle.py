"""Build a compact demonstration case bundle from repository test samples.

Layout (three provenance channels required by the workflow):

  live_storage/      primary hives as found on the live store
  casefile_excerpts/ standalone excerpt manifests saved by the case file

The bundle deliberately contains:
  * two byte-different hives that hold identical records at the same offsets,
    so equal content without a common-source proof stays unbound;
  * one excerpt with full provenance that resolves to a delivered hive;
  * two content-only excerpts of the identical record, kept as separate
    exhibits because content alone proves nothing about origin.
"""

import hashlib
import io
import json
import os
import shutil

from Registry import Registry, RegistryParse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUNDLE = os.path.join(REPO_ROOT, 'casework', 'demo_bundle')


def value_fingerprint(value):
    digest = hashlib.sha256()
    digest.update(b'vk' + chr(10).encode())
    digest.update(value.name().encode('utf-16le', errors='replace'))
    digest.update(chr(10).encode())
    digest.update(str(value.value_type()).encode('ascii'))
    digest.update(chr(10).encode())
    digest.update(value.raw_data())
    return digest.hexdigest()


def write_excerpt(path, records):
    payload = {'manifest_type': 'registry-excerpt/v1', 'records': records}
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


def main():
    if os.path.exists(BUNDLE):
        shutil.rmtree(BUNDLE)

    unicode_dir = os.path.join(BUNDLE, 'live_storage', 'UNICODE_TESTS')
    reorg_dir = os.path.join(BUNDLE, 'live_storage', 'REORGANIZED')
    tz_dir = os.path.join(BUNDLE, 'live_storage', 'TIMEZONE')
    excerpt_dir = os.path.join(BUNDLE, 'casefile_excerpts')
    for directory in (unicode_dir, reorg_dir, tz_dir, excerpt_dir):
        os.makedirs(directory)

    samples = os.path.join(REPO_ROOT, 'tests', 'reg_samples')
    unicode_src = os.path.join(samples, 'UNICODE_TESTS')
    reorg_src = os.path.join(samples, 'REORGANIZED_VALUES_TESTS')
    tz_src = os.path.join(samples, 'issue22.hive')
    shutil.copy(unicode_src, os.path.join(unicode_dir, 'UNICODE_TESTS'))
    shutil.copy(reorg_src, os.path.join(reorg_dir, 'REORGANIZED_VALUES_TESTS'))
    shutil.copy(tz_src, os.path.join(tz_dir, 'issue22.hive'))

    with open(unicode_src, 'rb') as handle:
        unicode_bytes = handle.read()
    unicode_digest = hashlib.sha256(unicode_bytes).hexdigest()
    unicode_regf = RegistryParse.REGFBlock(unicode_bytes, 0, False)
    registry = Registry.Registry(io.BytesIO(unicode_bytes))
    key = registry.open('ASCII_KEY_NAME0')
    value = key.value('ASCII_VALUE_NAME0')
    vk = value._vkrecord

    provenance = {
        'source_sha256': unicode_digest,
        'source_sequence1': unicode_regf.hive_sequence1(),
        'source_sequence2': unicode_regf.hive_sequence2(),
        'record_absolute_offset_hex': '0x%x' % vk.offset(),
        'record_relative_offset_hex': '0x%x' % (vk.offset() - 0x1000),
        'record_kind': 'value',
    }
    record = {
        'record_kind': 'value',
        'registry_path': key.path(),
        'value_name': value.name(),
        'value_type': value.value_type_str(),
        'timestamp': str(key.timestamp()),
        'content_fingerprint': value_fingerprint(value),
        'data_hex': value.raw_data().hex(),
        'provenance': provenance,
    }
    write_excerpt(os.path.join(excerpt_dir, 'excerpt_with_provenance.json'), [record])
    content_only = dict(record)
    content_only['provenance'] = {}
    write_excerpt(os.path.join(excerpt_dir, 'excerpt_content_only_a.json'), [dict(content_only)])
    write_excerpt(os.path.join(excerpt_dir, 'excerpt_content_only_b.json'), [dict(content_only)])

    print('Bundle written to %s' % BUNDLE)


if __name__ == '__main__':
    main()
