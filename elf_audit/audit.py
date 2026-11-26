"""Offline audit: dynamic table + string data vs. packaging manifest.

Material A (dynamic table): DT_NEEDED of the subject, DT_SONAME of each
delivered component -- establishes what a declaration points at.
Material B (string data): .note.gnu.build-id / .comment -- establishes
the concrete build identity of the delivered file.

A component is marked VERIFIED only when both materials correspond.
"""
import json
import os

from elftools.elf.elffile import ELFFile

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, 'samples')


def inspect(path):
    info = {'file': os.path.basename(path), 'needed': [], 'soname': None,
            'build_id': None, 'comment': None}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name('.dynamic')
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    info['needed'].append(tag.needed)
                elif tag.entry.d_tag == 'DT_SONAME':
                    info['soname'] = tag.soname
        note = elf.get_section_by_name('.note.gnu.build-id')
        if note is not None:
            for n in note.iter_notes():
                if n['n_type'] == 'NT_GNU_BUILD_ID':
                    info['build_id'] = n['n_desc']
        comment = elf.get_section_by_name('.comment')
        if comment is not None:
            info['comment'] = comment.data().rstrip(b'\x00').decode('utf-8', 'replace')
    return info


def audit(manifest_path):
    with open(manifest_path) as f:
        manifest = json.load(f)

    subject = inspect(os.path.join(SAMPLES, manifest['subject']))
    print('== Material A: subject dynamic table ==')
    print('subject:', subject['file'], '| SONAME:', subject['soname'])
    print('DT_NEEDED (%d):' % len(subject['needed']), subject['needed'])
    print('manifest components (%d):' % len(manifest['components']),
          [c['name'] for c in manifest['components']])
    print()

    print('== Component cross-check (A = dynamic table, B = string data) ==')
    for comp in manifest['components']:
        path = os.path.join(SAMPLES, comp['file'])
        a_ok = comp['name'] in subject['needed']
        if not os.path.exists(path):
            verdict = ('UNDELIVERED (manifest-only; %s)' %
                       ('referenced by DT_NEEDED' if a_ok
                        else 'no DT_NEEDED reference either'))
            print('%-14s -> %s' % (comp['name'], verdict))
            continue
        got = inspect(path)
        b_ok = got['build_id'] == comp['build_tag']
        renamed = got['soname'] == comp['name'] and got['file'] != comp['name']
        notes = []
        if renamed:
            notes.append('RENAMED: file %s carries SONAME %s'
                         % (got['file'], got['soname']))
        if a_ok and not b_ok:
            notes.append('ABI VARIANT: name matches but build tag differs '
                         '(manifest %s... vs file %s...)'
                         % (comp['build_tag'][:8], (got['build_id'] or '')[:8]))
        if a_ok and b_ok:
            verdict = 'VERIFIED (A: DT_NEEDED<->SONAME, B: build-id match)'
        else:
            verdict = 'NOT VERIFIED (%s)' % (
                'A ok, B mismatch' if a_ok else 'no dynamic-table anchor')
        print('%-14s -> %s' % (comp['name'], verdict))
        for n in notes:
            print('    ' + n)


def proof_same_name_diff_buildtag():
    print()
    print('== Proof: same name, different build tags are independent ==')
    a = inspect(os.path.join(SAMPLES, 'variant_a', 'libgamma.so.1'))
    b = inspect(os.path.join(SAMPLES, 'variant_b', 'libgamma.so.1'))
    print('variant_a/libgamma.so.1 SONAME=%s BuildID=%s' % (a['soname'], a['build_id']))
    print('variant_b/libgamma.so.1 SONAME=%s BuildID=%s' % (b['soname'], b['build_id']))
    same_identity = (a['soname'] == b['soname'])
    diff_build = (a['build_id'] != b['build_id'])
    print('dynamic-table view identical: %s; string-data distinguishes: %s'
          % (same_identity, diff_build))
    assert same_identity and diff_build


def real_world_rename_anchors():
    print()
    print('== Repo samples: filename vs SONAME divergence in the wild ==')
    base = os.path.join(HERE, '..', 'test', 'testfiles_for_readelf')
    for name in ('libelf0_8_13_32bit.so.elf', 'dwarf_gnuops4.so.elf'):
        got = inspect(os.path.join(base, name))
        print('%-28s SONAME=%s NEEDED=%s' % (name, got['soname'], got['needed']))


if __name__ == '__main__':
    audit(os.path.join(HERE, 'manifest.json'))
    proof_same_name_diff_buildtag()
    real_world_rename_anchors()
