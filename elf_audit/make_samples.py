"""Build minimal ELF64 shared-object samples for the audit demo.

Each sample carries only what the audit needs:
  .dynamic (DT_NEEDED / DT_SONAME), .dynstr,
  .note.gnu.build-id (string identity material), .comment.
"""
import os
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, 'samples')


def build_elf(path, soname=None, needed=(), build_id=b'', comment=b''):
    dynstr = b'\x00'

    def add_str(s):
        nonlocal dynstr
        off = len(dynstr)
        dynstr += s.encode() + b'\x00'
        return off

    needed_offs = [add_str(n) for n in needed]
    soname_off = add_str(soname) if soname else None

    dyn = b''
    for off in needed_offs:
        dyn += struct.pack('<qQ', 1, off)          # DT_NEEDED
    if soname_off is not None:
        dyn += struct.pack('<qQ', 14, soname_off)  # DT_SONAME
    dyn += struct.pack('<qQ', 0, 0)                # DT_NULL

    note = b''
    if build_id:
        note = struct.pack('<III', 4, len(build_id), 3) + b'GNU\x00' + build_id
        note += b'\x00' * (-len(note) % 4)

    shstr = b'\x00'
    name_off = {}
    for nm in ('.dynstr', '.dynamic', '.note.gnu.build-id', '.comment', '.shstrtab'):
        name_off[nm] = len(shstr)
        shstr += nm.encode() + b'\x00'

    # (name, sh_type, link, addralign, entsize, data)
    sections = [
        ('.dynstr', 3, 0, 1, 0, dynstr),
        ('.dynamic', 6, 1, 8, 16, dyn),
        ('.note.gnu.build-id', 7, 0, 4, 0, note),
        ('.comment', 1, 0, 1, 0, comment),
        ('.shstrtab', 3, 0, 1, 0, shstr),
    ]

    blob = bytearray(b'\x00' * 64)  # ELF header placeholder
    shdrs = [b'\x00' * 64]          # NULL section header
    for nm, shtype, link, align, entsize, data in sections:
        pad = -len(blob) % align
        blob += b'\x00' * pad
        off = len(blob)
        blob += data
        shdrs.append(struct.pack('<IIQQQQIIQQ',
                                 name_off[nm], shtype, 0, 0, off, len(data),
                                 link, 0, align, entsize))
    shoff = len(blob)
    blob += b''.join(shdrs)

    ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
    hdr = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, 62, 1, 0, 0, shoff, 0,
                      64, 0, 0, 64, len(shdrs), len(shdrs) - 1)
    blob[:64] = hdr

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(bytes(blob))


def main():
    # Subject under review: mirror says exactly 3 dynamic deps.
    build_elf(os.path.join(SAMPLES, 'libdemo.so.1'),
              soname='libdemo.so.1',
              needed=['libalpha.so.1', 'libbeta.so.1', 'libgamma.so.1'],
              build_id=bytes.fromhex('01' * 20),
              comment=b'demo-build 2026.11\x00')
    # Component delivered under a different file name (rename case).
    build_elf(os.path.join(SAMPLES, 'libalpha.so.1'),
              soname='libalpha.so.1',
              build_id=bytes.fromhex('0a' * 20))
    build_elf(os.path.join(SAMPLES, 'libbeta-1.2.0.so'),
              soname='libbeta.so.1',
              build_id=bytes.fromhex('0b' * 20))
    # Same name, different build tag than the manifest records (ABI variant).
    build_elf(os.path.join(SAMPLES, 'libgamma.so.1'),
              soname='libgamma.so.1',
              build_id=bytes.fromhex('0c' * 20))
    # Proof pair: identical file name + SONAME, different BuildIDs.
    build_elf(os.path.join(SAMPLES, 'variant_a', 'libgamma.so.1'),
              soname='libgamma.so.1',
              build_id=bytes.fromhex('a1' * 20))
    build_elf(os.path.join(SAMPLES, 'variant_b', 'libgamma.so.1'),
              soname='libgamma.so.1',
              build_id=bytes.fromhex('b2' * 20))
    print('samples written to', SAMPLES)


if __name__ == '__main__':
    main()
