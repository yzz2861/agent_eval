"""
   The MIT License (MIT)

   Copyright (C) 2017 Andris Raugulis (moo@arthepsy.eu)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.product import Product


# Maps algorithm aliases (i.e.: historical renames, vendor-suffixed variants,
# and draft names) to their canonical algorithm id.  Policy rules are matched
# against canonical ids so that different spellings of the same algorithm hit
# the same rule.
ALGORITHM_ALIASES: Dict[str, str] = {
    'sntrup761x25519-sha512@openssh.com': 'sntrup761x25519-sha512',
    'curve25519-sha256@libssh.org': 'curve25519-sha256',
    'diffie-hellman-group14-sha256@ssh.com': 'diffie-hellman-group14-sha256',
    'aes128-gcm@openssh.com': 'aes128-gcm',
    'aes256-gcm@openssh.com': 'aes256-gcm',
    'chacha20-poly1305@openssh.com': 'chacha20-poly1305',
    'ssh-rsa-sha2-256': 'rsa-sha2-256',
    'ssh-rsa-sha256@ssh.com': 'rsa-sha2-256',
    'ssh-rsa-sha2-512': 'rsa-sha2-512',
    'umac-128@openssh.com': 'umac-128',
}


class Algorithm:

    @staticmethod
    def canonical_id(alg_name: str) -> str:
        '''Returns the canonical id for an algorithm name, resolving known aliases (i.e.: "sntrup761x25519-sha512@openssh.com" -> "sntrup761x25519-sha512").  Unknown names are returned unchanged.'''
        return ALGORITHM_ALIASES.get(alg_name, alg_name)

    @staticmethod
    def get_ssh_version(version_desc: str) -> Tuple[str, str, bool]:
        is_client = version_desc.endswith('C')
        if is_client:
            version_desc = version_desc[:-1]
        if version_desc.startswith('d'):
            return Product.DropbearSSH, version_desc[1:], is_client
        elif version_desc.startswith('l1'):
            return Product.LibSSH, version_desc[2:], is_client
        else:
            return Product.OpenSSH, version_desc, is_client

    @classmethod
    def get_since_text(cls, versions: List[Optional[str]]) -> Optional[str]:
        tv = []
        if len(versions) == 0 or versions[0] is None:
            return None
        for v in versions[0].split(','):
            ssh_prod, ssh_ver, is_cli = cls.get_ssh_version(v)
            if not ssh_ver:
                continue
            if ssh_prod in [Product.LibSSH]:
                continue
            if is_cli:
                ssh_ver = '{} (client only)'.format(ssh_ver)
            tv.append('{} {}'.format(ssh_prod, ssh_ver))
        if len(tv) == 0:
            return None
        return 'available since ' + ', '.join(tv).rstrip(', ')
