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
import re

# pylint: disable=unused-import
from typing import Dict, List, Set, Sequence, Tuple, Iterable  # noqa: F401
from typing import Callable, Optional, Union, Any  # noqa: F401

from ssh_audit.banner import Banner
from ssh_audit.product import Product


class Software:
    def __init__(self, vendor: Optional[str], product: str, version: str, patch: Optional[str], os_version: Optional[str], raw_suffix: Optional[str] = None, platform: Optional[str] = None, vendor_suffix: Optional[str] = None) -> None:
        self.__vendor = vendor
        self.__product = product
        self.__version = version
        self.__patch = patch
        self.__os = os_version
        self.__raw_suffix = raw_suffix
        self.__platform = platform
        self.__vendor_suffix = vendor_suffix

    @property
    def vendor(self) -> Optional[str]:
        return self.__vendor

    @property
    def product(self) -> str:
        return self.__product

    @property
    def version(self) -> str:
        return self.__version

    @property
    def patch(self) -> Optional[str]:
        return self.__patch

    @property
    def os(self) -> Optional[str]:
        return self.__os

    @property
    def raw_suffix(self) -> Optional[str]:
        '''Returns the unmodified vendor/platform suffix following the version number (i.e.: 'Ubuntu-1ubuntu2.1' in 'OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'), or None if no suffix was present.'''
        return self.__raw_suffix

    @property
    def platform(self) -> Optional[str]:
        '''Returns the platform/vendor distribution embedded in a back-ported version string, or None if it could not be identified.'''
        return self.__platform

    @property
    def vendor_suffix(self) -> Optional[str]:
        '''Returns the full vendor/platform suffix (including distribution build identifiers from banner comments), or None when no such suffix exists.'''
        return self.__vendor_suffix

    @property
    def is_backported(self) -> bool:
        '''Returns True when the banner carries a non-portable vendor/platform build identifier (i.e. more than the upstream portable-release patch such as p1).  This is only a hint: actual security decisions are based on observed capabilities.'''
        portable_patch = self.__patch is not None and re.match(r'^p\d+$', self.__patch) is not None
        if self.__platform is not None:
            return True
        if self.__raw_suffix is None:
            return False
        # An upstream portable patch (p1, p2, ...) alone is an official OpenBSD portable release, not a distribution back-port.
        return not (portable_patch and self.__raw_suffix == self.__patch)

    def compare_version(self, other: Union[None, 'Software', str]) -> int:
        # pylint: disable=too-many-branches,too-many-return-statements
        if other is None:
            return 1
        if isinstance(other, Software):
            other = '{}{}'.format(other.version, other.patch or '')
        else:
            other = str(other)
        mx = re.match(r'^([\d\.]+\d+)(.*)$', other)
        if mx is not None:
            oversion, opatch = mx.group(1), mx.group(2).strip()
        else:
            oversion, opatch = other, ''

        # Attempt to parse the versions into floats.
        float_parse_error = False
        selfversion_float = 0.0
        oversion_float = 0.0
        try:
            selfversion_float = float(self.version)
            oversion_float = float(oversion)
        except ValueError:
            float_parse_error = True

        # If the versions could not be parsed into floats, use the old string compare method. This returns incorrect results when comparing modern OpenSSH versions ("9.6" > "10.4" evaluates to True!), but removing this may trigger other bugs, and we have no other good options here, soooo...
        if float_parse_error:
            if self.version < oversion:
                return -1
            elif self.version > oversion:
                return 1
        else:  # Float parsing worked, so we'll use this instead. That way (9.6 > 10.4) properly evaluates to False.
            if selfversion_float < oversion_float:  # pylint: disable=else-if-used
                return -1
            elif selfversion_float > oversion_float:
                return 1

        spatch = self.patch or ''
        if self.product == Product.DropbearSSH:
            if not re.match(r'^test\d.*$', opatch):
                opatch = 'z{}'.format(opatch)
            if not re.match(r'^test\d.*$', spatch):
                spatch = 'z{}'.format(spatch)
        elif self.product == Product.OpenSSH:
            mx1 = re.match(r'^p(\d).*', opatch)
            mx2 = re.match(r'^p(\d).*', spatch)
            if not (bool(mx1) and bool(mx2)):
                if mx1 is not None:
                    opatch = mx1.group(1)
                if mx2 is not None:
                    spatch = mx2.group(1)
            # OpenBSD version and p1 versions are considered the same.
            if ((spatch == '') and (opatch == '1')) or ((spatch == '1') and (opatch == '')):
                return 0
        if spatch < opatch:
            return -1
        elif spatch > opatch:
            return 1
        return 0

    def between_versions(self, vfrom: str, vtill: str) -> bool:
        if bool(vfrom) and self.compare_version(vfrom) < 0:
            return False
        if bool(vtill) and self.compare_version(vtill) > 0:
            return False
        return True

    def display(self, full: bool = True) -> str:
        r = '{} '.format(self.vendor) if bool(self.vendor) else ''
        r += self.product
        if bool(self.version):
            r += ' {}'.format(self.version)
        if full:
            patch = self.patch or ''
            if self.product == Product.OpenSSH:
                mx = re.match(r'^(p\d)(.*)$', patch)
                if mx is not None:
                    r += mx.group(1)
                    patch = mx.group(2).strip()
            if bool(patch):
                r += ' ({})'.format(patch)
            if bool(self.os):
                r += ' running on {}'.format(self.os)
        return r

    def __str__(self) -> str:
        return self.display()

    def __repr__(self) -> str:
        r = 'vendor={}, '.format(self.vendor) if bool(self.vendor) else ''
        r += 'product={}'.format(self.product)
        if bool(self.version):
            r += ', version={}'.format(self.version)
        if bool(self.patch):
            r += ', patch={}'.format(self.patch)
        if bool(self.os):
            r += ', os={}'.format(self.os)
        return '<{}({})>'.format(self.__class__.__name__, r)

    @staticmethod
    def _fix_patch(patch: str) -> Optional[str]:
        return re.sub(r'^[-_\.]+', '', patch) or None

    @staticmethod
    def _normalize_suffix(suffix: str) -> Optional[str]:
        '''Returns the unmodified vendor/platform suffix following the version, stripping only leading separator characters that are part of the banner grammar.'''
        return re.sub(r'^[-_\.]+', '', suffix).strip() or None

    @classmethod
    def _build_vendor_suffix(cls, raw_suffix: Optional[str], comments: Optional[str]) -> Optional[str]:
        '''Combines the in-band version suffix with banner comments into a single retained vendor/platform identifier.'''
        parts = []
        if raw_suffix and not re.match(r'^p\d+$', raw_suffix):
            parts.append(raw_suffix)
        if comments:
            # OS comments already surfaced through the os property (e.g. FreeBSD/NetBSD markers) are not duplicated in the vendor suffix.
            if cls._extract_os_version(comments) is None:
                parts.append(comments.strip())
        if len(parts) == 0:
            return None
        return ' '.join(part for part in parts if part).strip() or None

    # Vendor / distribution markers embedded in back-ported version strings.  Each marker maps to a normalized platform name.
    _PLATFORM_MARKERS = [
        (re.compile(r'(?i)ubuntu'), 'Ubuntu'),
        (re.compile(r'(?i)debian'), 'Debian'),
        (re.compile(r'(?i)\brhel\b|red[ _-]?hat|el\d'), 'Red Hat Enterprise Linux'),
        (re.compile(r'(?i)centos'), 'CentOS'),
        (re.compile(r'(?i)fedora'), 'Fedora'),
        (re.compile(r'(?i)rocky'), 'Rocky Linux'),
        (re.compile(r'(?i)alma'), 'AlmaLinux'),
        (re.compile(r'(?i)amazon|amzn'), 'Amazon Linux'),
        (re.compile(r'(?i)\bsuse\b|sles|opensuse'), 'SUSE'),
        (re.compile(r'(?i)alpine'), 'Alpine Linux'),
        (re.compile(r'(?i)arch\b'), 'Arch Linux'),
        (re.compile(r'(?i)gentoo'), 'Gentoo'),
        (re.compile(r'(?i)freebsd'), 'FreeBSD'),
        (re.compile(r'(?i)netbsd'), 'NetBSD'),
        (re.compile(r'(?i)openbsd'), 'OpenBSD'),
        (re.compile(r'(?i)hpn'), 'HPN'),
        (re.compile(r'(?i)caspur'), 'CASPUR'),
        (re.compile(r'(?i)fips'), 'FIPS'),
        # Generic vendor markers are evaluated last so an embedded OS comment (e.g. 'OVH-rescue FreeBSD') wins over the vendor name.
        (re.compile(r'(?i)ovh'), 'OVH'),
    ]

    @classmethod
    def _extract_platform(cls, raw_suffix: Optional[str], comments: Optional[str]) -> Optional[str]:
        '''Identifies the distribution / vendor behind a back-ported build from the raw version suffix and banner comments.'''
        combined = '{} {}'.format(raw_suffix or '', comments or '')
        for marker_regex, platform_name in cls._PLATFORM_MARKERS:
            if marker_regex.search(combined):
                return platform_name
        return None

    @staticmethod
    def _fix_date(d: Optional[str]) -> Optional[str]:
        if d is not None and len(d) == 8:
            return '{}-{}-{}'.format(d[:4], d[4:6], d[6:8])
        else:
            return None

    @classmethod
    def _extract_os_version(cls, c: Optional[str]) -> Optional[str]:
        if c is None:
            return None
        mx = re.match(r'^NetBSD(?:_Secure_Shell)?(?:[\s-]+(\d{8})(.*))?$', c)
        if mx is not None:
            d = cls._fix_date(mx.group(1))
            return 'NetBSD' if d is None else 'NetBSD ({})'.format(d)
        mx = re.match(r'^FreeBSD(?:\slocalisations)?[\s-]+(\d{8})(.*)$', c)
        if not bool(mx):
            mx = re.match(r'^[^@]+@FreeBSD\.org[\s-]+(\d{8})(.*)$', c)
        if mx is not None:
            d = cls._fix_date(mx.group(1))
            return 'FreeBSD' if d is None else 'FreeBSD ({})'.format(d)
        w = ['RemotelyAnywhere', 'DesktopAuthority', 'RemoteSupportManager']
        for win_soft in w:
            mx = re.match(r'^in ' + win_soft + r' ([\d\.]+\d)$', c)
            if mx is not None:
                ver = mx.group(1)
                return 'Microsoft Windows ({} {})'.format(win_soft, ver)
        generic = ['NetBSD', 'FreeBSD']
        for g in generic:
            if c.startswith(g) or c.endswith(g):
                return g
        return None

    @classmethod
    def parse(cls, banner: 'Banner') -> Optional['Software']:
        # pylint: disable=too-many-return-statements
        software = str(banner.software)
        mx = re.match(r'^dropbear_([\d\.]+\d+)(.*)', software)
        v: Optional[str] = None
        if mx is not None:
            raw_suffix = mx.group(2)
            patch = cls._fix_patch(raw_suffix)
            v, p = 'Matt Johnston', Product.DropbearSSH
            v = None
            platform = cls._extract_platform(raw_suffix, banner.comments)
            vendor_suffix = cls._build_vendor_suffix(cls._normalize_suffix(raw_suffix), banner.comments)
            return cls(v, p, mx.group(1), patch, None, cls._normalize_suffix(raw_suffix), platform, vendor_suffix)
        mx = re.match(r'^OpenSSH[_\.-]+([\d\.]+\d+)(.*)', software)
        if mx is not None:
            raw_suffix = mx.group(2)
            patch = cls._fix_patch(raw_suffix)
            v, p = 'OpenBSD', Product.OpenSSH
            v = None
            os_version = cls._extract_os_version(banner.comments)
            platform = cls._extract_platform(raw_suffix, banner.comments)
            vendor_suffix = cls._build_vendor_suffix(cls._normalize_suffix(raw_suffix), banner.comments)
            return cls(v, p, mx.group(1), patch, os_version, cls._normalize_suffix(raw_suffix), platform, vendor_suffix)
        mx = re.match(r'^libssh-([\d\.]+\d+)(.*)', software)
        if mx is not None:
            raw_suffix = mx.group(2)
            patch = cls._fix_patch(raw_suffix)
            v, p = None, Product.LibSSH
            os_version = cls._extract_os_version(banner.comments)
            platform = cls._extract_platform(raw_suffix, banner.comments)
            vendor_suffix = cls._build_vendor_suffix(cls._normalize_suffix(raw_suffix), banner.comments)
            return cls(v, p, mx.group(1), patch, os_version, cls._normalize_suffix(raw_suffix), platform, vendor_suffix)
        mx = re.match(r'^libssh_([\d\.]+\d+)(.*)', software)
        if mx is not None:
            raw_suffix = mx.group(2)
            patch = cls._fix_patch(raw_suffix)
            v, p = None, Product.LibSSH
            os_version = cls._extract_os_version(banner.comments)
            platform = cls._extract_platform(raw_suffix, banner.comments)
            vendor_suffix = cls._build_vendor_suffix(cls._normalize_suffix(raw_suffix), banner.comments)
            return cls(v, p, mx.group(1), patch, os_version, cls._normalize_suffix(raw_suffix), platform, vendor_suffix)
        mx = re.match(r'^RomSShell_([\d\.]+\d+)(.*)', software)
        if mx is not None:
            raw_suffix = mx.group(2)
            patch = cls._fix_patch(raw_suffix)
            v, p = 'Allegro Software', 'RomSShell'
            platform = cls._extract_platform(raw_suffix, banner.comments)
            vendor_suffix = cls._build_vendor_suffix(cls._normalize_suffix(raw_suffix), banner.comments)
            return cls(v, p, mx.group(1), patch, None, cls._normalize_suffix(raw_suffix), platform, vendor_suffix)
        mx = re.match(r'^mpSSH_([\d\.]+\d+)', software)
        if mx is not None:
            v, p = 'HP', 'iLO (Integrated Lights-Out) sshd'
            return cls(v, p, mx.group(1), None, None)
        mx = re.match(r'^Cisco-([\d\.]+\d+)', software)
        if mx is not None:
            v, p = 'Cisco', 'IOS/PIX sshd'
            return cls(v, p, mx.group(1), None, None)
        mx = re.match(r'^tinyssh_(.*)', software)
        if mx is not None:
            return cls(None, Product.TinySSH, mx.group(1), None, None)
        mx = re.match(r'^PuTTY_Release_(.*)', software)
        if mx:
            return cls(None, Product.PuTTY, mx.group(1), None, None)
        mx = re.match(r'^lancom(.*)', software)
        if mx:
            v, p = 'LANcom', 'LCOS sshd'
            return cls(v, p, mx.group(1), None, None)
        return None
