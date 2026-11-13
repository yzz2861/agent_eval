import pytest

from ssh_audit.banner import Banner, BannerReader, BannerError, NotAnSshBannerError, InvalidBannerError, BannerLimitError, BannerEncodingError


# pylint: disable=line-too-long,attribute-defined-outside-init
class TestBanner:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.banner = Banner

    def test_simple_banners(self):
        banner = lambda x: self.banner.parse(x)  # noqa
        b = banner('SSH-2.0-OpenSSH_7.3')
        assert b.protocol == (2, 0)
        assert b.software == 'OpenSSH_7.3'
        assert b.comments is None
        assert str(b) == 'SSH-2.0-OpenSSH_7.3'
        b = banner('SSH-1.99-Sun_SSH_1.1.3')
        assert b.protocol == (1, 99)
        assert b.software == 'Sun_SSH_1.1.3'
        assert b.comments is None
        assert str(b) == 'SSH-1.99-Sun_SSH_1.1.3'
        b = banner('SSH-1.5-Cisco-1.25')
        assert b.protocol == (1, 5)
        assert b.software == 'Cisco-1.25'
        assert b.comments is None
        assert str(b) == 'SSH-1.5-Cisco-1.25'

    def test_invalid_banners(self):
        b = lambda x: self.banner.parse(x)  # noqa
        assert b('Something') is None
        assert b('SSH-XXX-OpenSSH_7.3') is None

    def test_banners_with_spaces(self):
        b = lambda x: self.banner.parse(x)  # noqa
        s = 'SSH-2.0-OpenSSH_4.3p2'
        assert str(b('SSH-2.0-OpenSSH_4.3p2    ')) == s
        assert str(b('SSH-2.0-    OpenSSH_4.3p2')) == s
        assert str(b('SSH-2.0-  OpenSSH_4.3p2  ')) == s
        s = 'SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu'
        assert str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on i686-pc-linux-gnu')) == s
        assert str(b('SSH-2.0-OpenSSH_4.3p2 Debian-9etch3 on i686-pc-linux-gnu  ')) == s
        assert str(b('SSH-2.0-  OpenSSH_4.3p2 Debian-9etch3   on   i686-pc-linux-gnu  ')) == s

    def test_banners_without_software(self):
        b = lambda x: self.banner.parse(x)  # noqa
        assert b('SSH-2.0').protocol == (2, 0)
        assert b('SSH-2.0').software is None
        assert b('SSH-2.0').comments is None
        assert str(b('SSH-2.0')) == 'SSH-2.0'
        assert b('SSH-2.0-').protocol == (2, 0)
        assert b('SSH-2.0-').software == ''
        assert b('SSH-2.0-').comments is None
        assert str(b('SSH-2.0-')) == 'SSH-2.0-'

    def test_banners_with_comments(self):
        b = lambda x: self.banner.parse(x)  # noqa
        assert repr(b('SSH-2.0-OpenSSH_7.2p2 Ubuntu-1')) == '<Banner(protocol=2.0, software=OpenSSH_7.2p2, comments=Ubuntu-1)>'
        assert repr(b('SSH-1.99-OpenSSH_3.4p1 Debian 1:3.4p1-1.woody.3')) == '<Banner(protocol=1.99, software=OpenSSH_3.4p1, comments=Debian 1:3.4p1-1.woody.3)>'
        assert repr(b('SSH-1.5-1.3.7 F-SECURE SSH')) == '<Banner(protocol=1.5, software=1.3.7, comments=F-SECURE SSH)>'

    def test_banners_with_multiple_protocols(self):
        b = lambda x: self.banner.parse(x)  # noqa
        assert str(b('SSH-1.99-SSH-1.99-OpenSSH_3.6.1p2')) == 'SSH-1.99-OpenSSH_3.6.1p2'
        assert str(b('SSH-2.0-SSH-2.0-OpenSSH_4.3p2 Debian-9')) == 'SSH-2.0-OpenSSH_4.3p2 Debian-9'
        assert str(b('SSH-1.99-SSH-2.0-dropbear_0.5')) == 'SSH-1.99-dropbear_0.5'
        assert str(b('SSH-2.0-SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)')) == 'SSH-1.99-OpenSSH_4.2p1 SSH Secure Shell (non-commercial)'
        assert str(b('SSH-1.99-SSH-1.99-SSH-1.99-OpenSSH_3.9p1')) == 'SSH-1.99-OpenSSH_3.9p1'

    def test_strict_error_classification(self):
        # Not an SSH banner at all.
        with pytest.raises(NotAnSshBannerError):
            self.banner.parse_strict('Something')
        # SSH-prefixed but version format is wrong.
        with pytest.raises(InvalidBannerError):
            self.banner.parse_strict('SSH-XXX-OpenSSH_7.3')
        with pytest.raises(InvalidBannerError):
            self.banner.parse_strict('SSH-9.X-OpenSSH_7.3')
        # Legacy parse() keeps returning None for every failure.
        assert self.banner.parse('Something') is None
        assert self.banner.parse('SSH-XXX-OpenSSH_7.3') is None

    def test_nul_is_rejected(self):
        with pytest.raises(InvalidBannerError):
            self.banner.parse_strict('SSH-2.0-OpenSSH_7.3\x00')
        assert self.banner.parse('SSH-2.0-OpenSSH_7.3\x00') is None

    def test_control_sequences_are_neutralized(self):
        # CSI sequences must not interfere with software recognition.
        b = self.banner.parse('SSH-2.0-OpenSSH_7.3\x1b[2J\x1b[H')
        assert b is not None
        assert b.software == 'OpenSSH_7.3'
        # Bare CR inside the line is stripped before recognition.
        b = self.banner.parse('SSH-2.0-OpenSSH_7.3\rDebian')
        assert b is not None
        assert b.software == 'OpenSSH_7.3Debian'
        # OSC title-setting sequences are removed as well.
        b = self.banner.parse('\x1b]0;trusted host\x07SSH-2.0-dropbear_2022.82')
        assert b is not None
        assert b.software == 'dropbear_2022.82'
        # The original bytes are retained, but escaped output contains no raw ESC/CR.
        escaped = b.escaped_raw
        assert '\x1b' not in escaped
        assert '\r' not in escaped
        assert '\\e' in escaped
        assert '\\a' in escaped

    def test_escape_helper(self):
        assert Banner.escape('a\rb\x1bc\x00d\x7f') == 'a\\rb\\ec\\0d\\x7f'
        # Tabs are escaped too; regular printable text passes through untouched.
        assert Banner.escape('plain text\t!') == 'plain text\\t!'
        assert Banner.escape('plain text!') == 'plain text!'

    def test_field_length_limits(self):
        long_software = 'SSH-2.0-' + ('A' * (self.banner.MAX_SOFTWARE_LEN + 1))
        with pytest.raises(BannerLimitError):
            self.banner.parse_strict(long_software)
        long_comment = 'SSH-2.0-OpenSSH_7.3 ' + ('B' * (self.banner.MAX_COMMENT_LEN + 1))
        with pytest.raises(BannerLimitError):
            self.banner.parse_strict(long_comment)
        # Values exactly at the boundary are still accepted.
        ok_software = 'SSH-2.0-' + ('A' * self.banner.MAX_SOFTWARE_LEN)
        assert self.banner.parse(ok_software) is not None

    def test_line_length_limit(self):
        line = 'SSH-2.0-' + ('A' * self.banner.MAX_LINE_BYTES)
        with pytest.raises(BannerLimitError):
            self.banner.parse_strict(line)


class TestBannerReader:
    @pytest.fixture(autouse=True)
    def init(self, ssh_audit):
        self.banner = Banner

    def _reader(self, chunks, **kwargs):
        sequence = iter(chunks)
        clock = {'now': 0.0}

        def recv():
            try:
                item = next(sequence)
            except StopIteration:
                return b''
            if isinstance(item, Exception):
                raise item
            return item

        return BannerReader(recv, time_func=lambda: clock['now'], sleep_func=lambda _s: clock.__setitem__('now', clock['now'] + 0.01), **kwargs)

    def test_simple_streaming_banner(self):
        reader = self._reader([b'SSH-2.0-OpenSSH_8.9\r\n'])
        banner = reader.read()
        assert banner.protocol == (2, 0)
        assert banner.software == 'OpenSSH_8.9'
        assert reader.leftover == b''

    def test_chunked_and_no_newline_banner(self):
        # Data arriving in small chunks, without a trailing newline, is fine.
        reader = self._reader([b'SSH-2', b'.0-dro', b'pbear_2022.83'])
        banner = reader.read()
        assert banner.software == 'dropbear_2022.83'

    def test_header_lines_are_collected_escaped(self):
        reader = self._reader([b'preamble line\n', b'\x1b[31mred header\x1b[0m\n', b'SSH-2.0-OpenSSH_7.3\n'])
        banner = reader.read()
        assert banner.software == 'OpenSSH_7.3'
        assert reader.header == ['preamble line', '\\e[31mred header\\e[0m']

    def test_leftover_bytes_are_preserved(self):
        reader = self._reader([b'SSH-2.0-OpenSSH_7.3\r\nEXTRA-PACKET-BYTES'])
        reader.read()
        assert reader.leftover == b'EXTRA-PACKET-BYTES'

    def test_oversized_line_without_newline(self):
        reader = self._reader([b'A' * (self.banner.MAX_LINE_BYTES + 1)])
        with pytest.raises(BannerLimitError):
            reader.read()

    def test_total_byte_budget(self):
        reader = self._reader([b'X' * (self.banner.MAX_TOTAL_BYTES + 1)], max_line_bytes=self.banner.MAX_TOTAL_BYTES + 2)
        with pytest.raises(BannerLimitError):
            reader.read()

    def test_line_count_budget(self):
        chunks = [b'header\n'] * (self.banner.MAX_LINES + 1)
        chunks.append(b'SSH-2.0-OpenSSH_7.3\n')
        reader = self._reader(chunks)
        with pytest.raises(BannerLimitError):
            reader.read()

    def test_timeout_with_silent_peer(self):
        # Every recv() signals retry; the injected clock instantly expires the budget.
        reader = self._reader(iter(lambda: None, 0), timeout=0.05)
        with pytest.raises(BannerLimitError):
            reader.read()

    def test_retry_then_timeout_exception(self):
        import socket
        # None models an EAGAIN/EWOULDBLOCK translated by the socket adapter;
        # the next read raises a timeout which ends the budget.
        reader = self._reader([None, socket.timeout('timed out')])
        with pytest.raises(BannerLimitError):
            reader.read()

    def test_reset_is_not_an_ssh_banner(self):
        import socket
        reader = self._reader([socket.error(54, 'Connection reset by peer')])
        with pytest.raises(NotAnSshBannerError):
            reader.read()

    def test_closed_without_banner(self):
        reader = self._reader([b''])
        with pytest.raises(NotAnSshBannerError):
            reader.read()

    def test_invalid_utf8(self):
        reader = self._reader([b'SSH-2.0-OpenSSH_7.3\xff\xfe\n'])
        with pytest.raises(BannerEncodingError):
            reader.read()

    def test_banner_errors_share_base_class(self):
        for exc in (NotAnSshBannerError, InvalidBannerError, BannerLimitError, BannerEncodingError):
            assert issubclass(exc, BannerError)
