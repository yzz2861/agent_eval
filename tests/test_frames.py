from hyperframe.frame import (
    Frame, Flags, DataFrame, PriorityFrame, RstStreamFrame, SettingsFrame,
    PushPromiseFrame, PingFrame, GoAwayFrame, WindowUpdateFrame, HeadersFrame,
    ContinuationFrame, AltSvcFrame, ExtensionFrame
)
from hyperframe.exceptions import (
    UnknownFrameError, InvalidPaddingError, InvalidFrameError, InvalidDataError,
    FrameSizeError,
)
from hyperframe.frame import FRAME_MAX_LEN, EXTENSION_FRAME_MAX_LEN
import pytest


def decode_frame(frame_data):
    f, length = Frame.parse_frame_header(frame_data[:9])
    f.parse_body(memoryview(frame_data[9:9 + length]))
    assert 9 + length == len(frame_data)
    return f


class TestGeneralFrameBehaviour:
    def test_base_frame_ignores_flags(self):
        f = Frame(0)
        flags = f.parse_flags(0xFF)
        assert not flags
        assert isinstance(flags, Flags)

    def test_base_frame_cant_serialize(self):
        f = Frame(0)
        with pytest.raises(NotImplementedError):
            f.serialize()

    def test_base_frame_cant_parse_body(self):
        data = b''
        f = Frame(0)
        with pytest.raises(NotImplementedError):
            f.parse_body(data)

    def test_parse_frame_header_unknown_type_strict(self):
        with pytest.raises(UnknownFrameError) as excinfo:
            Frame.parse_frame_header(
                b'\x00\x00\x59\xFF\x00\x00\x00\x00\x01',
                strict=True
            )
        exception = excinfo.value
        assert exception.frame_type == 0xFF
        assert exception.length == 0x59
        assert str(exception) == (
            "UnknownFrameError: Unknown frame type 0xFF received, "
            "length 89 bytes"
        )

    def test_parse_frame_header_ignore_first_bit_of_stream_id(self):
        s = b'\x00\x00\x00\x06\x01\x80\x00\x00\x00'
        f, _ = Frame.parse_frame_header(s)

        assert f.stream_id == 0

    def test_parse_frame_header_unknown_type(self):
        frame, length = Frame.parse_frame_header(
            b'\x00\x00\x59\xFF\x00\x00\x00\x00\x01'
        )
        assert frame.type == 0xFF
        assert length == 0x59
        assert isinstance(frame, ExtensionFrame)
        assert frame.stream_id == 1

    def test_flags_are_persisted(self):
        frame, length = Frame.parse_frame_header(
            b'\x00\x00\x59\xFF\x09\x00\x00\x00\x01'
        )
        assert frame.type == 0xFF
        assert length == 0x59
        assert frame.flag_byte == 0x09

    def test_parse_body_unknown_type_skips_payload(self):
        frame = decode_frame(
            b'\x00\x00\x0C\xFF\x00\x00\x00\x00\x01hello world!'
        )
        assert frame.body == b''
        assert frame.body_len == 12
        assert frame.declared_length == 12
        assert frame.payload_skipped is True
        assert frame.stream_id == 1

    def test_skipped_unknown_frame_cannot_round_trip(self):
        frame_data = b'\x00\x00\x0C\xFF\x00\x00\x00\x00\x01hello world!'
        f = decode_frame(frame_data)
        with pytest.raises(InvalidDataError):
            f.serialize()

    def test_manually_built_extension_frame_round_trips(self):
        frame_data = b'\x00\x00\x0C\xFF\x00\x00\x00\x00\x01hello world!'
        f = ExtensionFrame(0xFF, 1, 0x0, b'hello world!')
        f.body_len = len(f.body)
        assert f.payload_skipped is False
        assert f.serialize() == frame_data
        decoded = decode_frame(frame_data)
        assert decoded.payload_skipped is True
        assert decoded.body == b''

    def test_unknown_frame_within_budget_is_accepted(self):
        payload = b'a' * FRAME_MAX_LEN
        wire = (
            FRAME_MAX_LEN.to_bytes(3, 'big')
            + b'\x42\x00\x00\x00\x00\x01'
            + payload
        )
        frame = decode_frame(wire)
        assert frame.type == 0x42
        assert frame.body_len == FRAME_MAX_LEN
        assert frame.declared_length == FRAME_MAX_LEN
        assert frame.body == b''
        assert frame.payload_skipped is True

    def test_unknown_frame_over_budget_rejected_at_header(self):
        oversized = EXTENSION_FRAME_MAX_LEN + 1
        header = (
            oversized.to_bytes(3, 'big')
            + b'\x42\x00\x00\x00\x00\x01'
        )
        with pytest.raises(FrameSizeError) as excinfo:
            Frame.parse_frame_header(memoryview(header))
        err = excinfo.value
        assert err.frame_type == 0x42
        assert err.declared_length == oversized
        assert err.allowed_length == EXTENSION_FRAME_MAX_LEN
        assert err.actual_length is None
        assert 'payload' not in str(err).lower()
        assert all(
            isinstance(getattr(err, name), int)
            for name in ('frame_type', 'declared_length', 'allowed_length')
        )

    def test_unknown_frame_over_budget_rejected_at_body(self):
        frame = ExtensionFrame(type=0x42, stream_id=1)
        frame.declared_length = EXTENSION_FRAME_MAX_LEN + 1
        frame.payload_skipped = True
        with pytest.raises(FrameSizeError):
            frame.parse_body(memoryview(b'a' * (EXTENSION_FRAME_MAX_LEN + 1)))

    def test_unknown_frame_body_length_mismatch_rejected(self):
        header = b'\x00\x00\x0C\xFF\x00\x00\x00\x00\x01'
        frame, length = Frame.parse_frame_header(memoryview(header))
        assert length == 12
        with pytest.raises(FrameSizeError) as excinfo:
            frame.parse_body(memoryview(b'short'))
        err = excinfo.value
        assert err.frame_type == 0xFF
        assert err.declared_length == 12
        assert err.actual_length == 5
        assert '12 bytes but received 5 bytes' in str(err)

    def test_unknown_frame_with_unregistered_flags_is_retained(self):
        # All flag bits, including unregistered/high bits, are retained
        # on the extension frame without being interpreted.
        frame, length = Frame.parse_frame_header(
            b'\x00\x00\x05\xFE\xFF\x00\x00\x00\x03'
        )
        assert frame.type == 0xFE
        assert frame.flag_byte == 0xFF
        assert frame.stream_id == 3
        assert len(frame.flags) == 0
        frame.parse_body(memoryview(b'abcde'))
        assert frame.flag_byte == 0xFF
        assert frame.body == b''
        assert frame.body_len == 5

    def test_registered_frame_type_cannot_use_skip_path(self):
        for registered_type in (0x0, 0x01, 0x04, 0x09, 0x0A):
            with pytest.raises(InvalidDataError):
                Frame.skip_unknown_frame(
                    frame_type=registered_type,
                    flag_byte=0x0,
                    stream_id=1,
                    length=0,
                )

    def test_skip_path_rejects_out_of_range_stream_id(self):
        with pytest.raises(InvalidDataError):
            Frame.skip_unknown_frame(
                frame_type=0x42,
                flag_byte=0x0,
                stream_id=0x80000000,
                length=0,
            )

    def test_mixed_known_and_unknown_frames(self):
        # A registered frame keeps its strict parsing path even when
        # adjacent to unknown frames carrying high flag bits.
        settings = SettingsFrame(0)
        settings.settings[SettingsFrame.HEADER_TABLE_SIZE] = 4096
        wire = settings.serialize()
        wire += (
            b'\x00\x00\x03\xFF\x80\x00\x00\x00\x01' + b'abc'
        )
        wire += PingFrame(0, b'12345678').serialize()

        offset = 0
        known_one, length = Frame.parse_frame_header(memoryview(wire[offset:offset + 9]))
        known_one.parse_body(memoryview(wire[offset + 9:offset + 9 + length]))
        offset += 9 + length
        assert isinstance(known_one, SettingsFrame)
        assert known_one.settings == {0x01: 4096}

        unknown, length = Frame.parse_frame_header(memoryview(wire[offset:offset + 9]))
        unknown.parse_body(memoryview(wire[offset + 9:offset + 9 + length]))
        offset += 9 + length
        assert isinstance(unknown, ExtensionFrame)
        assert unknown.type == 0xFF
        assert unknown.flag_byte == 0x80
        assert unknown.body == b''
        assert unknown.body_len == 3

        known_two, length = Frame.parse_frame_header(memoryview(wire[offset:offset + 9]))
        known_two.parse_body(memoryview(wire[offset + 9:offset + 9 + length]))
        offset += 9 + length
        assert isinstance(known_two, PingFrame)
        assert known_two.opaque_data == b'12345678'
        assert offset == len(wire)

    def test_known_frame_drops_unregistered_flags(self):
        # DATA (type 0x0) only defines END_STREAM(0x01) and PADDED(0x08);
        # unknown high flag bits must not leak into the parsed Flags object.
        frame, _ = Frame.parse_frame_header(
            b'\x00\x00\x00\x00\xFF\x00\x00\x00\x01'
        )
        assert isinstance(frame, DataFrame)
        assert 'END_STREAM' in frame.flags
        assert 'PADDED' in frame.flags
        assert len(frame.flags) == 2

    def test_repr(self, monkeypatch):
        f = Frame(0)
        monkeypatch.setattr(Frame, "serialize_body", lambda _: b"body")
        assert repr(f) == (
            "Frame(stream_id=0, flags=[]): <hex:626f6479>"
        )

        f.stream_id = 42
        f.flags = ["END_STREAM", "PADDED"]
        assert repr(f) == (
            "Frame(stream_id=42, flags=['END_STREAM', 'PADDED']): <hex:626f6479>"
        )

        monkeypatch.setattr(Frame, "serialize_body", lambda _: b"A"*25)
        assert repr(f) == (
            "Frame(stream_id=42, flags=['END_STREAM', 'PADDED']): <hex:{}...>".format("41"*10)
        )

    def test_frame_explain(self, capsys):
        d = b'\x00\x00\x08\x00\x01\x00\x00\x00\x01testdata'
        Frame.explain(memoryview(d))
        captured = capsys.readouterr()
        assert captured.out.strip() == "DataFrame(stream_id=1, flags=['END_STREAM']): <hex:7465737464617461>"

    def test_cannot_parse_invalid_frame_header(self):
        with pytest.raises(InvalidFrameError):
            Frame.parse_frame_header(b'\x00\x00\x08\x00\x01\x00\x00\x00')


class TestDataFrame:
    payload = b'\x00\x00\x08\x00\x01\x00\x00\x00\x01testdata'
    payload_with_padding = (
        b'\x00\x00\x13\x00\x09\x00\x00\x00\x01\x0Atestdata' + b'\0' * 10
    )

    def test_repr(self):
        f = DataFrame(1, b"testdata")
        assert repr(f).endswith("<hex:7465737464617461>")

    def test_data_frame_has_correct_flags(self):
        f = DataFrame(1)
        flags = f.parse_flags(0xFF)
        assert flags == set([
            'END_STREAM', 'PADDED'
        ])

    @pytest.mark.parametrize('data', [
        b'testdata',
        memoryview(b'testdata')
    ])
    def test_data_frame_serializes_properly(self, data):
        f = DataFrame(1)
        f.flags = set(['END_STREAM'])
        f.data = data

        s = f.serialize()
        assert s == self.payload

    def test_data_frame_with_padding_serializes_properly(self):
        f = DataFrame(1)
        f.flags = set(['END_STREAM', 'PADDED'])
        f.data = b'testdata'
        f.pad_length = 10

        s = f.serialize()
        assert s == self.payload_with_padding

    def test_data_frame_parses_properly(self):
        f = decode_frame(self.payload)

        assert isinstance(f, DataFrame)
        assert f.flags == set(['END_STREAM'])
        assert f.pad_length == 0
        assert f.data == b'testdata'
        assert f.body_len == 8

    def test_data_frame_with_padding_parses_properly(self):
        f = decode_frame(self.payload_with_padding)

        assert isinstance(f, DataFrame)
        assert f.flags == set(['END_STREAM', 'PADDED'])
        assert f.pad_length == 10
        assert f.data == b'testdata'
        assert f.body_len == 19

    def test_data_frame_with_invalid_padding_errors(self):
        with pytest.raises(InvalidFrameError):
            decode_frame(self.payload_with_padding[:9])

    def test_data_frame_with_padding_calculates_flow_control_len(self):
        f = DataFrame(1)
        f.flags = set(['PADDED'])
        f.data = b'testdata'
        f.pad_length = 10

        assert f.flow_controlled_length == 19

    def test_data_frame_zero_length_padding_calculates_flow_control_len(self):
        f = DataFrame(1)
        f.flags = set(['PADDED'])
        f.data = b'testdata'
        f.pad_length = 0

        assert f.flow_controlled_length == len(b'testdata') + 1

    def test_data_frame_without_padding_calculates_flow_control_len(self):
        f = DataFrame(1)
        f.data = b'testdata'

        assert f.flow_controlled_length == 8

    def test_data_frame_comes_on_a_stream(self):
        with pytest.raises(InvalidDataError):
            DataFrame(0)

    def test_long_data_frame(self):
        f = DataFrame(1)

        # Use more than 256 bytes of data to force setting higher bits.
        f.data = b'\x01' * 300
        data = f.serialize()

        # The top three bytes should be numerically equal to 300. That means
        # they should read 00 01 2C.
        # The weird double index trick is to ensure this test behaves equally
        # on Python 2 and Python 3.
        assert data[0] == b'\x00'[0]
        assert data[1] == b'\x01'[0]
        assert data[2] == b'\x2C'[0]

    def test_body_length_behaves_correctly(self):
        f = DataFrame(1)

        f.data = b'\x01' * 300

        # Initially the body length is zero. For now this is incidental, but
        # I'm going to test it to ensure that the behaviour is codified. We
        # should change this test if we change that.
        assert f.body_len == 0

        f.serialize()
        assert f.body_len == 300

    def test_data_frame_with_invalid_padding_fails_to_parse(self):
        # This frame has a padding length of 6 bytes, but a total length of
        # only 5.
        data = b'\x00\x00\x05\x00\x0b\x00\x00\x00\x01\x06\x54\x65\x73\x74'

        with pytest.raises(InvalidPaddingError):
            decode_frame(data)

    def test_data_frame_with_no_length_parses(self):
        # Fixes issue with empty data frames raising InvalidPaddingError.
        f = DataFrame(1)
        f.data = b''
        data = f.serialize()

        new_frame = decode_frame(data)
        assert new_frame.data == b''


class TestPriorityFrame:
    payload = b'\x00\x00\x05\x02\x00\x00\x00\x00\x01\x80\x00\x00\x04\x40'

    def test_repr(self):
        f = PriorityFrame(1)
        assert repr(f).endswith("exclusive=False, depends_on=0, stream_weight=0")
        f.exclusive = True
        f.depends_on = 0x04
        f.stream_weight = 64
        assert repr(f).endswith("exclusive=True, depends_on=4, stream_weight=64")

    def test_priority_frame_has_no_flags(self):
        f = PriorityFrame(1)
        flags = f.parse_flags(0xFF)
        assert flags == set()
        assert isinstance(flags, Flags)

    def test_priority_frame_default_serializes_properly(self):
        f = PriorityFrame(1)

        assert f.serialize() == (
            b'\x00\x00\x05\x02\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00'
        )

    def test_priority_frame_with_all_data_serializes_properly(self):
        f = PriorityFrame(1)
        f.depends_on = 0x04
        f.stream_weight = 64
        f.exclusive = True

        assert f.serialize() == self.payload

    def test_priority_frame_with_all_data_parses_properly(self):
        f = decode_frame(self.payload)

        assert isinstance(f, PriorityFrame)
        assert f.flags == set()
        assert f.depends_on == 4
        assert f.stream_weight == 64
        assert f.exclusive is True
        assert f.body_len == 5

    def test_priority_frame_invalid(self):
        with pytest.raises(InvalidFrameError):
            decode_frame(
                b'\x00\x00\x06\x02\x00\x00\x00\x00\x01\x80\x00\x00\x04\x40\xFF'
            )

    def test_priority_frame_comes_on_a_stream(self):
        with pytest.raises(InvalidDataError):
            PriorityFrame(0)

    def test_short_priority_frame_errors(self):
        with pytest.raises(InvalidFrameError):
            decode_frame(self.payload[:-2])


class TestRstStreamFrame:
    def test_repr(self):
        f = RstStreamFrame(1)
        assert repr(f).endswith("error_code=0")
        f.error_code = 420
        assert repr(f).endswith("error_code=420")

    def test_rst_stream_frame_has_no_flags(self):
        f = RstStreamFrame(1)
        flags = f.parse_flags(0xFF)
        assert not flags
        assert isinstance(flags, Flags)

    def test_rst_stream_frame_serializes_properly(self):
        f = RstStreamFrame(1)
        f.error_code = 420

        s = f.serialize()
        assert s == b'\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x01\xa4'

    def test_rst_stream_frame_parses_properly(self):
        s = b'\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x01\xa4'
        f = decode_frame(s)

        assert isinstance(f, RstStreamFrame)
        assert f.flags == set()
        assert f.error_code == 420
        assert f.body_len == 4

    def test_rst_stream_frame_comes_on_a_stream(self):
        with pytest.raises(InvalidDataError):
            RstStreamFrame(0)

    def test_rst_stream_frame_must_have_body_length_four(self):
        f = RstStreamFrame(1)
        with pytest.raises(InvalidFrameError):
            f.parse_body(b'\x01')


class TestSettingsFrame:
    serialized = (
        b'\x00\x00\x2A\x04\x01\x00\x00\x00\x00' +  # Frame header
        b'\x00\x01\x00\x00\x10\x00' +              # HEADER_TABLE_SIZE
        b'\x00\x02\x00\x00\x00\x00' +              # ENABLE_PUSH
        b'\x00\x03\x00\x00\x00\x64' +              # MAX_CONCURRENT_STREAMS
        b'\x00\x04\x00\x00\xFF\xFF' +              # INITIAL_WINDOW_SIZE
        b'\x00\x05\x00\x00\x40\x00' +              # MAX_FRAME_SIZE
        b'\x00\x06\x00\x00\xFF\xFF' +              # MAX_HEADER_LIST_SIZE
        b'\x00\x08\x00\x00\x00\x01'                # ENABLE_CONNECT_PROTOCOL
    )

    settings = {
        SettingsFrame.HEADER_TABLE_SIZE: 4096,
        SettingsFrame.ENABLE_PUSH: 0,
        SettingsFrame.MAX_CONCURRENT_STREAMS: 100,
        SettingsFrame.INITIAL_WINDOW_SIZE: 65535,
        SettingsFrame.MAX_FRAME_SIZE: 16384,
        SettingsFrame.MAX_HEADER_LIST_SIZE: 65535,
        SettingsFrame.ENABLE_CONNECT_PROTOCOL: 1,
    }

    def test_repr(self):
        f = SettingsFrame()
        assert repr(f).endswith("settings={}")
        f.settings[SettingsFrame.MAX_FRAME_SIZE] = 16384
        assert repr(f).endswith("settings={5: 16384}")

    def test_settings_frame_has_only_one_flag(self):
        f = SettingsFrame()
        flags = f.parse_flags(0xFF)
        assert flags == set(['ACK'])

    def test_settings_frame_serializes_properly(self):
        f = SettingsFrame()
        f.parse_flags(0xFF)
        f.settings = self.settings

        s = f.serialize()
        assert s == self.serialized

    def test_settings_frame_with_settings(self):
        f = SettingsFrame(settings=self.settings)
        assert f.settings == self.settings

    def test_settings_frame_without_settings(self):
        f = SettingsFrame()
        assert f.settings == {}

    def test_settings_frame_with_ack(self):
        f = SettingsFrame(flags=('ACK',))
        assert 'ACK' in f.flags

    def test_settings_frame_ack_and_settings(self):
        with pytest.raises(InvalidDataError):
            SettingsFrame(settings=self.settings, flags=('ACK',))

        with pytest.raises(InvalidDataError):
            decode_frame(self.serialized)

    def test_settings_frame_parses_properly(self):
        # unset the ACK flag to allow correct parsing
        data = self.serialized[:4] + b"\x00" + self.serialized[5:]

        f = decode_frame(data)

        assert isinstance(f, SettingsFrame)
        assert f.flags == set()
        assert f.settings == self.settings
        assert f.body_len == 42

    def test_settings_frame_invalid_body_length(self):
        with pytest.raises(InvalidFrameError):
            decode_frame(
                b'\x00\x00\x2A\x04\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF'
            )

    def test_settings_frames_never_have_streams(self):
        with pytest.raises(InvalidDataError):
            SettingsFrame(1)

    def test_short_settings_frame_errors(self):
        with pytest.raises(InvalidDataError):
            decode_frame(self.serialized[:-2])

    def test_settings_frame_with_large_setting_ids(self):
        f = SettingsFrame()
        f.settings[0xFFFE] = 12345
        f.settings[0xFFFF] = 54321

        s = f.serialize()
        new_f = decode_frame(s)

        assert new_f.settings[0xFFFE] == 12345
        assert new_f.settings[0xFFFF] == 54321

    def test_settings_frame_serializes_with_large_setting_ids(self):
        f = SettingsFrame()
        f.settings[0xFFFE] = 12345
        f.settings[0xFFFF] = 54321

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0C\x04\x00\x00\x00\x00\x00' +  # Frame header
            b'\xFF\xFE\x00\x00\x30\x39' +              # Setting ID 0xFFFE
            b'\xFF\xFF\x00\x00\xd4\x31'                # Setting ID 0xFFFF
        )


class TestPushPromiseFrame:
    def test_repr(self):
        f = PushPromiseFrame(1)
        assert repr(f).endswith("promised_stream_id=0, data=None")
        f.promised_stream_id = 4
        f.data = b"testdata"
        assert repr(f).endswith("promised_stream_id=4, data=<hex:7465737464617461>")

    def test_push_promise_frame_flags(self):
        f = PushPromiseFrame(1)
        flags = f.parse_flags(0xFF)

        assert flags == set(['END_HEADERS', 'PADDED'])

    def test_push_promise_frame_serializes_properly(self):
        f = PushPromiseFrame(1)
        f.flags = set(['END_HEADERS'])
        f.promised_stream_id = 4
        f.data = b'hello world'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0F\x05\x04\x00\x00\x00\x01' +
            b'\x00\x00\x00\x04' +
            b'hello world'
        )

    def test_push_promise_frame_parses_properly(self):
        s = (
            b'\x00\x00\x0F\x05\x04\x00\x00\x00\x01' +
            b'\x00\x00\x00\x04' +
            b'hello world'
        )
        f = decode_frame(s)

        assert isinstance(f, PushPromiseFrame)
        assert f.flags == set(['END_HEADERS'])
        assert f.promised_stream_id == 4
        assert f.data == b'hello world'
        assert f.body_len == 15

    def test_push_promise_frame_with_padding(self):
        s = (
            b'\x00\x00\x17\x05\x0C\x00\x00\x00\x01' +
            b'\x07\x00\x00\x00\x04' +
            b'hello world' +
            b'padding'
        )
        f = decode_frame(s)

        assert isinstance(f, PushPromiseFrame)
        assert f.flags == set(['END_HEADERS', 'PADDED'])
        assert f.promised_stream_id == 4
        assert f.data == b'hello world'
        assert f.body_len == 23

    def test_push_promise_frame_with_invalid_padding_fails_to_parse(self):
        # This frame has a padding length of 6 bytes, but a total length of
        # only 5.
        data = b'\x00\x00\x05\x05\x08\x00\x00\x00\x01\x06\x54\x65\x73\x74'

        with pytest.raises(InvalidPaddingError):
            decode_frame(data)

    def test_push_promise_frame_with_no_length_parses(self):
        # Fixes issue with empty data frames raising InvalidPaddingError.
        f = PushPromiseFrame(1, 2)
        f.data = b''
        data = f.serialize()

        new_frame = decode_frame(data)
        assert new_frame.data == b''

    def test_push_promise_frame_invalid(self):
        data = PushPromiseFrame(1, 0).serialize()
        with pytest.raises(InvalidDataError):
            decode_frame(data)

        data = PushPromiseFrame(1, 3).serialize()
        with pytest.raises(InvalidDataError):
            decode_frame(data)

    def test_short_push_promise_errors(self):
        s = (
            b'\x00\x00\x0F\x05\x04\x00\x00\x00\x01' +
            b'\x00\x00\x00'  # One byte short
        )

        with pytest.raises(InvalidFrameError):
            decode_frame(s)


class TestPingFrame:
    def test_repr(self):
        f = PingFrame()
        assert repr(f).endswith("opaque_data=b''")
        f.opaque_data = b'hello'
        assert repr(f).endswith("opaque_data=b'hello'")

    def test_ping_frame_has_only_one_flag(self):
        f = PingFrame()
        flags = f.parse_flags(0xFF)

        assert flags == set(['ACK'])

    def test_ping_frame_serializes_properly(self):
        f = PingFrame()
        f.parse_flags(0xFF)
        f.opaque_data = b'\x01\x02'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x08\x06\x01\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00'
            b'\x00'
        )

    def test_no_more_than_8_octets(self):
        f = PingFrame()
        f.opaque_data = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09'

        with pytest.raises(InvalidFrameError):
            f.serialize()

    def test_ping_frame_parses_properly(self):
        s = (
            b'\x00\x00\x08\x06\x01\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x00'
            b'\x00'
        )
        f = decode_frame(s)

        assert isinstance(f, PingFrame)
        assert f.flags == set(['ACK'])
        assert f.opaque_data == b'\x01\x02\x00\x00\x00\x00\x00\x00'
        assert f.body_len == 8

    def test_ping_frame_never_has_a_stream(self):
        with pytest.raises(InvalidDataError):
            PingFrame(1)

    def test_ping_frame_has_no_more_than_body_length_8(self):
        f = PingFrame()
        with pytest.raises(InvalidFrameError):
            f.parse_body(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09')

    def test_ping_frame_has_no_less_than_body_length_8(self):
        f = PingFrame()
        with pytest.raises(InvalidFrameError):
            f.parse_body(b'\x01\x02\x03\x04\x05\x06\x07')


class TestGoAwayFrame:
    def test_repr(self):
        f = GoAwayFrame()
        assert repr(f).endswith("last_stream_id=0, error_code=0, additional_data=b''")
        f.last_stream_id = 64
        f.error_code = 32
        f.additional_data = b'hello'
        assert repr(f).endswith("last_stream_id=64, error_code=32, additional_data=b'hello'")

    def test_go_away_has_no_flags(self):
        f = GoAwayFrame()
        flags = f.parse_flags(0xFF)

        assert not flags
        assert isinstance(flags, Flags)

    def test_goaway_serializes_properly(self):
        f = GoAwayFrame()
        f.last_stream_id = 64
        f.error_code = 32
        f.additional_data = b'hello'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0D\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x00\x00\x00\x40' +                      # Last Stream ID
            b'\x00\x00\x00\x20' +                      # Error Code
            b'hello'                                   # Additional data
        )

    def test_goaway_frame_parses_properly(self):
        s = (
            b'\x00\x00\x0D\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x00\x00\x00\x40' +                      # Last Stream ID
            b'\x00\x00\x00\x20' +                      # Error Code
            b'hello'                                   # Additional data
        )
        f = decode_frame(s)

        assert isinstance(f, GoAwayFrame)
        assert f.flags == set()
        assert f.additional_data == b'hello'
        assert f.body_len == 13

        s = (
            b'\x00\x00\x08\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x00\x00\x00\x40' +                      # Last Stream ID
            b'\x00\x00\x00\x20' +                      # Error Code
            b''                                        # Additional data
        )
        f = decode_frame(s)

        assert isinstance(f, GoAwayFrame)
        assert f.flags == set()
        assert f.additional_data == b''
        assert f.body_len == 8

    def test_goaway_frame_never_has_a_stream(self):
        with pytest.raises(InvalidDataError):
            GoAwayFrame(1)

    def test_short_goaway_frame_errors(self):
        s = (
            b'\x00\x00\x0D\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x00\x00\x00\x40' +                      # Last Stream ID
            b'\x00\x00\x00'                            # short Error Code
        )
        with pytest.raises(InvalidFrameError):
            decode_frame(s)

    def test_goaway_frame_with_reserved_bit_set_parses_properly(self):
        s = (
            b'\x00\x00\x0D\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x80\x00\x00\x40' +                      # Last Stream ID with reserved bit set
            b'\x00\x00\x00\x20' +                      # Error Code
            b'hello'                                   # Additional data
        )
        f = decode_frame(s)

        assert isinstance(f, GoAwayFrame)
        assert f.flags == set()
        assert f.additional_data == b'hello'
        assert f.body_len == 13
        assert f.last_stream_id == 64

    def test_goaway_frame_with_reserved_bit_set_serializes_properly(self):
        f = GoAwayFrame()
        f.last_stream_id = 64
        f.error_code = 32
        f.additional_data = b'hello'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0D\x07\x00\x00\x00\x00\x00' +  # Frame header
            b'\x00\x00\x00\x40' +                      # Last Stream ID
            b'\x00\x00\x00\x20' +                      # Error Code
            b'hello'                                   # Additional data
        )


class TestWindowUpdateFrame:
    def test_repr(self):
        f = WindowUpdateFrame(0)
        assert repr(f).endswith("window_increment=0")
        f.stream_id = 1
        f.window_increment = 512
        assert repr(f).endswith("window_increment=512")

    def test_window_update_has_no_flags(self):
        f = WindowUpdateFrame(0)
        flags = f.parse_flags(0xFF)

        assert not flags
        assert isinstance(flags, Flags)

    def test_window_update_serializes_properly(self):
        f = WindowUpdateFrame(0)
        f.window_increment = 512

        s = f.serialize()
        assert s == b'\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x02\x00'

    def test_windowupdate_frame_parses_properly(self):
        s = b'\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x02\x00'
        f = decode_frame(s)

        assert isinstance(f, WindowUpdateFrame)
        assert f.flags == set()
        assert f.window_increment == 512
        assert f.body_len == 4

    def test_short_windowupdate_frame_errors(self):
        s = b'\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x02'  # -1 byte
        with pytest.raises(InvalidFrameError):
            decode_frame(s)

        s = b'\x00\x00\x05\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
        with pytest.raises(InvalidFrameError):
            decode_frame(s)

        with pytest.raises(InvalidDataError):
            decode_frame(WindowUpdateFrame(0).serialize())

        with pytest.raises(InvalidDataError):
            decode_frame(WindowUpdateFrame(2**31).serialize())

    def test_window_update_frame_with_reserved_bit_set_parses_properly(self):
        s = b'\x00\x00\x04\x08\x00\x00\x00\x00\x80\x00\x00\x02\x00'
        f = decode_frame(s)

        assert isinstance(f, WindowUpdateFrame)
        assert f.flags == set()
        assert f.window_increment == 512
        assert f.body_len == 4

    def test_window_update_frame_with_reserved_bit_set_serializes_properly(self):
        f = WindowUpdateFrame(0)
        f.window_increment = 512

        s = f.serialize()
        assert s == b'\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x02\x00'


class TestHeadersFrame:
    def test_repr(self):
        f = HeadersFrame(1)
        assert repr(f).endswith("exclusive=False, depends_on=0, stream_weight=0, data=None")
        f.data = b'hello'
        f.exclusive = True
        f.depends_on = 42
        f.stream_weight = 64
        assert repr(f).endswith("exclusive=True, depends_on=42, stream_weight=64, data=<hex:68656c6c6f>")

    def test_headers_frame_flags(self):
        f = HeadersFrame(1)
        flags = f.parse_flags(0xFF)

        assert flags == set(['END_STREAM', 'END_HEADERS',
                             'PADDED', 'PRIORITY'])

    def test_headers_frame_serializes_properly(self):
        f = HeadersFrame(1)
        f.flags = set(['END_STREAM', 'END_HEADERS'])
        f.data = b'hello world'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0B\x01\x05\x00\x00\x00\x01' +
            b'hello world'
        )

    def test_headers_frame_parses_properly(self):
        s = (
            b'\x00\x00\x0B\x01\x05\x00\x00\x00\x01' +
            b'hello world'
        )
        f = decode_frame(s)

        assert isinstance(f, HeadersFrame)
        assert f.flags == set(['END_STREAM', 'END_HEADERS'])
        assert f.data == b'hello world'
        assert f.body_len == 11

    def test_headers_frame_with_priority_parses_properly(self):
        # This test also tests that we can receive a HEADERS frame with no
        # actual headers on it. This is technically possible.
        s = (
            b'\x00\x00\x05\x01\x20\x00\x00\x00\x01' +
            b'\x80\x00\x00\x04\x40'
        )
        f = decode_frame(s)

        assert isinstance(f, HeadersFrame)
        assert f.flags == set(['PRIORITY'])
        assert f.data == b''
        assert f.depends_on == 4
        assert f.stream_weight == 64
        assert f.exclusive is True
        assert f.body_len == 5

    def test_headers_frame_with_priority_serializes_properly(self):
        # This test also tests that we can receive a HEADERS frame with no
        # actual headers on it. This is technically possible.
        s = (
            b'\x00\x00\x05\x01\x20\x00\x00\x00\x01' +
            b'\x80\x00\x00\x04\x40'
        )
        f = HeadersFrame(1)
        f.flags = set(['PRIORITY'])
        f.data = b''
        f.depends_on = 4
        f.stream_weight = 64
        f.exclusive = True

        assert f.serialize() == s

    def test_headers_frame_with_invalid_padding_fails_to_parse(self):
        # This frame has a padding length of 6 bytes, but a total length of
        # only 5.
        data = b'\x00\x00\x05\x01\x08\x00\x00\x00\x01\x06\x54\x65\x73\x74'

        with pytest.raises(InvalidPaddingError):
            decode_frame(data)

    def test_headers_frame_with_no_length_parses(self):
        # Fixes issue with empty data frames raising InvalidPaddingError.
        f = HeadersFrame(1)
        f.data = b''
        data = f.serialize()

        new_frame = decode_frame(data)
        assert new_frame.data == b''


class TestContinuationFrame:
    def test_repr(self):
        f = ContinuationFrame(1)
        assert repr(f).endswith("data=None")
        f.data = b'hello'
        assert repr(f).endswith("data=<hex:68656c6c6f>")

    def test_continuation_frame_flags(self):
        f = ContinuationFrame(1)
        flags = f.parse_flags(0xFF)

        assert flags == set(['END_HEADERS'])

    def test_continuation_frame_serializes(self):
        f = ContinuationFrame(1)
        f.parse_flags(0x04)
        f.data = b'hello world'

        s = f.serialize()
        assert s == (
            b'\x00\x00\x0B\x09\x04\x00\x00\x00\x01' +
            b'hello world'
        )

    def test_continuation_frame_parses_properly(self):
        s = b'\x00\x00\x0B\x09\x04\x00\x00\x00\x01hello world'
        f = decode_frame(s)

        assert isinstance(f, ContinuationFrame)
        assert f.flags == set(['END_HEADERS'])
        assert f.data == b'hello world'
        assert f.body_len == 11


class TestAltSvcFrame:
    payload_with_origin = (
        b'\x00\x00\x31'  # Length
        b'\x0A'  # Type
        b'\x00'  # Flags
        b'\x00\x00\x00\x00'  # Stream ID
        b'\x00\x0B'  # Origin len
        b'example.com'  # Origin
        b'h2="alt.example.com:8000", h2=":443"'  # Field Value
    )
    payload_without_origin = (
        b'\x00\x00\x13'  # Length
        b'\x0A'  # Type
        b'\x00'  # Flags
        b'\x00\x00\x00\x01'  # Stream ID
        b'\x00\x00'  # Origin len
        b''  # Origin
        b'h2=":8000"; ma=60'  # Field Value
    )
    payload_with_origin_and_stream = (
        b'\x00\x00\x36'  # Length
        b'\x0A'  # Type
        b'\x00'  # Flags
        b'\x00\x00\x00\x01'  # Stream ID
        b'\x00\x0B'  # Origin len
        b'example.com'  # Origin
        b'Alt-Svc: h2=":443"; ma=2592000; persist=1'  # Field Value
    )

    def test_repr(self):
        f = AltSvcFrame(0)
        assert repr(f).endswith("origin=b'', field=b''")
        f.field = b'h2="alt.example.com:8000", h2=":443"'
        assert repr(f).endswith("origin=b'', field=b'h2=\"alt.example.com:8000\", h2=\":443\"'")
        f.origin = b'example.com'
        assert repr(f).endswith("origin=b'example.com', field=b'h2=\"alt.example.com:8000\", h2=\":443\"'")

    def test_altsvc_frame_flags(self):
        f = AltSvcFrame(0)
        flags = f.parse_flags(0xFF)

        assert flags == set()

    def test_altsvc_frame_with_origin_serializes_properly(self):
        f = AltSvcFrame(0)
        f.origin = b'example.com'
        f.field = b'h2="alt.example.com:8000", h2=":443"'

        s = f.serialize()
        assert s == self.payload_with_origin

    def test_altsvc_frame_with_origin_parses_properly(self):
        f = decode_frame(self.payload_with_origin)

        assert isinstance(f, AltSvcFrame)
        assert f.origin == b'example.com'
        assert f.field == b'h2="alt.example.com:8000", h2=":443"'
        assert f.body_len == 49
        assert f.stream_id == 0

    def test_altsvc_frame_without_origin_serializes_properly(self):
        f = AltSvcFrame(1, origin=b'', field=b'h2=":8000"; ma=60')
        s = f.serialize()
        assert s == self.payload_without_origin

    def test_altsvc_frame_without_origin_parses_properly(self):
        f = decode_frame(self.payload_without_origin)

        assert isinstance(f, AltSvcFrame)
        assert f.origin == b''
        assert f.field == b'h2=":8000"; ma=60'
        assert f.body_len == 19
        assert f.stream_id == 1

    def test_altsvc_frame_with_origin_and_stream_serializes_properly(self):
        # This frame is not valid, but we allow it to be serialized anyway.
        f = AltSvcFrame(1)
        f.origin = b'example.com'
        f.field = b'Alt-Svc: h2=":443"; ma=2592000; persist=1'

        assert f.serialize() == self.payload_with_origin_and_stream

    def test_short_altsvc_frame_errors(self):
        with pytest.raises(InvalidFrameError):
            decode_frame(self.payload_with_origin[:12])

        with pytest.raises(InvalidFrameError):
            decode_frame(self.payload_with_origin[:10])

    def test_altsvc_with_unicode_origin_fails(self):
        with pytest.raises(InvalidDataError):
            AltSvcFrame(
                stream_id=0, origin=u'hello', field=b'h2=":8000"; ma=60'

            )

    def test_altsvc_with_unicode_field_fails(self):
        with pytest.raises(InvalidDataError):
            AltSvcFrame(
                stream_id=0, origin=b'hello', field=u'h2=":8000"; ma=60'
            )


class TestExtensionFrame:
    def test_repr(self):
        f = ExtensionFrame(0xFF, 1, 42, b'hello')
        assert repr(f).endswith("type=255, flag_byte=42, body=<hex:68656c6c6f>")
