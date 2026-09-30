import base64
import socket
import smtplib
import tempfile
import threading
from contextlib import contextmanager
from email import message_from_bytes, policy
from pathlib import Path

from django.core.mail import EmailMessage
from django.core.mail.backends import smtp
from django.core.mail.message import StreamingBinaryAttachment, StreamingFileAttachment
from django.test import SimpleTestCase


class LimitedReadStream:
    def __init__(self, data, max_read_size, fail_reads=0):
        self.data = memoryview(data)
        self.offset = 0
        self.max_read_size = max_read_size
        self.max_observed_read = 0
        self.read_calls = 0
        self.fail_reads = fail_reads
        self.closed = False

    def read(self, size=-1):
        if size is None or size < 0:
            raise AssertionError("streaming attachments must use bounded reads")
        self.read_calls += 1
        if self.fail_reads:
            self.fail_reads -= 1
            raise OSError("read failure")
        self.max_observed_read = max(self.max_observed_read, size)
        if size > self.max_read_size:
            raise AssertionError(
                f"requested {size} bytes, limit is {self.max_read_size}"
            )
        chunk = self.data[self.offset : self.offset + size]
        self.offset += len(chunk)
        return bytes(chunk)

    def close(self):
        self.closed = True


class SMTPTestSession:
    def __init__(self):
        self.messages = []

    def handle(self, rfile, wfile):
        in_data = False
        data = b""
        envelope = {}
        wfile.write(b"220 localhost SMTP\r\n")
        wfile.flush()

        while True:
            line = rfile.readline()
            if not line:
                return
            line = line[:-2]

            if in_data:
                line += b"\r\n"
                if line == b".\r\n":
                    self.messages.append((dict(envelope), data))
                    data = b""
                    in_data = False
                    wfile.write(b"250 OK\r\n")
                    wfile.flush()
                    continue
                if line.startswith(b".."):
                    line = line[1:]
                data += line
                continue

            command, _, argument = line.partition(b" ")
            command = command.upper()
            if command == b"EHLO":
                wfile.write(b"250-localhost\r\n250 AUTH\r\n")
            elif command == b"MAIL":
                envelope.clear()
                envelope["mail_from"] = argument.decode()
                wfile.write(b"250 OK\r\n")
            elif command == b"RCPT":
                envelope.setdefault("rcpt_tos", []).append(argument.decode())
                wfile.write(b"250 OK\r\n")
            elif command == b"DATA":
                in_data = True
                wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif command == b"RSET":
                in_data = False
                data = b""
                envelope.clear()
                wfile.write(b"250 OK\r\n")
            elif command == b"QUIT":
                wfile.write(b"221 Bye\r\n")
                wfile.flush()
                return
            else:
                wfile.write(b"250 OK\r\n")
            wfile.flush()


@contextmanager
def smtp_session():
    client_sock, server_sock = socket.socketpair()
    session = SMTPTestSession()
    server_thread = threading.Thread(
        target=session.handle,
        args=(server_sock.makefile("rb"), server_sock.makefile("wb")),
        daemon=True,
    )
    server_thread.start()
    client = smtplib.SMTP(local_hostname="localhost")
    client.sock = client_sock
    client.file = client_sock.makefile("rb")
    client.getreply()
    client.ehlo("localhost")
    try:
        yield client, session
        client.quit()
    finally:
        client.close()
        server_sock.close()
        server_thread.join(timeout=2)


class StreamingSMTPTests(SimpleTestCase):
    def backend(self, connection, **kwargs):
        backend = smtp.EmailBackend(
            alias="streaming-test",
            host="localhost",
            port=25,
            stream_chunk_size=4096,
            **kwargs,
        )
        backend.connection = connection
        return backend

    def send_streaming_attachment(
        self, connection, source, filename, content, mimetype
    ):
        message = EmailMessage(
            "流式主题",
            "正文\n.dotted body line",
            "from@example.com",
            ["to@example.com"],
        )
        if isinstance(source, Path):
            message.attach_file(filename, mimetype=mimetype, stream=True)
        else:
            message.attach_stream(
                source, filename, mimetype=mimetype, close_stream=False
            )

        backend = self.backend(connection)
        self.assertEqual(backend.send_messages([message]), 1)
        return message

    def test_file_attachment_is_streamed_and_restored(self):
        content = b"\r\n".join(
            [b".leading dot", bytes(range(256)) * 90, "中文内容".encode()]
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "中文 报告.bin"
            path.write_bytes(content)
            with smtp_session() as (connection, session):
                message = self.send_streaming_attachment(
                    connection, path, path, content, "application/octet-stream"
                )
                self.send_streaming_attachment(
                    connection, path, path, content, "application/octet-stream"
                )
                envelope, raw_message = session.messages[-1]
                parsed = message_from_bytes(raw_message, policy=policy.default)
                attachment = next(parsed.iter_attachments())
                self.assertEqual(attachment.get_filename(), "中文 报告.bin")
                self.assertEqual(attachment.get_payload(decode=True), content)
                self.assertEqual(envelope["rcpt_tos"], ["TO:<to@example.com>"])

    def test_binary_stream_uses_bounded_reads_and_cannot_be_resent(self):
        content = base64.b64encode(b"x" * 300000) + b"\r\n.dot\r\n"
        stream = LimitedReadStream(content, 4096)
        with smtp_session() as (connection, session):
            message = self.send_streaming_attachment(
                connection,
                stream,
                "一次性流.dat",
                content,
                "application/octet-stream",
            )
            self.assertLessEqual(stream.max_observed_read, 4096)
            self.assertGreater(stream.read_calls, 1)
            self.assertFalse(stream.closed)
            envelope, raw_message = session.messages[0]
            parsed = message_from_bytes(raw_message, policy=policy.default)
            attachment = next(parsed.iter_attachments())
            self.assertEqual(attachment.get_filename(), "一次性流.dat")
            self.assertEqual(attachment.get_payload(decode=True), content)
            self.assertEqual(envelope["mail_from"], "FROM:<from@example.com>")

            with self.assertRaisesMessage(ValueError, "can only be sent once"):
                self.backend(connection).send_messages([message])

    def test_external_stream_is_closed_when_requested(self):
        stream = LimitedReadStream(b"data", 4096)
        attachment = StreamingBinaryAttachment(
            stream, "closed.dat", "application/octet-stream", close_stream=True
        )
        with smtp_session() as (connection, session):
            message = EmailMessage(to=["to@example.com"], attachments=[attachment])
            self.assertEqual(self.backend(connection).send_messages([message]), 1)
            self.assertTrue(stream.closed)
            self.assertEqual(len(session.messages), 1)

    def test_message_rejects_streaming_attachment(self):
        message = EmailMessage(to=["to@example.com"])
        message.attach_stream(BytesIOLike(b"data"), "file.bin")
        with self.assertRaisesMessage(ValueError, "streaming serialization"):
            message.message()


class BytesIOLike:
    def __init__(self, data):
        self.data = data

    def read(self, size=-1):
        chunk = self.data[:size]
        self.data = self.data[size:]
        return chunk

    def close(self):
        pass


class StreamingSMTPHelpersTests(SimpleTestCase):
    def test_base64_chunks_remain_correct_across_block_boundaries(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "data.bin"
            for size in range(0, 130):
                path.write_bytes(
                    bytes(range(256)) * (size // 256) + bytes(range(size % 256))
                )
                attachment = StreamingFileAttachment(path)
                for read_size in range(1, 13):
                    encoded = b"".join(attachment.chunks(read_size))
                    self.assertEqual(
                        encoded,
                        base64.encodebytes(path.read_bytes()).replace(
                            b"\n", b"\r\n"
                        ),
                    )

    def test_stream_chunk_size_must_be_positive(self):
        with self.assertRaisesMessage(
            ValueError, "stream_chunk_size must be a positive integer"
        ):
            smtp.EmailBackend(
                alias="streaming-test", host="localhost", stream_chunk_size=0
            )

    def test_quote_smtp_data_escapes_lines_starting_with_period(self):
        chunks = iter(
            [
                b"Subject: test\r\n\r\n.one\r\n..two\r\nsp",
                b"lit\r\n.four\r\n.",
                b"\r\n",
            ]
        )
        self.assertEqual(
            b"".join(smtp.quote_smtp_data(chunks)),
            b"Subject: test\r\n\r\n..one\r\n...two\r\nsplit\r\n..four\r\n..\r\n.\r\n",
        )

    def test_binary_stream_is_marked_consumed_after_failed_read(self):
        class FailingStream:
            def __init__(self):
                self.closed = False

            def read(self, size):
                raise OSError("boom")

            def close(self):
                self.closed = True

        stream = FailingStream()
        attachment = StreamingBinaryAttachment(
            stream, "failure.bin", close_stream=True
        )
        with self.assertRaises(OSError):
            b"".join(attachment.chunks(1024))
        self.assertTrue(stream.closed)
        with self.assertRaisesMessage(ValueError, "can only be sent once"):
            attachment.prepare_to_send()

    def test_streamed_file_can_reopen_after_a_failed_send_attempt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "retry.bin"
            file_path.write_bytes(b"retryable content")
            message = EmailMessage(to=["to@example.com"])
            message.attach_file(file_path, stream=True)
            attachment = message.attachments[0]

            class FailingStream:
                def read(self, size):
                    raise OSError("read failure")

                def close(self):
                    pass

            attachment.stream = FailingStream()
            attachment._opened = True
            attachment._consumed = True
            with self.assertRaises(OSError):
                b"".join(attachment.chunks(4096))

            self.assertEqual(
                b"".join(attachment.chunks(4096)),
                b"cmV0cnlhYmxlIGNvbnRlbnQ=\r\n",
            )
