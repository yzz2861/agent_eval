import hashlib
from pathlib import Path

import pytest

from python_multipart.exceptions import FileError
from python_multipart.multipart import File


def test_upload_dir_with_leading_slash_in_filename(tmp_path: Path) -> None:
    upload_dir = tmp_path / "upload"
    upload_dir.mkdir()

    # When the file_name provided has a leading slash, we should only use the basename.
    # This is to avoid directory traversal.
    to_upload = tmp_path / "foo.txt"

    file = File(
        bytes(to_upload),
        config={
            "UPLOAD_DIR": bytes(upload_dir),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    assert not file.in_memory
    assert Path(upload_dir / "foo.txt").exists()
    assert Path(upload_dir / "foo.txt").read_bytes() == b"123456789012"


def test_str_upload_dir_with_keep_filename(tmp_path: Path) -> None:
    file = File(
        b"foo.txt",
        config={
            "UPLOAD_DIR": str(tmp_path),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    file.close()

    assert not file.in_memory
    assert file.actual_file_name == b"foo.txt"
    assert (tmp_path / "foo.txt").read_bytes() == b"123456789012"


def test_keep_extensions_without_filename() -> None:
    # An application/octet-stream upload has no filename; keeping the
    # extension must not fail when the file moves to disk.
    file = File(None, config={"UPLOAD_KEEP_EXTENSIONS": True, "MAX_MEMORY_FILE_SIZE": 10})
    file.write(b"123456789012")
    assert not file.in_memory
    assert file.actual_file_name is not None


def test_keep_filename_without_filename(tmp_path: Path) -> None:
    # Without a filename to keep, the file goes to a temporary name in UPLOAD_DIR.
    file = File(
        None,
        config={
            "UPLOAD_DIR": bytes(tmp_path),
            "UPLOAD_KEEP_FILENAME": True,
            "UPLOAD_KEEP_EXTENSIONS": True,
            "UPLOAD_DELETE_TMP": False,
            "MAX_MEMORY_FILE_SIZE": 10,
        },
    )
    file.write(b"123456789012")
    file.close()
    assert not file.in_memory
    assert file.actual_file_name is not None
    assert Path(file.actual_file_name.decode()).parent == tmp_path
    assert Path(file.actual_file_name.decode()).read_bytes() == b"123456789012"


def test_file_size_and_digest_are_observable(tmp_path: Path) -> None:
    data = b"content that crosses the memory threshold"
    file = File(
        b"sample.bin", config={"UPLOAD_TMP_DIR": str(tmp_path), "MAX_MEMORY_FILE_SIZE": 1, "UPLOAD_DELETE_TMP": False}
    )
    file.write(data)

    assert file.size == len(data)
    assert file.digest == hashlib.sha256(data).hexdigest()
    assert file.digest_bytes == hashlib.sha256(data).digest()

    file.close()


def test_close_is_idempotent() -> None:
    file = File(b"sample.bin")
    file.write(b"data")

    file.close()
    file.close()

    assert file.file_object.closed


def test_max_file_size_fails_before_writing_more(tmp_path: Path) -> None:
    file = File(b"sample.bin", config={"UPLOAD_TMP_DIR": str(tmp_path), "MAX_MEMORY_FILE_SIZE": 1, "MAX_FILE_SIZE": 4})
    file.write(b"1234")
    assert file.size == 4

    with pytest.raises(FileError, match="File exceeds maximum size"):
        file.write(b"5")

    assert file.size == 4
    file.file_object.seek(0)
    assert file.file_object.read() == b"1234"
    file.close()
