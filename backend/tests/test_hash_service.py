import tempfile
from pathlib import Path

import pytest

from app.services.hash_service import (
    hash_file_sha256,
    hash_sha256,
    verify_file_sha256,
    verify_sha256,
)


class TestHashSha256:
    """Tests for SHA-256 hashing of bytes data."""

    def test_hash_with_known_value(self) -> None:
        """Test SHA-256 hash against a known value."""
        data = b"hello world"
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

        result = hash_sha256(data)

        assert result == expected_hash

    def test_hash_deterministic(self) -> None:
        """Test that hashing same data twice produces same result."""
        data = b"test data for hashing"

        hash1 = hash_sha256(data)
        hash2 = hash_sha256(data)

        assert hash1 == hash2

    def test_hash_changes_with_single_byte_change(self) -> None:
        """Test that changing a single byte completely changes the hash."""
        data1 = b"hello world"
        data2 = b"hello worle"  # Changed last 'd' to 'e'

        hash1 = hash_sha256(data1)
        hash2 = hash_sha256(data2)

        assert hash1 != hash2
        assert len(hash1) == len(hash2)  # Same length but different values

    def test_hash_empty_bytes(self) -> None:
        """Test hashing empty bytes."""
        data = b""
        expected_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        result = hash_sha256(data)

        assert result == expected_hash

    def test_hash_large_data(self) -> None:
        """Test hashing large data (100 MB)."""
        data = b"x" * (100 * 1024 * 1024)  # 100 MB

        result = hash_sha256(data)

        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex is always 64 characters

    def test_hash_none_data_raises_error(self) -> None:
        """Test that hashing None raises ValueError."""
        with pytest.raises(ValueError, match="Data cannot be None"):
            hash_sha256(None)

    def test_hash_non_bytes_data_raises_error(self) -> None:
        """Test that hashing non-bytes data raises TypeError."""
        with pytest.raises(TypeError, match="Data must be bytes"):
            hash_sha256("not bytes")

        with pytest.raises(TypeError, match="Data must be bytes"):
            hash_sha256(123)


class TestHashFileSha256:
    """Tests for SHA-256 hashing of files."""

    def test_hash_file_with_known_content(self) -> None:
        """Test hashing a file with known content."""
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"hello world")
            temp_path = f.name

        try:
            result = hash_file_sha256(temp_path)
            expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

            assert result == expected
        finally:
            Path(temp_path).unlink()

    def test_hash_file_matches_hash_bytes(self) -> None:
        """Test that hashing a file gives same result as hashing its content as bytes."""
        content = b"test file content with some data"

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(content)
            temp_path = f.name

        try:
            file_hash = hash_file_sha256(temp_path)
            bytes_hash = hash_sha256(content)

            assert file_hash == bytes_hash
        finally:
            Path(temp_path).unlink()

    def test_hash_file_large_file(self) -> None:
        """Test hashing a large file (50 MB) by chunks."""
        # Create a 50 MB file
        content = b"x" * (50 * 1024 * 1024)

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(content)
            temp_path = f.name

        try:
            # Hash by file chunks
            file_hash = hash_file_sha256(temp_path)

            # Hash entire content at once
            bytes_hash = hash_sha256(content)

            # Results should be identical
            assert file_hash == bytes_hash
        finally:
            Path(temp_path).unlink()

    def test_hash_file_with_custom_chunk_size(self) -> None:
        """Test that different chunk sizes produce same result."""
        content = b"test content for chunk size verification" * 100

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(content)
            temp_path = f.name

        try:
            hash_small_chunks = hash_file_sha256(temp_path, chunk_size=1024)
            hash_large_chunks = hash_file_sha256(temp_path, chunk_size=1024 * 1024)

            assert hash_small_chunks == hash_large_chunks
        finally:
            Path(temp_path).unlink()

    def test_hash_nonexistent_file_raises_error(self) -> None:
        """Test that hashing nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            hash_file_sha256("/nonexistent/file/path.txt")

    def test_hash_directory_raises_error(self) -> None:
        """Test that hashing a directory raises ValueError."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with pytest.raises(ValueError, match="Path is not a file"):
                hash_file_sha256(temp_dir)

    def test_hash_invalid_chunk_size_raises_error(self) -> None:
        """Test that invalid chunk size raises ValueError."""
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"test")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Chunk size must be positive"):
                hash_file_sha256(temp_path, chunk_size=0)

            with pytest.raises(ValueError, match="Chunk size must be positive"):
                hash_file_sha256(temp_path, chunk_size=-1)
        finally:
            Path(temp_path).unlink()


class TestVerifySha256:
    """Tests for SHA-256 verification of bytes."""

    def test_verify_correct_hash(self) -> None:
        """Test verification with correct hash."""
        data = b"hello world"
        correct_hash = hash_sha256(data)

        assert verify_sha256(data, correct_hash) is True

    def test_verify_incorrect_hash(self) -> None:
        """Test verification with incorrect hash."""
        data = b"hello world"
        incorrect_hash = "0000000000000000000000000000000000000000000000000000000000000000"

        assert verify_sha256(data, incorrect_hash) is False

    def test_verify_modified_data(self) -> None:
        """Test verification fails when data is modified."""
        original_data = b"hello world"
        original_hash = hash_sha256(original_data)

        modified_data = b"hello worle"  # Modified

        assert verify_sha256(modified_data, original_hash) is False

    def test_verify_empty_data(self) -> None:
        """Test verification of empty data."""
        data = b""
        correct_hash = hash_sha256(data)

        assert verify_sha256(data, correct_hash) is True

    def test_verify_none_data_raises_error(self) -> None:
        """Test that verifying None data raises ValueError."""
        with pytest.raises(ValueError, match="Data cannot be None"):
            verify_sha256(None, "somehash")

    def test_verify_non_bytes_data_raises_error(self) -> None:
        """Test that verifying non-bytes data raises TypeError."""
        with pytest.raises(TypeError, match="Data must be bytes"):
            verify_sha256("string", "somehash")

    def test_verify_non_string_hash_raises_error(self) -> None:
        """Test that non-string hash raises TypeError."""
        with pytest.raises(TypeError, match="Expected hash must be a string"):
            verify_sha256(b"data", 12345)


class TestVerifyFileSha256:
    """Tests for SHA-256 verification of files."""

    def test_verify_correct_file_hash(self) -> None:
        """Test file verification with correct hash."""
        content = b"file content for verification"

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(content)
            temp_path = f.name

        try:
            correct_hash = hash_file_sha256(temp_path)
            assert verify_file_sha256(temp_path, correct_hash) is True
        finally:
            Path(temp_path).unlink()

    def test_verify_incorrect_file_hash(self) -> None:
        """Test file verification with incorrect hash."""
        content = b"file content"

        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(content)
            temp_path = f.name

        try:
            wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            assert verify_file_sha256(temp_path, wrong_hash) is False
        finally:
            Path(temp_path).unlink()

    def test_verify_nonexistent_file_raises_error(self) -> None:
        """Test that verifying nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            verify_file_sha256("/nonexistent/file.txt", "somehash")

    def test_verify_non_string_hash_raises_error(self) -> None:
        """Test that non-string hash raises TypeError."""
        with tempfile.NamedTemporaryFile(delete=False, mode="wb") as f:
            f.write(b"content")
            temp_path = f.name

        try:
            with pytest.raises(TypeError, match="Expected hash must be a string"):
                verify_file_sha256(temp_path, 12345)
        finally:
            Path(temp_path).unlink()
