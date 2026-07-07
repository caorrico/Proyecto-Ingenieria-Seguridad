import hmac
from pathlib import Path

from cryptography.hazmat.primitives import hashes


def hash_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 hash of bytes data.

    Args:
        data: Bytes to hash.

    Returns:
        Hex-encoded SHA-256 hash as string.

    Raises:
        ValueError: If data is None or not bytes.
    """
    if data is None:
        raise ValueError("Data cannot be None")
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def hash_file_sha256(file_path: str, chunk_size: int = 8192) -> str:
    """
    Calculate SHA-256 hash of a file by reading in chunks.

    Useful for large files without loading entire content in memory.

    Args:
        file_path: Path to the file.
        chunk_size: Number of bytes to read per chunk (default 8192).

    Returns:
        Hex-encoded SHA-256 hash as string.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If chunk_size is invalid.
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive")

    file_path_obj = Path(file_path)
    if not file_path_obj.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    if not file_path_obj.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    digest = hashes.Hash(hashes.SHA256())

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.finalize().hex()


def verify_sha256(data: bytes, expected_hash: str) -> bool:
    """
    Verify data integrity by comparing its hash with expected hash.

    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.

    Args:
        data: Bytes to verify.
        expected_hash: Expected hex-encoded SHA-256 hash.

    Returns:
        True if hash matches, False otherwise.

    Raises:
        ValueError: If data is None or expected_hash is invalid.
    """
    if data is None:
        raise ValueError("Data cannot be None")
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")
    if not isinstance(expected_hash, str):
        raise TypeError("Expected hash must be a string")

    try:
        calculated_hash = hash_sha256(data)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Failed to calculate hash: {e}")

    return hmac.compare_digest(calculated_hash, expected_hash)


def verify_file_sha256(file_path: str, expected_hash: str) -> bool:
    """
    Verify file integrity by comparing its hash with expected hash.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        file_path: Path to the file.
        expected_hash: Expected hex-encoded SHA-256 hash.

    Returns:
        True if hash matches, False otherwise.

    Raises:
        FileNotFoundError: If file does not exist.
        ValueError: If expected_hash is invalid.
    """
    if not isinstance(expected_hash, str):
        raise TypeError("Expected hash must be a string")

    try:
        calculated_hash = hash_file_sha256(file_path)
    except (FileNotFoundError, ValueError) as e:
        raise

    return hmac.compare_digest(calculated_hash, expected_hash)
