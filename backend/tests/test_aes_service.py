import pytest
from cryptography.exceptions import InvalidTag

from app.services.aes_service import (
    EncryptedData,
    decrypt_aes_256_gcm,
    decrypt_aes_256_gcm_raw,
    encrypt_aes_256_gcm,
    encrypt_aes_256_gcm_raw,
    generate_aes_key,
)


class TestGenerateAesKey:
    """Tests for AES key generation."""

    def test_generate_aes_256_key(self) -> None:
        """Test generating AES-256 key (32 bytes)."""
        key = generate_aes_key(256)

        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_generate_aes_192_key(self) -> None:
        """Test generating AES-192 key (24 bytes)."""
        key = generate_aes_key(192)

        assert isinstance(key, bytes)
        assert len(key) == 24

    def test_generate_aes_128_key(self) -> None:
        """Test generating AES-128 key (16 bytes)."""
        key = generate_aes_key(128)

        assert isinstance(key, bytes)
        assert len(key) == 16

    def test_generate_aes_key_default_is_256(self) -> None:
        """Test that default key size is 256 bits (32 bytes)."""
        key = generate_aes_key()

        assert len(key) == 32

    def test_generate_aes_key_randomness(self) -> None:
        """Test that generated keys are random (different each time)."""
        key1 = generate_aes_key(256)
        key2 = generate_aes_key(256)

        assert key1 != key2

    def test_generate_aes_key_invalid_size_raises_error(self) -> None:
        """Test that invalid key size raises ValueError."""
        with pytest.raises(ValueError, match="Key size must be one of"):
            generate_aes_key(256 + 1)  # Invalid size

        with pytest.raises(ValueError, match="Key size must be one of"):
            generate_aes_key(512)

        with pytest.raises(ValueError, match="Key size must be one of"):
            generate_aes_key(64)


class TestEncryptAes256Gcm:
    """Tests for AES-256-GCM encryption."""

    def test_encrypt_plaintext(self) -> None:
        """Test basic encryption."""
        key = generate_aes_key(256)
        plaintext = b"Hello, World!"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        assert isinstance(encrypted_data, EncryptedData)
        assert isinstance(encrypted_data.ciphertext, bytes)
        assert isinstance(encrypted_data.iv, bytes)
        assert isinstance(encrypted_data.tag, bytes)
        assert len(encrypted_data.iv) == 12  # GCM nonce is 12 bytes
        assert len(encrypted_data.tag) == 16  # GCM tag is 16 bytes

    def test_encrypt_empty_plaintext(self) -> None:
        """Test encrypting empty plaintext."""
        key = generate_aes_key(256)
        plaintext = b""

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        assert encrypted_data.ciphertext == b""  # Empty plaintext, empty ciphertext
        assert len(encrypted_data.iv) == 12
        assert len(encrypted_data.tag) == 16

    def test_encrypt_large_plaintext(self) -> None:
        """Test encrypting large plaintext (100 MB)."""
        key = generate_aes_key(256)
        plaintext = b"x" * (100 * 1024 * 1024)

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        assert len(encrypted_data.ciphertext) == len(plaintext)

    def test_encrypt_each_call_generates_different_iv(self) -> None:
        """Test that each encryption generates a different IV (nonce)."""
        key = generate_aes_key(256)
        plaintext = b"Same message"

        encrypted1 = encrypt_aes_256_gcm(plaintext, key)
        encrypted2 = encrypt_aes_256_gcm(plaintext, key)

        # Different IVs
        assert encrypted1.iv != encrypted2.iv
        # Different ciphertexts (because different IVs)
        assert encrypted1.ciphertext != encrypted2.ciphertext
        # But same tags length (always 16 for GCM)
        assert len(encrypted1.tag) == len(encrypted2.tag)

    def test_encrypt_invalid_key_length_raises_error(self) -> None:
        """Test that invalid key length raises ValueError."""
        plaintext = b"test"

        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            encrypt_aes_256_gcm(plaintext, b"short_key")

        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            encrypt_aes_256_gcm(plaintext, b"x" * 16)  # 16 bytes, not 32

    def test_encrypt_non_bytes_plaintext_raises_error(self) -> None:
        """Test that non-bytes plaintext raises TypeError."""
        key = generate_aes_key(256)

        with pytest.raises(TypeError, match="Plaintext must be bytes"):
            encrypt_aes_256_gcm("string plaintext", key)

        with pytest.raises(TypeError, match="Plaintext must be bytes"):
            encrypt_aes_256_gcm(123, key)

    def test_encrypt_non_bytes_key_raises_error(self) -> None:
        """Test that non-bytes key raises TypeError."""
        plaintext = b"test"

        with pytest.raises(TypeError, match="Key must be bytes"):
            encrypt_aes_256_gcm(plaintext, "string key")


class TestDecryptAes256Gcm:
    """Tests for AES-256-GCM decryption."""

    def test_decrypt_round_trip(self) -> None:
        """Test that decrypt(encrypt(plaintext)) == plaintext."""
        key = generate_aes_key(256)
        original_plaintext = b"Hello, World! This is a test message."

        encrypted_data = encrypt_aes_256_gcm(original_plaintext, key)
        decrypted_plaintext = decrypt_aes_256_gcm(encrypted_data, key)

        assert decrypted_plaintext == original_plaintext

    def test_decrypt_empty_plaintext_round_trip(self) -> None:
        """Test round-trip with empty plaintext."""
        key = generate_aes_key(256)
        original_plaintext = b""

        encrypted_data = encrypt_aes_256_gcm(original_plaintext, key)
        decrypted_plaintext = decrypt_aes_256_gcm(encrypted_data, key)

        assert decrypted_plaintext == original_plaintext

    def test_decrypt_large_plaintext_round_trip(self) -> None:
        """Test round-trip with large plaintext."""
        key = generate_aes_key(256)
        original_plaintext = b"x" * (10 * 1024 * 1024)  # 10 MB

        encrypted_data = encrypt_aes_256_gcm(original_plaintext, key)
        decrypted_plaintext = decrypt_aes_256_gcm(encrypted_data, key)

        assert decrypted_plaintext == original_plaintext

    def test_decrypt_multiple_messages_with_same_key(self) -> None:
        """Test decrypting multiple different messages with same key."""
        key = generate_aes_key(256)
        messages = [b"Message 1", b"Message 2", b"Message 3"]

        encrypted_list = [encrypt_aes_256_gcm(msg, key) for msg in messages]
        decrypted_list = [decrypt_aes_256_gcm(enc, key) for enc in encrypted_list]

        assert decrypted_list == messages

    def test_decrypt_wrong_key_raises_error(self) -> None:
        """Test that decrypting with wrong key raises InvalidTag."""
        key1 = generate_aes_key(256)
        key2 = generate_aes_key(256)
        plaintext = b"secret message"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key1)

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm(encrypted_data, key2)

    def test_decrypt_tampered_ciphertext_raises_error(self) -> None:
        """Test that tampering with ciphertext causes InvalidTag."""
        key = generate_aes_key(256)
        plaintext = b"secret message"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        # Tamper with ciphertext
        tampered_ciphertext = bytes(
            [encrypted_data.ciphertext[0] ^ 0xFF] + list(encrypted_data.ciphertext[1:])
        )
        tampered_data = EncryptedData(
            ciphertext=tampered_ciphertext, iv=encrypted_data.iv, tag=encrypted_data.tag
        )

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm(tampered_data, key)

    def test_decrypt_tampered_tag_raises_error(self) -> None:
        """Test that tampering with authentication tag causes InvalidTag."""
        key = generate_aes_key(256)
        plaintext = b"secret message"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        # Tamper with tag
        tampered_tag = bytes([encrypted_data.tag[0] ^ 0xFF] + list(encrypted_data.tag[1:]))
        tampered_data = EncryptedData(
            ciphertext=encrypted_data.ciphertext, iv=encrypted_data.iv, tag=tampered_tag
        )

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm(tampered_data, key)

    def test_decrypt_tampered_iv_raises_error(self) -> None:
        """Test that tampering with IV causes InvalidTag."""
        key = generate_aes_key(256)
        plaintext = b"secret message"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        # Tamper with IV
        tampered_iv = bytes([encrypted_data.iv[0] ^ 0xFF] + list(encrypted_data.iv[1:]))
        tampered_data = EncryptedData(
            ciphertext=encrypted_data.ciphertext, iv=tampered_iv, tag=encrypted_data.tag
        )

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm(tampered_data, key)

    def test_decrypt_invalid_key_length_raises_error(self) -> None:
        """Test that invalid key length raises ValueError."""
        key = generate_aes_key(256)
        plaintext = b"test"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        with pytest.raises(ValueError, match="Key must be 32 bytes"):
            decrypt_aes_256_gcm(encrypted_data, b"short_key")

    def test_decrypt_non_bytes_key_raises_error(self) -> None:
        """Test that non-bytes key raises TypeError."""
        key = generate_aes_key(256)
        plaintext = b"test"

        encrypted_data = encrypt_aes_256_gcm(plaintext, key)

        with pytest.raises(TypeError, match="Key must be bytes"):
            decrypt_aes_256_gcm(encrypted_data, "string key")


class TestEncryptDecryptRaw:
    """Tests for raw encryption/decryption functions (ciphertext, iv, tag as separate bytes)."""

    def test_encrypt_raw_returns_three_components(self) -> None:
        """Test that encrypt_raw returns (ciphertext, iv, tag) tuple."""
        key = generate_aes_key(256)
        plaintext = b"test message"

        ciphertext, iv, tag = encrypt_aes_256_gcm_raw(plaintext, key)

        assert isinstance(ciphertext, bytes)
        assert isinstance(iv, bytes)
        assert isinstance(tag, bytes)
        assert len(iv) == 12
        assert len(tag) == 16

    def test_encrypt_decrypt_raw_round_trip(self) -> None:
        """Test round-trip with raw functions."""
        key = generate_aes_key(256)
        original_plaintext = b"Hello, Secure World!"

        ciphertext, iv, tag = encrypt_aes_256_gcm_raw(original_plaintext, key)
        decrypted_plaintext = decrypt_aes_256_gcm_raw(ciphertext, iv, tag, key)

        assert decrypted_plaintext == original_plaintext

    def test_decrypt_raw_wrong_key_raises_error(self) -> None:
        """Test that decrypt_raw with wrong key raises InvalidTag."""
        key1 = generate_aes_key(256)
        key2 = generate_aes_key(256)
        plaintext = b"secret"

        ciphertext, iv, tag = encrypt_aes_256_gcm_raw(plaintext, key1)

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm_raw(ciphertext, iv, tag, key2)

    def test_decrypt_raw_tampered_ciphertext_raises_error(self) -> None:
        """Test that decrypt_raw detects tampered ciphertext."""
        key = generate_aes_key(256)
        plaintext = b"secret"

        ciphertext, iv, tag = encrypt_aes_256_gcm_raw(plaintext, key)

        # Tamper with ciphertext
        tampered_ciphertext = bytes([ciphertext[0] ^ 0xFF] + list(ciphertext[1:]))

        with pytest.raises(InvalidTag):
            decrypt_aes_256_gcm_raw(tampered_ciphertext, iv, tag, key)


class TestEncryptedDataClass:
    """Tests for EncryptedData dataclass."""

    def test_encrypted_data_is_frozen(self) -> None:
        """Test that EncryptedData is immutable (frozen)."""
        data = EncryptedData(ciphertext=b"cipher", iv=b"iv" * 6, tag=b"tag" * 5)

        with pytest.raises(AttributeError):
            data.ciphertext = b"modified"

    def test_encrypted_data_equality(self) -> None:
        """Test EncryptedData equality."""
        data1 = EncryptedData(ciphertext=b"cipher", iv=b"iv" * 6, tag=b"tag" * 5)
        data2 = EncryptedData(ciphertext=b"cipher", iv=b"iv" * 6, tag=b"tag" * 5)
        data3 = EncryptedData(ciphertext=b"different", iv=b"iv" * 6, tag=b"tag" * 5)

        assert data1 == data2
        assert data1 != data3
