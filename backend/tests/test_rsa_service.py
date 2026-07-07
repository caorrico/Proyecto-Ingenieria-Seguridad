import pytest
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from app.services.rsa_service import (
    decrypt_rsa,
    deserialize_private_key_pem,
    deserialize_public_key_pem,
    encrypt_rsa,
    generate_rsa_keypair,
    serialize_private_key_pem,
    serialize_public_key_pem,
)


class TestGenerateRsaKeypair:
    """Tests for RSA key pair generation."""

    def test_generate_rsa_keypair_default_size(self) -> None:
        """Test generating RSA keypair with default size (4096 bits)."""
        private_key, public_key = generate_rsa_keypair()

        assert isinstance(private_key, RSAPrivateKey)
        assert isinstance(public_key, RSAPublicKey)
        assert private_key.key_size == 4096
        assert public_key.key_size == 4096

    def test_generate_rsa_keypair_2048(self) -> None:
        """Test generating RSA keypair with 2048 bits."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)

        assert private_key.key_size == 2048
        assert public_key.key_size == 2048

    def test_public_key_derived_from_private(self) -> None:
        """Test that public key can be derived from private key."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        derived_public_key = private_key.public_key()

        # Both should work the same
        message = b"test"
        ciphertext1 = encrypt_rsa(message, public_key)
        ciphertext2 = encrypt_rsa(message, derived_public_key)

        decrypted1 = decrypt_rsa(ciphertext1, private_key)
        decrypted2 = decrypt_rsa(ciphertext2, private_key)

        assert decrypted1 == message
        assert decrypted2 == message

    def test_generate_rsa_keypair_invalid_size(self) -> None:
        """Test that key size < 2048 raises ValueError."""
        with pytest.raises(ValueError, match="at least 2048 bits"):
            generate_rsa_keypair(key_size=1024)


class TestSerializeDeserializeKeys:
    """Tests for key serialization and deserialization."""

    def test_serialize_private_key_unencrypted(self) -> None:
        """Test serializing private key without encryption."""
        private_key, _ = generate_rsa_keypair(key_size=2048)
        pem = serialize_private_key_pem(private_key)

        assert b"-----BEGIN PRIVATE KEY-----" in pem

    def test_serialize_deserialize_private_key_round_trip(self) -> None:
        """Test PEM round-trip for private key."""
        original_private_key, _ = generate_rsa_keypair(key_size=2048)
        pem = serialize_private_key_pem(original_private_key)
        loaded_private_key = deserialize_private_key_pem(pem)

        # Verify the loaded key works
        plaintext = b"test"
        public_key = loaded_private_key.public_key()
        ciphertext = encrypt_rsa(plaintext, public_key)
        decrypted = decrypt_rsa(ciphertext, loaded_private_key)

        assert decrypted == plaintext

    def test_serialize_deserialize_public_key_round_trip(self) -> None:
        """Test PEM round-trip for public key."""
        _, original_public_key = generate_rsa_keypair(key_size=2048)
        pem = serialize_public_key_pem(original_public_key)
        loaded_public_key = deserialize_public_key_pem(pem)

        assert original_public_key.public_numbers() == loaded_public_key.public_numbers()

    def test_private_key_with_password(self) -> None:
        """Test serializing and deserializing password-protected private key."""
        private_key, _ = generate_rsa_keypair(key_size=2048)
        password = b"test_password_123"

        pem = serialize_private_key_pem(private_key, password=password)
        loaded_key = deserialize_private_key_pem(pem, password=password)

        # Verify loaded key works
        plaintext = b"test"
        public_key = loaded_key.public_key()
        ciphertext = encrypt_rsa(plaintext, public_key)
        decrypted = decrypt_rsa(ciphertext, loaded_key)

        assert decrypted == plaintext


class TestEncryptDecryptRoundTrip:
    """Tests for RSA encryption/decryption round-trips."""

    def test_round_trip_short_message(self) -> None:
        """Test round-trip encryption/decryption with short message."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b"Hello, RSA encryption!"

        ciphertext = encrypt_rsa(plaintext, public_key)
        decrypted = decrypt_rsa(ciphertext, private_key)

        assert decrypted == plaintext

    def test_round_trip_empty_message(self) -> None:
        """Test round-trip with empty message."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b""

        ciphertext = encrypt_rsa(plaintext, public_key)
        decrypted = decrypt_rsa(ciphertext, private_key)

        assert decrypted == plaintext

    def test_round_trip_maximum_size_message(self) -> None:
        """Test round-trip with maximum size message for RSA-2048."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b"x" * 190

        ciphertext = encrypt_rsa(plaintext, public_key)
        decrypted = decrypt_rsa(ciphertext, private_key)

        assert decrypted == plaintext

    def test_multiple_encryptions_different_ciphertexts(self) -> None:
        """Test that OAEP produces different ciphertexts for same plaintext."""
        _, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b"test message"

        ciphertext1 = encrypt_rsa(plaintext, public_key)
        ciphertext2 = encrypt_rsa(plaintext, public_key)

        assert ciphertext1 != ciphertext2


class TestEncryptRsaErrors:
    """Tests for RSA encryption error handling."""

    def test_encrypt_plaintext_too_large(self) -> None:
        """Test that plaintext exceeding max size raises ValueError."""
        _, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b"x" * 1000

        with pytest.raises(ValueError, match="Plaintext too large"):
            encrypt_rsa(plaintext, public_key)

    def test_encrypt_non_bytes_plaintext(self) -> None:
        """Test that non-bytes plaintext raises TypeError."""
        _, public_key = generate_rsa_keypair(key_size=2048)

        with pytest.raises(TypeError, match="Plaintext must be bytes"):
            encrypt_rsa("string", public_key)


class TestDecryptRsaErrors:
    """Tests for RSA decryption error handling."""

    def test_decrypt_wrong_private_key(self) -> None:
        """Test that decrypting with wrong private key raises ValueError."""
        _, public_key1 = generate_rsa_keypair(key_size=2048)
        private_key2, _ = generate_rsa_keypair(key_size=2048)

        plaintext = b"secret message"
        ciphertext = encrypt_rsa(plaintext, public_key1)

        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_rsa(ciphertext, private_key2)

    def test_decrypt_corrupted_ciphertext(self) -> None:
        """Test that corrupted ciphertext raises ValueError."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        plaintext = b"test"

        ciphertext = encrypt_rsa(plaintext, public_key)
        corrupted = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_rsa(corrupted, private_key)

    def test_decrypt_non_bytes_ciphertext(self) -> None:
        """Test that non-bytes ciphertext raises TypeError."""
        private_key, _ = generate_rsa_keypair(key_size=2048)

        with pytest.raises(TypeError, match="Ciphertext must be bytes"):
            decrypt_rsa("not bytes", private_key)
