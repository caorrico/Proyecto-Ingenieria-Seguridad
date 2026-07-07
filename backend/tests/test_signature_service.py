import pytest

from app.services.hash_service import hash_sha256
from app.services.rsa_service import generate_rsa_keypair
from app.services.signature_service import sign, verify


class TestSignature:
    """Tests for digital signature generation and verification."""

    def test_sign_and_verify_valid_signature(self) -> None:
        """Test that a valid signature verifies successfully."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        data = b"Document to sign"

        signature = sign(data, private_key)
        is_valid = verify(data, signature, public_key)

        assert is_valid is True

    def test_verify_invalid_signature_returns_false(self) -> None:
        """Test that an invalid signature returns False."""
        _, public_key = generate_rsa_keypair(key_size=2048)
        data = b"Document to sign"
        invalid_signature = b"not a real signature"

        is_valid = verify(data, invalid_signature, public_key)

        assert is_valid is False

    def test_signature_fails_with_modified_document(self) -> None:
        """Test that modifying the document makes signature invalid."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        original_data = b"Original document"
        modified_data = b"Modified document"

        signature = sign(original_data, private_key)
        is_valid = verify(modified_data, signature, public_key)

        assert is_valid is False

    def test_signature_fails_with_single_byte_modification(self) -> None:
        """Test that changing one byte makes signature invalid."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        original_data = b"Hello world"
        modified_data = b"Hello wprld"

        signature = sign(original_data, private_key)
        is_valid = verify(modified_data, signature, public_key)

        assert is_valid is False

    def test_signature_fails_with_modified_signature(self) -> None:
        """Test that modifying the signature makes it invalid."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        data = b"Document"

        signature = sign(data, private_key)
        modified_signature = bytes([signature[0] ^ 0xFF]) + signature[1:]
        is_valid = verify(data, modified_signature, public_key)

        assert is_valid is False

    def test_signature_fails_with_wrong_public_key(self) -> None:
        """Test that verifying with wrong public key fails."""
        private_key1, _ = generate_rsa_keypair(key_size=2048)
        _, public_key2 = generate_rsa_keypair(key_size=2048)
        data = b"Secret message"

        signature = sign(data, private_key1)
        is_valid = verify(data, signature, public_key2)

        assert is_valid is False

    def test_signature_with_empty_data(self) -> None:
        """Test signing and verifying empty data."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        data = b""

        signature = sign(data, private_key)
        is_valid = verify(data, signature, public_key)

        assert is_valid is True

    def test_signature_with_large_data(self) -> None:
        """Test signing and verifying large data (1 MB)."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        data = b"x" * (1024 * 1024)

        signature = sign(data, private_key)
        is_valid = verify(data, signature, public_key)

        assert is_valid is True

    def test_multiple_signatures_of_same_data_are_different(self) -> None:
        """Test that PSS produces different signatures."""
        private_key, _ = generate_rsa_keypair(key_size=2048)
        data = b"Same data"

        signature1 = sign(data, private_key)
        signature2 = sign(data, private_key)

        assert signature1 != signature2

    def test_both_signatures_are_valid(self) -> None:
        """Test that both different PSS signatures are valid."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        data = b"Data"

        signature1 = sign(data, private_key)
        signature2 = sign(data, private_key)

        is_valid1 = verify(data, signature1, public_key)
        is_valid2 = verify(data, signature2, public_key)

        assert is_valid1 is True
        assert is_valid2 is True


class TestSignatureErrors:
    """Tests for signature error handling."""

    def test_sign_non_bytes_data_raises_error(self) -> None:
        """Test that non-bytes data raises TypeError."""
        private_key, _ = generate_rsa_keypair(key_size=2048)

        with pytest.raises(TypeError, match="Data must be bytes"):
            sign("string data", private_key)

    def test_sign_invalid_private_key_raises_error(self) -> None:
        """Test that invalid private key raises TypeError."""
        data = b"test"

        with pytest.raises(TypeError, match="must be an RSA PrivateKey"):
            sign(data, "not a key")

    def test_verify_non_bytes_data_raises_error(self) -> None:
        """Test that non-bytes data raises TypeError."""
        _, public_key = generate_rsa_keypair(key_size=2048)

        with pytest.raises(TypeError, match="Data must be bytes"):
            verify("string", b"sig", public_key)

    def test_verify_non_bytes_signature_raises_error(self) -> None:
        """Test that non-bytes signature raises TypeError."""
        _, public_key = generate_rsa_keypair(key_size=2048)

        with pytest.raises(TypeError, match="Signature must be bytes"):
            verify(b"data", "string", public_key)

    def test_verify_invalid_public_key_raises_error(self) -> None:
        """Test that invalid public key raises TypeError."""
        with pytest.raises(TypeError, match="must be an RSA PublicKey"):
            verify(b"data", b"sig", "not a key")


class TestSignatureIntegration:
    """Integration tests combining signature and hash services."""

    def test_signature_on_hash_service_output(self) -> None:
        """Test that signing a file hash works."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        file_content = b"Important document content"

        file_hash = hash_sha256(file_content)
        hash_bytes = bytes.fromhex(file_hash)
        signature = sign(hash_bytes, private_key)
        is_valid = verify(hash_bytes, signature, public_key)

        assert is_valid is True

    def test_multiple_documents_with_same_keypair(self) -> None:
        """Test signing multiple documents with same keypair."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        documents = [b"Doc1", b"Doc2", b"Doc3"]

        signatures = [sign(doc, private_key) for doc in documents]
        verifications = [verify(doc, sig, public_key) for doc, sig in zip(documents, signatures)]

        assert all(verifications)

    def test_cross_signature_verification_fails(self) -> None:
        """Test that signature of doc1 fails for doc2."""
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        doc1 = b"Document 1"
        doc2 = b"Document 2"

        sig1 = sign(doc1, private_key)
        is_valid = verify(doc2, sig1, public_key)

        assert is_valid is False
