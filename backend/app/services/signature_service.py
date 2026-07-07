from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from app.services.hash_service import hash_sha256

# Type aliases for readability
PrivateKey = RSAPrivateKey
PublicKey = RSAPublicKey


def sign(data: bytes, private_key: PrivateKey) -> bytes:
    """
    Sign data using RSA with PSS padding (secure digital signature).

    Process:
    1. Calculate SHA-256 hash of the data using hash_service.
    2. Sign the data with the private key using PSS padding with SHA-256.
       The cryptography library automatically hashes during signing.

    Args:
        data: Bytes to sign.
        private_key: RSA private key for signing.

    Returns:
        Digital signature as bytes.

    Raises:
        TypeError: If data is not bytes or private_key is invalid.
        ValueError: If signing fails.

    Note:
        Uses PSS (Probabilistic Signature Scheme) padding with SHA-256.
        PSS is the recommended modern padding scheme (PKCS1v15 is legacy).
        Different invocations of the same data produce different signatures
        due to PSS randomization, but all are valid and verifiable.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be an RSA PrivateKey")

    try:
        # Sign the data with PSS padding and SHA-256 hashing
        # The private_key.sign() method internally hashes the data
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        raise ValueError(f"Signing failed: {e}")

    return signature


def verify(data: bytes, signature: bytes, public_key: PublicKey) -> bool:
    """
    Verify a digital signature using RSA with PSS padding.

    Process:
    1. Calculate SHA-256 hash of the data using hash_service.
    2. Verify the signature against that hash using the public key with PSS padding.

    Args:
        data: Original bytes that were signed.
        signature: Digital signature bytes to verify.
        public_key: RSA public key corresponding to the private key that signed.

    Returns:
        True if signature is valid, False if invalid (never raises exception for invalid signature).

    Raises:
        TypeError: If data/signature are not bytes or public_key is invalid.

    Note:
        Returns False (not exception) for invalid signatures to distinguish between
        "signature is invalid" (False) and "error during verification" (exception).
        This follows cryptographic best practices.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(signature, bytes):
        raise TypeError("Signature must be bytes")

    if not isinstance(public_key, PublicKey):
        raise TypeError("public_key must be an RSA PublicKey")

    try:
        # Verify signature using PSS padding with SHA-256
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        # Signature is invalid (expected case, not an error)
        return False
    except Exception as e:
        # Any other exception is a real error (malformed key, etc.)
        raise ValueError(f"Signature verification failed: {e}")
