from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

# Type aliases for readability
PrivateKey = RSAPrivateKey
PublicKey = RSAPublicKey


def generate_rsa_keypair(key_size: int = 4096) -> Tuple[PrivateKey, PublicKey]:
    """
    Generate an RSA key pair (private and public keys).

    Args:
        key_size: RSA key size in bits. Default 4096 (recommended for security).
                 Minimum 2048 bits acceptable but 4096 recommended.

    Returns:
        Tuple of (private_key, public_key).

    Raises:
        ValueError: If key_size is less than 2048 bits.

    Note:
        Uses 4096 bits by default for strong security. The public exponent is fixed
        to 65537 (F4), the standard secure choice for RSA.
    """
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits for security")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    public_key = private_key.public_key()

    return private_key, public_key


def serialize_private_key_pem(private_key: PrivateKey, password: bytes = None) -> bytes:
    """
    Serialize a private key to PEM format (bytes).

    Args:
        private_key: The private key to serialize.
        password: Optional password to encrypt the private key.
                 If None, key is serialized unencrypted (use with caution).

    Returns:
        PEM-formatted bytes representing the private key.

    Note:
        If password is provided, uses PBKDF2 for key derivation and AES-256
        for encryption. If password is None, key is unprotected in PEM format.
    """
    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be an RSA PrivateKey")

    if password is not None:
        if not isinstance(password, bytes):
            raise TypeError("Password must be bytes or None")
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )

    return pem


def serialize_public_key_pem(public_key: PublicKey) -> bytes:
    """
    Serialize a public key to PEM format (bytes).

    Args:
        public_key: The public key to serialize.

    Returns:
        PEM-formatted bytes representing the public key.
    """
    if not isinstance(public_key, PublicKey):
        raise TypeError("public_key must be an RSA PublicKey")

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return pem


def deserialize_private_key_pem(
    pem_data: bytes, password: bytes = None
) -> PrivateKey:
    """
    Deserialize a private key from PEM format (bytes).

    Args:
        pem_data: PEM-formatted bytes representing the private key.
        password: Password if the private key is encrypted. None if unencrypted.

    Returns:
        Deserialized RSA PrivateKey object.

    Raises:
        ValueError: If PEM data is invalid or password is incorrect.
    """
    if not isinstance(pem_data, bytes):
        raise TypeError("pem_data must be bytes")

    try:
        private_key = serialization.load_pem_private_key(pem_data, password=password)
    except ValueError as e:
        raise ValueError(f"Failed to deserialize private key: {e}")

    if not isinstance(private_key, PrivateKey):
        raise ValueError("Loaded key is not an RSA private key")

    return private_key


def deserialize_public_key_pem(pem_data: bytes) -> PublicKey:
    """
    Deserialize a public key from PEM format (bytes).

    Args:
        pem_data: PEM-formatted bytes representing the public key.

    Returns:
        Deserialized RSA PublicKey object.

    Raises:
        ValueError: If PEM data is invalid.
    """
    if not isinstance(pem_data, bytes):
        raise TypeError("pem_data must be bytes")

    try:
        public_key = serialization.load_pem_public_key(pem_data)
    except ValueError as e:
        raise ValueError(f"Failed to deserialize public key: {e}")

    if not isinstance(public_key, PublicKey):
        raise ValueError("Loaded key is not an RSA public key")

    return public_key


def encrypt_rsa(plaintext: bytes, public_key: PublicKey) -> bytes:
    """
    Encrypt data using RSA with OAEP padding (secure asymmetric encryption).

    Args:
        plaintext: Bytes to encrypt (limited by RSA key size minus padding overhead).
                  For RSA-4096, maximum plaintext size is approximately 446 bytes.
        public_key: RSA public key for encryption.

    Returns:
        Encrypted bytes (ciphertext).

    Raises:
        TypeError: If plaintext is not bytes or public_key is invalid.
        ValueError: If plaintext exceeds maximum size for the key.
        cryptography.hazmat.primitives.asymmetric.utils.InvalidSignature:
            If encryption fails (unlikely with valid inputs).

    Note:
        Uses OAEP padding with SHA-256 hash (secure).
        For large data, combine with AES (hybrid encryption) — not done here.
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")

    if not isinstance(public_key, PublicKey):
        raise TypeError("public_key must be an RSA PublicKey")

    max_plaintext_size = (public_key.key_size // 8) - 66  # Approximate overhead for OAEP-SHA256

    if len(plaintext) > max_plaintext_size:
        raise ValueError(
            f"Plaintext too large ({len(plaintext)} bytes). "
            f"Maximum for this key is {max_plaintext_size} bytes."
        )

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return ciphertext


def decrypt_rsa(ciphertext: bytes, private_key: PrivateKey) -> bytes:
    """
    Decrypt data using RSA with OAEP padding.

    Args:
        ciphertext: Encrypted bytes to decrypt.
        private_key: RSA private key for decryption.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        TypeError: If ciphertext is not bytes or private_key is invalid.
        ValueError: If decryption fails (ciphertext is corrupted or wrong key).
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not isinstance(private_key, PrivateKey):
        raise TypeError("private_key must be an RSA PrivateKey")

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise ValueError(f"Decryption failed (ciphertext corrupted or wrong key): {e}")

    return plaintext
