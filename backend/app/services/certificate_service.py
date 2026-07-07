import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID

# Type aliases for readability
PrivateKey = RSAPrivateKey
PublicKey = RSAPublicKey


def create_certificate(
    subject_public_key: PublicKey,
    subject_cn: str,
    subject_org: str = "Organization",
    subject_country: str = "US",
    issuer_private_key: PrivateKey = None,
    issuer_cn: str = None,
    issuer_org: str = None,
    issuer_country: str = None,
    not_valid_before: datetime = None,
    not_valid_after: datetime = None,
    serial_number: int = None,
) -> x509.Certificate:
    """
    Create and sign an X.509 v3 certificate.

    Args:
        subject_public_key: Public key of the certificate holder (to be embedded).
        subject_cn: Common Name (CN) of the certificate subject (e.g., "example.com").
        subject_org: Organization (O) of the subject. Default: "Organization".
        subject_country: Country (C) of the subject. Default: "US".
        issuer_private_key: Private key of the issuer (signer). If None, certificate is self-signed.
        issuer_cn: Common Name of the issuer. If None, uses subject_cn (self-signed).
        issuer_org: Organization of the issuer. Default: "Organization".
        issuer_country: Country of the issuer. Default: "US".
        not_valid_before: Certificate validity start (UTC). Default: now.
        not_valid_after: Certificate validity end (UTC). Default: now + 365 days.
        serial_number: Unique serial number (1-2^159-1). Default: random UUID-based.

    Returns:
        Signed X.509 Certificate object.

    Raises:
        TypeError: If keys or dates are invalid.
        ValueError: If certificate parameters are invalid.

    Note:
        Uses timezone-aware UTC datetimes to avoid comparison bugs.
        If issuer_private_key is None, creates self-signed certificate.
    """
    if not isinstance(subject_public_key, PublicKey):
        raise TypeError("subject_public_key must be an RSA PublicKey")

    # Default dates (UTC timezone-aware)
    now_utc = datetime.now(timezone.utc)
    if not_valid_before is None:
        not_valid_before = now_utc
    if not_valid_after is None:
        not_valid_after = now_utc + timedelta(days=365)

    # Ensure dates are timezone-aware (UTC)
    if not_valid_before.tzinfo is None:
        not_valid_before = not_valid_before.replace(tzinfo=timezone.utc)
    if not_valid_after.tzinfo is None:
        not_valid_after = not_valid_after.replace(tzinfo=timezone.utc)

    if not_valid_after <= not_valid_before:
        raise ValueError("not_valid_after must be after not_valid_before")

    # Default serial number (based on UUID for uniqueness)
    if serial_number is None:
        serial_number = int(uuid.uuid4().int) % (2**159 - 1)
    if serial_number <= 0 or serial_number >= 2**159:
        raise ValueError("Serial number must be between 1 and 2^159-1")

    # Build subject name (ensure all values are strings)
    subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, str(subject_country)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(subject_org)),
            x509.NameAttribute(NameOID.COMMON_NAME, str(subject_cn)),
        ]
    )

    # Validate issuer private key
    if issuer_private_key is None:
        raise ValueError("issuer_private_key must be provided (cannot be None)")

    if not isinstance(issuer_private_key, PrivateKey):
        raise TypeError("issuer_private_key must be an RSA PrivateKey")

    # Default issuer data (self-signed if not provided)
    if issuer_cn is None:
        issuer_cn = subject_cn
    if issuer_org is None:
        issuer_org = subject_org
    if issuer_country is None:
        issuer_country = subject_country

    # Build issuer name
    issuer_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, str(issuer_country)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(issuer_org)),
            x509.NameAttribute(NameOID.COMMON_NAME, str(issuer_cn)),
        ]
    )

    # Build certificate
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject_name)
    builder = builder.issuer_name(issuer_name)
    builder = builder.public_key(subject_public_key)
    builder = builder.serial_number(serial_number)
    builder = builder.not_valid_before(not_valid_before)
    builder = builder.not_valid_after(not_valid_after)

    # Add basic extensions
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Sign the certificate (issuer_private_key is already validated above)
    certificate = builder.sign(
        private_key=issuer_private_key,
        algorithm=hashes.SHA256(),
    )

    return certificate


def serialize_certificate_pem(certificate: x509.Certificate) -> bytes:
    """
    Serialize a certificate to PEM format (bytes).

    Args:
        certificate: X.509 Certificate object.

    Returns:
        PEM-formatted bytes representing the certificate.

    Raises:
        TypeError: If certificate is not an X.509 Certificate object.
    """
    if not isinstance(certificate, x509.Certificate):
        raise TypeError("certificate must be an X.509 Certificate object")

    pem = certificate.public_bytes(serialization.Encoding.PEM)
    return pem


def deserialize_certificate_pem(pem_data: bytes) -> x509.Certificate:
    """
    Deserialize a certificate from PEM format (bytes).

    Args:
        pem_data: PEM-formatted bytes representing the certificate.

    Returns:
        Deserialized X.509 Certificate object.

    Raises:
        TypeError: If pem_data is not bytes.
        ValueError: If PEM data is invalid or malformed.
    """
    if not isinstance(pem_data, bytes):
        raise TypeError("pem_data must be bytes")

    try:
        certificate = x509.load_pem_x509_certificate(pem_data)
    except Exception as e:
        raise ValueError(f"Failed to deserialize certificate: {e}")

    return certificate


def is_certificate_valid(certificate: x509.Certificate) -> bool:
    """
    Check if a certificate is within its validity period (not expired).

    Args:
        certificate: X.509 Certificate object to check.

    Returns:
        True if current time is within [not_valid_before, not_valid_after), False otherwise.

    Raises:
        TypeError: If certificate is not an X.509 Certificate object.

    Note:
        Uses UTC timezone-aware datetime for comparison to avoid bugs.
    """
    if not isinstance(certificate, x509.Certificate):
        raise TypeError("certificate must be an X.509 Certificate object")

    now_utc = datetime.now(timezone.utc)
    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc

    # Ensure all datetimes are timezone-aware for safe comparison
    if not_valid_before.tzinfo is None:
        not_valid_before = not_valid_before.replace(tzinfo=timezone.utc)
    if not_valid_after.tzinfo is None:
        not_valid_after = not_valid_after.replace(tzinfo=timezone.utc)

    is_valid = not_valid_before <= now_utc <= not_valid_after
    return is_valid


def get_certificate_info(certificate: x509.Certificate) -> dict:
    """
    Extract key information from a certificate.

    Args:
        certificate: X.509 Certificate object.

    Returns:
        Dictionary with keys: subject_cn, issuer_cn, not_valid_before, not_valid_after,
        serial_number, public_key (as PublicKey object), is_valid.

    Raises:
        TypeError: If certificate is not an X.509 Certificate object.
    """
    if not isinstance(certificate, x509.Certificate):
        raise TypeError("certificate must be an X.509 Certificate object")

    # Extract subject CN
    try:
        subject_cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        subject_cn = None

    # Extract issuer CN
    try:
        issuer_cn = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        issuer_cn = None

    info = {
        "subject_cn": subject_cn,
        "issuer_cn": issuer_cn,
        "not_valid_before": certificate.not_valid_before_utc,
        "not_valid_after": certificate.not_valid_after_utc,
        "serial_number": certificate.serial_number,
        "public_key": certificate.public_key(),
        "is_valid": is_certificate_valid(certificate),
    }

    return info


def get_certificate_subject_cn(certificate: x509.Certificate) -> str:
    """
    Extract the Common Name (CN) from the certificate subject.

    Args:
        certificate: X.509 Certificate object.

    Returns:
        Common Name string, or None if not found.

    Raises:
        TypeError: If certificate is not an X.509 Certificate object.
    """
    if not isinstance(certificate, x509.Certificate):
        raise TypeError("certificate must be an X.509 Certificate object")

    try:
        cn_attrs = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except (IndexError, AttributeError, ValueError):
        return None

    return None


def get_certificate_issuer_cn(certificate: x509.Certificate) -> str:
    """
    Extract the Common Name (CN) from the certificate issuer.

    Args:
        certificate: X.509 Certificate object.

    Returns:
        Common Name string, or None if not found.

    Raises:
        TypeError: If certificate is not an X.509 Certificate object.
    """
    if not isinstance(certificate, x509.Certificate):
        raise TypeError("certificate must be an X.509 Certificate object")

    try:
        cn_attrs = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except (IndexError, AttributeError, ValueError):
        return None

    return None
