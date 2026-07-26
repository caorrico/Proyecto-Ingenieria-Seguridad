from datetime import datetime, timedelta, timezone
from typing import List, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID

from app.services.certificate_service import (
    create_certificate,
    get_certificate_info,
    get_certificate_issuer_cn,
    get_certificate_subject_cn,
    is_certificate_valid,
)
from app.services.rsa_service import generate_rsa_keypair, serialize_private_key_pem, serialize_public_key_pem

# Type aliases
PrivateKey = RSAPrivateKey
PublicKey = RSAPublicKey


class CertificateAuthority:
    """
    Simulated Certificate Authority (CA) for issuing and validating certificates.

    This CA maintains:
    - Its own keypair and self-signed certificate
    - A list of revoked certificate serial numbers
    """

    def __init__(
        self,
        ca_cn: str = "Secure Platform CA",
        ca_org: str = "Secure Platform",
        ca_country: str = "US",
        ca_key_size: int = 4096,
    ):
        """
        Initialize the CA by generating its root certificate.

        Args:
            ca_cn: Common Name for the CA. Default: "Secure Platform CA".
            ca_org: Organization for the CA. Default: "Secure Platform".
            ca_country: Country code for the CA. Default: "US".
            ca_key_size: RSA key size for the CA. Default: 4096.
        """
        # Generate CA keypair
        self.ca_private_key, self.ca_public_key = generate_rsa_keypair(key_size=ca_key_size)

        # Create self-signed CA certificate
        self.ca_certificate = create_certificate(
            subject_public_key=self.ca_public_key,
            subject_cn=ca_cn,
            subject_org=ca_org,
            subject_country=ca_country,
            issuer_private_key=self.ca_private_key,
            issuer_cn=ca_cn,
            issuer_org=ca_org,
            issuer_country=ca_country,
            not_valid_before=datetime.now(timezone.utc),
            not_valid_after=datetime.now(timezone.utc) + timedelta(days=3650),  # 10 years
            serial_number=1,  # CA root certificate serial is 1
        )

        # List of revoked certificate serial numbers
        self._revoked_serials: List[int] = []

    def issue_certificate(
        self,
        subject_public_key: PublicKey,
        subject_cn: str,
        subject_org: str = "Organization",
        subject_country: str = "US",
        validity_days: int = 365,
        serial_number: int = None,
    ) -> x509.Certificate:
        """
        Issue a certificate signed by this CA.

        Args:
            subject_public_key: Public key of the certificate subject.
            subject_cn: Common Name of the subject.
            subject_org: Organization of the subject. Default: "Organization".
            subject_country: Country code of the subject. Default: "US".
            validity_days: Number of days the certificate is valid. Default: 365.
            serial_number: Unique serial number. Default: auto-generated.

        Returns:
            Signed X.509 Certificate.

        Raises:
            TypeError: If parameters are invalid.
            ValueError: If parameters are invalid.
        """
        if not isinstance(subject_public_key, PublicKey):
            raise TypeError("subject_public_key must be an RSA PublicKey")

        now = datetime.now(timezone.utc)

        certificate = create_certificate(
            subject_public_key=subject_public_key,
            subject_cn=subject_cn,
            subject_org=subject_org,
            subject_country=subject_country,
            issuer_private_key=self.ca_private_key,
            issuer_cn=get_certificate_subject_cn(self.ca_certificate),
            issuer_org="Secure Platform",
            issuer_country="US",
            not_valid_before=now,
            not_valid_after=now + timedelta(days=validity_days),
            serial_number=serial_number,
        )

        return certificate

    def validate_chain(self, certificate: x509.Certificate) -> bool:
        """
        Validate that a certificate was issued by this CA.

        Checks if the certificate issuer matches the CA issuer (name-based validation).
        In a real implementation, cryptographic signature verification would be performed.

        Args:
            certificate: X.509 Certificate to validate.

        Returns:
            True if certificate issuer matches this CA's subject, False otherwise.

        Raises:
            TypeError: If certificate is not an X.509 Certificate.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be an X.509 Certificate")

        # Check issuer identity and verify the certificate signature.
        ca_cn = get_certificate_subject_cn(self.ca_certificate)
        cert_issuer_cn = get_certificate_issuer_cn(certificate)
        if cert_issuer_cn != ca_cn:
            return False
        try:
            self.ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm,
            )
            return True
        except InvalidSignature:
            return False

    def is_revoked(self, certificate: x509.Certificate) -> bool:
        """
        Check if a certificate has been revoked.

        Args:
            certificate: X.509 Certificate to check.

        Returns:
            True if certificate serial is in revocation list, False otherwise.

        Raises:
            TypeError: If certificate is not an X.509 Certificate.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be an X.509 Certificate")

        return certificate.serial_number in self._revoked_serials

    def revoke_certificate(self, certificate: x509.Certificate) -> None:
        """
        Revoke a certificate.

        Args:
            certificate: X.509 Certificate to revoke.

        Raises:
            TypeError: If certificate is not an X.509 Certificate.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be an X.509 Certificate")

        if certificate.serial_number not in self._revoked_serials:
            self._revoked_serials.append(certificate.serial_number)

    def validate_certificate(self, certificate: x509.Certificate) -> Tuple[bool, str]:
        """
        Perform complete validation: vigency + chain + revocation.

        Args:
            certificate: X.509 Certificate to validate.

        Returns:
            Tuple of (is_valid: bool, reason: str).
            Reasons for invalidity: "EXPIRED", "NOT_VALID_YET", "NOT_ISSUED_BY_CA", "REVOKED", "VALID".

        Raises:
            TypeError: If certificate is not an X.509 Certificate.
        """
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be an X.509 Certificate")

        # Check vigency
        if not is_certificate_valid(certificate):
            info = get_certificate_info(certificate)
            now = datetime.now(timezone.utc)
            if now > info["not_valid_after"]:
                return False, "EXPIRED"
            else:
                return False, "NOT_VALID_YET"

        # Check chain (issued by CA)
        if not self.validate_chain(certificate):
            return False, "NOT_ISSUED_BY_CA"

        # Check revocation
        if self.is_revoked(certificate):
            return False, "REVOKED"

        return True, "VALID"

    def validate_certificate_simple(self, certificate: x509.Certificate) -> bool:
        """
        Validate certificate with simple boolean result.

        Args:
            certificate: X.509 Certificate to validate.

        Returns:
            True if all validations pass, False otherwise.

        Raises:
            TypeError: If certificate is not an X.509 Certificate.
        """
        is_valid, _ = self.validate_certificate(certificate)
        return is_valid

    def get_revoked_serials(self) -> List[int]:
        """
        Get list of revoked certificate serial numbers.

        Returns:
            List of revoked serial numbers.
        """
        return self._revoked_serials.copy()

    def get_ca_certificate_info(self) -> dict:
        """
        Get information about the CA's own certificate.

        Returns:
            Dictionary with CA certificate information (subject_cn, issuer_cn, serial_number, etc.).
        """
        return get_certificate_info(self.ca_certificate)
