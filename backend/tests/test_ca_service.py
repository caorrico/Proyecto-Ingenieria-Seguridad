import pytest
from datetime import datetime, timedelta, timezone

from app.services.ca_service import CertificateAuthority
from app.services.rsa_service import generate_rsa_keypair


class TestCAInitialization:
    """Tests for CA initialization and root certificate."""

    def test_ca_initialization(self) -> None:
        """Test that CA is initialized with a valid self-signed root certificate."""
        ca = CertificateAuthority()

        assert ca.ca_certificate is not None
        assert ca.ca_private_key is not None
        assert ca.ca_public_key is not None

    def test_ca_root_certificate_is_self_signed(self) -> None:
        """Test that CA root certificate is self-signed."""
        ca = CertificateAuthority()

        assert ca.ca_certificate.subject == ca.ca_certificate.issuer

    def test_ca_root_certificate_is_valid(self) -> None:
        """Test that CA root certificate is currently valid."""
        ca = CertificateAuthority()

        from app.services.certificate_service import is_certificate_valid
        assert is_certificate_valid(ca.ca_certificate) is True


class TestIssueCertificate:
    """Tests for certificate issuance."""

    def test_issue_certificate(self) -> None:
        """Test issuing a certificate."""
        ca = CertificateAuthority()
        user_private, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="user.example.com",
            subject_org="User Corp",
        )

        assert cert is not None
        from app.services.certificate_service import get_certificate_subject_cn
        assert get_certificate_subject_cn(cert) == "user.example.com"

    def test_issued_certificate_has_correct_issuer(self) -> None:
        """Test that issued certificate has CA as issuer."""
        ca = CertificateAuthority()
        user_private, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        from app.services.certificate_service import get_certificate_issuer_cn, get_certificate_subject_cn
        ca_cn = get_certificate_subject_cn(ca.ca_certificate)
        cert_issuer_cn = get_certificate_issuer_cn(cert)
        assert cert_issuer_cn == ca_cn

    def test_issue_multiple_certificates(self) -> None:
        """Test issuing multiple certificates."""
        ca = CertificateAuthority()

        certs = []
        for i in range(3):
            _, public = generate_rsa_keypair(key_size=2048)
            cert = ca.issue_certificate(
                subject_public_key=public,
                subject_cn=f"user{i}.com",
            )
            certs.append(cert)

        assert len(certs) == 3
        for cert in certs:
            assert cert is not None


class TestValidateChain:
    """Tests for chain validation."""

    def test_validate_chain_issued_by_ca(self) -> None:
        """Test validating a certificate issued by the CA."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        assert ca.validate_chain(cert) is True

    def test_validate_chain_not_issued_by_ca(self) -> None:
        """Test validating a certificate NOT issued by this CA."""
        ca1 = CertificateAuthority(ca_cn="CA1")
        ca2 = CertificateAuthority(ca_cn="CA2")

        _, user_public = generate_rsa_keypair(key_size=2048)
        cert = ca1.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        assert ca2.validate_chain(cert) is False

    def test_validate_chain_self_signed_by_user(self) -> None:
        """Test validating a self-signed user certificate (not by CA)."""
        ca = CertificateAuthority()
        user_private, user_public = generate_rsa_keypair(key_size=2048)

        from app.services.certificate_service import create_certificate
        user_cert = create_certificate(
            subject_public_key=user_public,
            subject_cn="self.signed.com",
            issuer_private_key=user_private,
        )

        assert ca.validate_chain(user_cert) is False


class TestRevocation:
    """Tests for certificate revocation."""

    def test_revoke_certificate(self) -> None:
        """Test revoking a certificate."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        assert ca.is_revoked(cert) is False
        ca.revoke_certificate(cert)
        assert ca.is_revoked(cert) is True

    def test_revoked_certificate_in_list(self) -> None:
        """Test that revoked certificate serial is in revocation list."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
            serial_number=999,
        )

        ca.revoke_certificate(cert)
        assert 999 in ca.get_revoked_serials()

    def test_revoke_multiple_certificates(self) -> None:
        """Test revoking multiple certificates."""
        ca = CertificateAuthority()

        certs = []
        for i in range(3):
            _, public = generate_rsa_keypair(key_size=2048)
            cert = ca.issue_certificate(
                subject_public_key=public,
                subject_cn=f"user{i}.com",
                serial_number=100 + i,
            )
            certs.append(cert)

        for cert in certs:
            ca.revoke_certificate(cert)

        for cert in certs:
            assert ca.is_revoked(cert) is True


class TestValidateCertificate:
    """Tests for complete certificate validation."""

    def test_validate_valid_certificate(self) -> None:
        """Test validating a valid certificate."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        is_valid, reason = ca.validate_certificate(cert)
        assert is_valid is True
        assert reason == "VALID"

    def test_validate_expired_certificate(self) -> None:
        """Test validating an expired certificate."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        now = datetime.now(timezone.utc)
        from app.services.certificate_service import create_certificate
        cert = create_certificate(
            subject_public_key=user_public,
            subject_cn="expired.com",
            issuer_private_key=ca.ca_private_key,
            issuer_cn="Secure Platform CA",
            not_valid_before=now - timedelta(days=10),
            not_valid_after=now - timedelta(days=1),
        )

        is_valid, reason = ca.validate_certificate(cert)
        assert is_valid is False
        assert reason == "EXPIRED"

    def test_validate_not_issued_by_ca(self) -> None:
        """Test validating a certificate not issued by this CA."""
        ca = CertificateAuthority()
        other_ca = CertificateAuthority(ca_cn="Other CA")

        _, user_public = generate_rsa_keypair(key_size=2048)
        cert = other_ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        is_valid, reason = ca.validate_certificate(cert)
        assert is_valid is False
        assert reason == "NOT_ISSUED_BY_CA"

    def test_validate_revoked_certificate(self) -> None:
        """Test validating a revoked certificate."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        ca.revoke_certificate(cert)

        is_valid, reason = ca.validate_certificate(cert)
        assert is_valid is False
        assert reason == "REVOKED"

    def test_validate_certificate_simple(self) -> None:
        """Test simple boolean certificate validation."""
        ca = CertificateAuthority()
        _, user_public = generate_rsa_keypair(key_size=2048)

        cert = ca.issue_certificate(
            subject_public_key=user_public,
            subject_cn="test.com",
        )

        assert ca.validate_certificate_simple(cert) is True

        ca.revoke_certificate(cert)
        assert ca.validate_certificate_simple(cert) is False
