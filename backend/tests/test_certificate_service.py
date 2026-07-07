import pytest
from datetime import datetime, timedelta, timezone

from app.services.certificate_service import (
    create_certificate,
    deserialize_certificate_pem,
    get_certificate_info,
    get_certificate_issuer_cn,
    get_certificate_subject_cn,
    is_certificate_valid,
    serialize_certificate_pem,
)
from app.services.rsa_service import generate_rsa_keypair


class TestCreateCertificate:
    def test_create_self_signed_certificate(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="example.com",
            issuer_private_key=private_key,
        )
        assert cert is not None
        assert cert.subject == cert.issuer

    def test_create_certificate_with_custom_dates(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        now = datetime.now(timezone.utc)
        start = now
        end = now + timedelta(days=30)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
            not_valid_before=start,
            not_valid_after=end,
        )
        assert cert.not_valid_before_utc.replace(microsecond=0) == start.replace(microsecond=0)
        assert cert.not_valid_after_utc.replace(microsecond=0) == end.replace(microsecond=0)

    def test_create_certificate_with_custom_serial(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        serial = 12345
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
            serial_number=serial,
        )
        assert cert.serial_number == serial

    def test_create_certificate_invalid_key_type(self) -> None:
        private_key, _ = generate_rsa_keypair(key_size=2048)
        with pytest.raises(TypeError, match="must be an RSA PublicKey"):
            create_certificate(
                subject_public_key="not a key",
                subject_cn="test.com",
                issuer_private_key=private_key,
            )

    def test_create_certificate_invalid_date_range(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        now = datetime.now(timezone.utc)
        start = now + timedelta(days=10)
        end = now
        with pytest.raises(ValueError, match="not_valid_after must be after"):
            create_certificate(
                subject_public_key=public_key,
                subject_cn="test.com",
                issuer_private_key=private_key,
                not_valid_before=start,
                not_valid_after=end,
            )


class TestSerializeDeserializeCertificate:
    def test_serialize_certificate_to_pem(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
        )
        pem = serialize_certificate_pem(cert)
        assert isinstance(pem, bytes)
        assert b"-----BEGIN CERTIFICATE-----" in pem

    def test_serialize_deserialize_round_trip(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        original_cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="example.com",
            issuer_private_key=private_key,
            serial_number=42,
        )
        pem = serialize_certificate_pem(original_cert)
        loaded_cert = deserialize_certificate_pem(pem)
        assert loaded_cert.serial_number == original_cert.serial_number
        assert get_certificate_subject_cn(loaded_cert) == "example.com"

    def test_deserialize_invalid_pem_raises_error(self) -> None:
        invalid_pem = b"not a certificate"
        with pytest.raises(ValueError, match="Failed to deserialize"):
            deserialize_certificate_pem(invalid_pem)


class TestCertificateValidity:
    def test_valid_certificate_is_valid(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        now = datetime.now(timezone.utc)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
            not_valid_before=now - timedelta(days=1),
            not_valid_after=now + timedelta(days=1),
        )
        assert is_certificate_valid(cert) is True

    def test_expired_certificate_is_invalid(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        now = datetime.now(timezone.utc)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
            not_valid_before=now - timedelta(days=10),
            not_valid_after=now - timedelta(days=1),
        )
        assert is_certificate_valid(cert) is False

    def test_not_yet_valid_certificate_is_invalid(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        now = datetime.now(timezone.utc)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
            not_valid_before=now + timedelta(days=1),
            not_valid_after=now + timedelta(days=10),
        )
        assert is_certificate_valid(cert) is False


class TestCertificatePublicKey:
    def test_certificate_contains_correct_public_key(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.com",
            issuer_private_key=private_key,
        )
        embedded_key = cert.public_key()
        assert embedded_key.public_numbers() == public_key.public_numbers()


class TestCertificateInfo:
    def test_get_certificate_info(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="example.com",
            issuer_private_key=private_key,
        )
        info = get_certificate_info(cert)
        assert info["subject_cn"] == "example.com"
        assert info["issuer_cn"] == "example.com"
        assert "serial_number" in info
        assert "public_key" in info

    def test_get_certificate_subject_cn(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="test.example.com",
            issuer_private_key=private_key,
        )
        cn = get_certificate_subject_cn(cert)
        assert cn == "test.example.com"

    def test_get_certificate_issuer_cn(self) -> None:
        private_key, public_key = generate_rsa_keypair(key_size=2048)
        cert = create_certificate(
            subject_public_key=public_key,
            subject_cn="subject.com",
            issuer_private_key=private_key,
            issuer_cn="issuer.com",
        )
        issuer_cn = get_certificate_issuer_cn(cert)
        assert issuer_cn == "issuer.com"

