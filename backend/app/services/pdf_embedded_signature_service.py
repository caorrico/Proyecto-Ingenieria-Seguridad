from datetime import datetime, timedelta, timezone
from io import BytesIO
from uuid import uuid4

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko_certvalidator.registry import SimpleCertificateStore


def embed_adobe_compatible_signature(
    pdf_data: bytes,
    private_key: RSAPrivateKey,
    signer_name: str,
) -> bytes:
    """Embed a CMS/PAdES signature field that standard PDF readers can detect."""
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureSign"),
            x509.NameAttribute(NameOID.COMMON_NAME, signer_name),
        ]
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
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
        .sign(private_key, hashes.SHA256())
    )
    signing_cert = asn1_x509.Certificate.load(
        certificate.public_bytes(serialization.Encoding.DER)
    )
    signing_key = asn1_keys.PrivateKeyInfo.load(
        private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer = signers.SimpleSigner(
        signing_cert=signing_cert,
        signing_key=signing_key,
        cert_registry=SimpleCertificateStore(),
    )
    field_name = f"SecureSign_{uuid4().hex[:12]}"
    metadata = signers.PdfSignatureMetadata(
        field_name=field_name,
        name=signer_name,
        reason="Firma digital de documento mediante SecureSign",
        location="Ecuador",
        subfilter=SigSeedSubFilter.PADES,
    )
    writer = IncrementalPdfFileWriter(BytesIO(pdf_data))
    output = BytesIO()
    signers.PdfSigner(metadata, signer=signer).sign_pdf(writer, output=output)
    return output.getvalue()
