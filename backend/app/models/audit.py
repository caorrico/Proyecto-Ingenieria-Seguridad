from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String

from app.core.database import Base


class AuditLog(Base):
    """
    Audit log model for cryptographic operations, validations, and errors.

    Fields:
    - id: unique identifier
    - timestamp: UTC timezone-aware datetime of the event
    - usuario_id: optional user ID if authenticated
    - tipo_evento: event type (HASH, AES_ENCRYPT, VERIFY_FAILED, ERROR, etc.)
    - resultado: result of the operation (ÉXITO, FALLO, etc.)
    - detalle: event details (no sensitive data like keys, passwords, plaintext)
    """

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    usuario_id = Column(Integer, nullable=True, index=True)
    tipo_evento = Column(String(50), nullable=False, index=True)
    resultado = Column(String(20), nullable=False)
    detalle = Column(String(500), nullable=True)

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, timestamp={self.timestamp}, tipo_evento={self.tipo_evento}, resultado={self.resultado})>"
