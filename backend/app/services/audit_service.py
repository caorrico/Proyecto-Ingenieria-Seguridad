from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from app.core.database import engine
from app.models.audit import AuditLog


def get_db_session() -> Session:
    """Get a database session."""
    from sqlalchemy.orm import sessionmaker

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return SessionLocal()


def log_event(
    tipo_evento: str,
    usuario_id: Optional[int] = None,
    resultado: str = "ÉXITO",
    detalle: Optional[str] = None,
) -> None:
    """
    Log a cryptographic event, validation result, or error to the audit database.

    Args:
        tipo_evento: Event type (ej. HASH, AES_ENCRYPT, VERIFY_FAILED, ERROR, etc.).
                     Follows 4 categories:
                     1. Cryptographic operations: HASH, AES_ENCRYPT, AES_DECRYPT, RSA_ENCRYPT, RSA_DECRYPT, SIGN, CERT_ISSUE, CERT_REVOKE
                     2. Failed validations (expected outcomes): VERIFY_FAILED, CERT_VALIDATION_FAILED, CERT_EXPIRED, CERT_REVOKED
                     3. Unexpected errors: ERROR (with exception type in detalle)
                     4. Access events: LOGIN, LOGOUT, ACCESS_DENIED (may be used by other modules)

        usuario_id: Optional user ID if operation is associated with authenticated user.

        resultado: Result status (ÉXITO, FALLO, etc.). Default: ÉXITO.

        detalle: Event details as safe metadata (never raw keys, passwords, plaintexts, or sensitive data).
                 Examples: "hash calculated", "certificate issued for user X, serial 12345",
                          "signature verification failed for document", "unexpected ValueError in decrypt"

    Returns:
        None

    Raises:
        Exception: If database insert fails (logs to stderr, does not re-raise to avoid disrupting operations).
    """
    try:
        db = get_db_session()
        audit_record = AuditLog(
            timestamp=datetime.now(timezone.utc),
            usuario_id=usuario_id,
            tipo_evento=tipo_evento,
            resultado=resultado,
            detalle=detalle,
        )
        db.add(audit_record)
        db.commit()
        db.close()
    except Exception as e:
        # Log to stderr instead of raising to avoid disrupting the main operation
        import sys

        print(f"Failed to log event: {e}", file=sys.stderr)


def get_audit_logs(
    tipo_evento: Optional[str] = None,
    usuario_id: Optional[int] = None,
    fecha_inicio: Optional[datetime] = None,
    fecha_fin: Optional[datetime] = None,
    limit: int = 100,
) -> List[dict]:
    """
    Query audit logs with optional filters.

    Args:
        tipo_evento: Filter by event type (ej. HASH, VERIFY_FAILED, ERROR).

        usuario_id: Filter by user ID.

        fecha_inicio: Filter events from this datetime onwards (UTC).

        fecha_fin: Filter events up to this datetime (UTC).

        limit: Maximum number of records to return. Default: 100.

    Returns:
        List of audit log records as dictionaries.

    Raises:
        Exception: If query fails.
    """
    try:
        db = get_db_session()
        query = db.query(AuditLog)

        if tipo_evento:
            query = query.filter(AuditLog.tipo_evento == tipo_evento)

        if usuario_id:
            query = query.filter(AuditLog.usuario_id == usuario_id)

        if fecha_inicio:
            if fecha_inicio.tzinfo is None:
                fecha_inicio = fecha_inicio.replace(tzinfo=timezone.utc)
            query = query.filter(AuditLog.timestamp >= fecha_inicio)

        if fecha_fin:
            if fecha_fin.tzinfo is None:
                fecha_fin = fecha_fin.replace(tzinfo=timezone.utc)
            query = query.filter(AuditLog.timestamp <= fecha_fin)

        results = query.order_by(AuditLog.timestamp.desc()).limit(limit).all()

        logs = []
        for record in results:
            logs.append(
                {
                    "id": record.id,
                    "timestamp": record.timestamp.isoformat(),
                    "usuario_id": record.usuario_id,
                    "tipo_evento": record.tipo_evento,
                    "resultado": record.resultado,
                    "detalle": record.detalle,
                }
            )

        db.close()
        return logs
    except Exception as e:
        import sys

        print(f"Failed to query audit logs: {e}", file=sys.stderr)
        return []


def clear_audit_logs() -> None:
    """
    Clear all audit logs (useful for testing).

    Returns:
        None
    """
    try:
        db = get_db_session()
        db.query(AuditLog).delete()
        db.commit()
        db.close()
    except Exception as e:
        import sys

        print(f"Failed to clear audit logs: {e}", file=sys.stderr)
