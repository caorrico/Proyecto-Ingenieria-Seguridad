import pytest
from datetime import datetime, timedelta, timezone

from app.services.audit_service import log_event, get_audit_logs, clear_audit_logs


class TestAuditService:
    """Tests for audit logging service."""

    @pytest.fixture(autouse=True)
    def cleanup(self) -> None:
        """Clear audit logs before and after each test."""
        clear_audit_logs()
        yield
        clear_audit_logs()

    def test_log_event_basic(self) -> None:
        """Test logging a basic event."""
        log_event(tipo_evento="HASH", resultado="ÉXITO", detalle="hash calculated")

        logs = get_audit_logs()
        assert len(logs) == 1
        assert logs[0]["tipo_evento"] == "HASH"
        assert logs[0]["resultado"] == "ÉXITO"

    def test_log_event_with_user_id(self) -> None:
        """Test logging an event with user ID."""
        log_event(tipo_evento="SIGN", usuario_id=42, resultado="ÉXITO", detalle="document signed")

        logs = get_audit_logs(usuario_id=42)
        assert len(logs) == 1
        assert logs[0]["usuario_id"] == 42

    def test_log_event_validation_failed(self) -> None:
        """Test logging a validation failure (expected outcome, not error)."""
        log_event(tipo_evento="VERIFY_FAILED", resultado="FALLO", detalle="signature mismatch")

        logs = get_audit_logs(tipo_evento="VERIFY_FAILED")
        assert len(logs) == 1
        assert logs[0]["resultado"] == "FALLO"

    def test_log_event_error(self) -> None:
        """Test logging an unexpected error."""
        log_event(tipo_evento="ERROR", resultado="FALLO", detalle="ValueError in decrypt: invalid padding")

        logs = get_audit_logs(tipo_evento="ERROR")
        assert len(logs) == 1

    def test_filter_by_tipo_evento(self) -> None:
        """Test filtering logs by event type."""
        log_event(tipo_evento="HASH", resultado="ÉXITO")
        log_event(tipo_evento="AES_ENCRYPT", resultado="ÉXITO")
        log_event(tipo_evento="HASH", resultado="ÉXITO")

        hash_logs = get_audit_logs(tipo_evento="HASH")
        assert len(hash_logs) == 2
        assert all(log["tipo_evento"] == "HASH" for log in hash_logs)

    def test_filter_by_date_range(self) -> None:
        """Test filtering logs by date range."""
        now = datetime.now(timezone.utc)
        past = now - timedelta(days=10)
        future = now + timedelta(days=10)

        log_event(tipo_evento="HASH", resultado="ÉXITO")

        logs_in_range = get_audit_logs(fecha_inicio=past, fecha_fin=future)
        assert len(logs_in_range) == 1

        logs_before = get_audit_logs(fecha_fin=past)
        assert len(logs_before) == 0

    def test_log_limit(self) -> None:
        """Test that limit parameter works."""
        for i in range(5):
            log_event(tipo_evento="HASH", resultado="ÉXITO", detalle=f"hash {i}")

        logs = get_audit_logs(limit=3)
        assert len(logs) == 3

    def test_log_no_sensitive_data_warning(self) -> None:
        """Document that detalle should not contain sensitive data."""
        # This is a documentation test — no automatic check, but it shows expectations.
        # If a developer tries to log a key or password, code review should catch it.
        log_event(tipo_evento="AES_ENCRYPT", detalle="data encrypted (32 bytes)")

        logs = get_audit_logs()
        assert "key" not in logs[0]["detalle"].lower()
        assert "password" not in logs[0]["detalle"].lower()
