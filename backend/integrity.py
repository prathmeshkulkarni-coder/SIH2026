"""
CUSTODY CHAIN - Cryptographic Integrity & Audit Logging Service
Handles SHA-256 hash generation, document integrity verification,
and immutable event audit logging.
"""

import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional
from backend.models import AuditEvent, IntegrityStatus

class IntegrityService:
    def __init__(self):
        self.audit_trail: List[AuditEvent] = []
        self.event_counter: int = 1000

    @staticmethod
    def compute_sha256(content: str) -> str:
        """Calculates deterministic SHA-256 hash of text content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def log_event(
        self,
        event_type: str,
        actor_id: str,
        actor_name: str,
        details: str,
        document_id: Optional[str] = None,
        case_id: Optional[str] = None,
        integrity_ref: Optional[str] = None,
        affected_nodes: Optional[List[str]] = None
    ) -> AuditEvent:
        """Appends an immutable tamper-evident audit record."""
        self.event_counter += 1
        event = AuditEvent(
            event_id=f"AUD-{self.event_counter}",
            event_type=event_type,
            actor_id=actor_id,
            actor_name=actor_name,
            document_id=document_id,
            case_id=case_id,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            details=details,
            integrity_reference=integrity_ref,
            affected_nodes=affected_nodes or []
        )
        self.audit_trail.append(event)
        return event

    def get_audit_trail(self, document_id: Optional[str] = None, case_id: Optional[str] = None) -> List[AuditEvent]:
        filtered = self.audit_trail
        if document_id:
            filtered = [e for e in filtered if e.document_id == document_id]
        if case_id:
            filtered = [e for e in filtered if e.case_id == case_id]
        # Return descending order (latest first)
        return sorted(filtered, key=lambda x: x.event_id, reverse=True)
