"""Shared fixtures for the TraceX / NCRB Secure DMS test suite.

Every test gets its own SQLite file database, its own document storage
directory and a clean audit trail, so no test can observe another test's
writes or touch the developer's ncrb_dms.db.
"""

import os
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Importing the application initializes its default database.  Keep that import
# side effect in memory; every test below still receives its own file database.
os.environ["POSTGRES_URL"] = "sqlite://"

from fastapi.testclient import TestClient

from backend import app as app_module
from backend.database import (
    AccessRequestDB,
    AuditLogDB,
    Base,
    BlockchainBlockDB,
    CaseDB,
    DocumentDB,
    IntegrityEventDB,
    PoliceAssetDB,
    ProvenanceEdgeDB,
    UserDB,
    VersionDB,
)

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def now_str() -> str:
    return datetime.now().strftime(TIMESTAMP_FORMAT)


def offset_str(**delta) -> str:
    """Timestamp relative to now, e.g. offset_str(hours=-1) for one hour ago."""
    return (datetime.now() + timedelta(**delta)).strftime(TIMESTAMP_FORMAT)


def sha256(text: str) -> str:
    return app_module.hashlib.sha256(text.encode()).hexdigest()


class Factory:
    """Row builders so each test can describe exactly the data it needs."""

    def __init__(self, db):
        self.db = db

    def _add(self, row):
        self.db.add(row)
        self.db.commit()
        return row

    def case(self, case_id, name="Extra Case", case_type="Criminal", status="OPEN"):
        return self._add(CaseDB(case_id=case_id, case_name=name, case_type=case_type,
                                status=status, created_at=now_str()))

    def user(self, user_id, username=None, password="secret", name=None,
             role="Investigator", department="NCRB", badge="BDG-1"):
        return self._add(UserDB(
            user_id=user_id, username=username or user_id.lower(), hashed_password=password,
            name=name or f"Officer {user_id}", role=role, department=department,
            badge_number=badge,
        ))

    def document(self, doc_id, case_id="CASE-T1", document_type="Investigation Record",
                 title=None, classification="Confidential", content="body text",
                 status="VERIFIED", created_by="OFF-001", version=1, file_path=None,
                 signature_json=None, current_hash=None):
        return self._add(DocumentDB(
            document_id=doc_id, case_id=case_id, document_type=document_type,
            title=title or f"Document {doc_id}", description=title or f"Document {doc_id}",
            classification=classification, content_text=content,
            current_hash=current_hash if current_hash is not None else sha256(content),
            integrity_status=status, created_at=now_str(), created_by=created_by,
            version=version, file_path=file_path, hash_algorithm="SHA-256",
            digital_signature_json=signature_json,
        ))

    def edge(self, edge_id, source, target, case_id="CASE-T1",
             relationship_type="derived_from", description="derived"):
        return self._add(ProvenanceEdgeDB(
            id=edge_id, case_id=case_id, source_doc_id=source, target_doc_id=target,
            relationship_type=relationship_type, description=description, created_at=now_str(),
        ))

    def version(self, version_id, doc_id, version=1, content="body text", created_by="OFF-001"):
        return self._add(VersionDB(
            version_id=version_id, document_id=doc_id, version=version, hash=sha256(content),
            created_by=created_by, created_at=now_str(), status="Current", file_path=None,
        ))

    def access_request(self, request_id, doc_id, requester_id, status="PENDING",
                       token=None, expires_at=None, approver_id=None, approved_at=None,
                       rejection_reason=None):
        return self._add(AccessRequestDB(
            request_id=request_id, document_id=doc_id, requester_id=requester_id,
            requester_name=f"Officer {requester_id}", requester_role="Investigator",
            requested_action="VIEW", purpose_reason="Case review", status=status,
            approver_id=approver_id, session_token=token, requested_at=now_str(),
            approved_at=approved_at, expires_at=expires_at,
            rejection_reason=rejection_reason,
        ))

    def block(self, number, previous_hash, block_hash, doc_id="DOC-001", action="TEST"):
        return self._add(BlockchainBlockDB(
            block_number=number, tx_id=f"TX-{number}", timestamp=now_str(), action=action,
            document_id=doc_id, previous_hash=previous_hash, block_hash=block_hash,
            merkle_root=block_hash[:32],
        ))

    def asset(self, asset_id, case_id="CASE-T1", name="Seized laptop"):
        return self._add(PoliceAssetDB(
            asset_id=asset_id, case_id=case_id, asset_name=name, serial_number="SN-1",
            location="Evidence Vault", status="SEIZED_STORED", custodian_id="LAB-001",
        ))

    def audit_log(self, event_id, doc_id="DOC-001", event_type="VIEWED", timestamp=None):
        return self._add(AuditLogDB(
            event_id=event_id, timestamp=timestamp or now_str(), event_type=event_type,
            actor_id="OFF-001", actor_name="IO Test", document_id=doc_id, case_id="CASE-T1",
            details=f"{event_type} {doc_id}",
        ))

    def integrity_event(self, event_id, doc_id="DOC-001", result="PASS"):
        return self._add(IntegrityEventDB(
            event_id=event_id, document_id=doc_id, expected_hash="a" * 64,
            actual_hash="a" * 64 if result == "PASS" else "b" * 64, result=result,
            detected_at=now_str(),
        ))


@pytest.fixture()
def storage_dir(tmp_path, monkeypatch):
    """Redirect physical document writes into the test's temporary directory."""
    docs_dir = tmp_path / "documents"
    docs_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(app_module, "DOCS_STORAGE_DIR", str(docs_dir))
    return docs_dir


@pytest.fixture()
def audit_service():
    """The module level IntegrityService keeps state in memory, so reset it."""
    app_module.INTEGRITY_SERVICE.audit_trail.clear()
    app_module.INTEGRITY_SERVICE.event_counter = 1000
    yield app_module.INTEGRITY_SERVICE
    app_module.INTEGRITY_SERVICE.audit_trail.clear()


@pytest.fixture()
def db_session(tmp_path, storage_dir, audit_service):
    """Return a fresh SQLite session factory and keep file writes in a temp directory."""
    test_engine = create_engine(
        f"sqlite:///{tmp_path / 'tracex_test.db'}",
        connect_args={"check_same_thread": False},
    )
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    Base.metadata.create_all(test_engine)
    _seed(TestSession())
    yield TestSession
    test_engine.dispose()


@pytest.fixture()
def db(db_session):
    """A ready-to-use session against the seeded per-test database."""
    session = db_session()
    yield session
    session.close()


@pytest.fixture()
def factory(db):
    return Factory(db)


@pytest.fixture()
def client(db_session):
    """TestClient that exercises the real HTTP layer against the seeded database."""
    def override_get_db():
        session = db_session()
        try:
            yield session
        finally:
            session.close()

    app_module.app.dependency_overrides[app_module.get_db] = override_get_db
    with TestClient(app_module.app) as test_client:
        yield test_client
    app_module.app.dependency_overrides.clear()


def _seed(db):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.add(CaseDB(case_id="CASE-T1", case_name="Test Investigation", case_type="Cyber", status="OPEN", created_at=now))
    db.add_all([
        UserDB(user_id="SUP-001", username="supervisor", hashed_password="secret", name="SP Test", role="Supervisor", department="NCRB", badge_number="SUP-1"),
        UserDB(user_id="OFF-001", username="investigator", hashed_password="secret", name="IO Test", role="Investigator", department="NCRB", badge_number="OFF-1"),
    ])
    docs = [
        ("DOC-001", "FIR", "Public source", "Public Record", "source text"),
        ("DOC-002", "Forensic Report", "Restricted analysis", "Confidential", "analysis text"),
        ("DOC-003", "Charge Sheet", "Derived charge sheet", "Confidential", "charge text"),
    ]
    for doc_id, doc_type, title, classification, text in docs:
        db.add(DocumentDB(
            document_id=doc_id, case_id="CASE-T1", document_type=doc_type, title=title,
            description=title, classification=classification, content_text=text,
            current_hash=app_module.hashlib.sha256(text.encode()).hexdigest(), integrity_status="VERIFIED",
            created_at=now, created_by="OFF-001", version=1, file_path=None, hash_algorithm="SHA-256",
        ))
    db.add(ProvenanceEdgeDB(id="REL-1", case_id="CASE-T1", source_doc_id="DOC-002", target_doc_id="DOC-003", relationship_type="derived_from", description="Forensic findings used in charge sheet", created_at=now))
    db.add(BlockchainBlockDB(block_number=1, tx_id="TX-1", timestamp=now, action="GENESIS", document_id="DOC-001", previous_hash="0" * 64, block_hash="a" * 64, merkle_root="b" * 64))
    db.commit()
    db.close()
