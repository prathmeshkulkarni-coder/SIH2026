import asyncio
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from backend import app as api
from backend.database import AccessRequestDB, AuditLogDB, BlockchainBlockDB, DocumentDB, UserDB


def test_login_case_graph_search_and_document_details(db_session):
    db = db_session()
    assert api.login_user({"username": "investigator", "password": "secret"}, db)["status"] == "SUCCESS"
    with pytest.raises(HTTPException, match="Invalid username"):
        api.login_user({"username": "investigator", "password": "wrong"}, db)
    cases = api.list_cases(db)
    assert cases == [{"case_id": "CASE-T1", "title": "Test Investigation", "case_type": "Cyber", "total_documents": 3, "provenance_links": 1, "verified_documents": 3, "review_required_documents": 0, "integrity_issues": 0}]
    graph = api.get_case_provenance_graph("CASE-T1", db)
    assert len(graph["nodes"]) == 3 and graph["links"][0]["source"] == "DOC-002"
    officer = db.query(UserDB).filter_by(user_id="OFF-001").one()
    assert api.search_documents("analysis", officer, db)["total_results"] == 1
    detail = api.get_document_details("DOC-003", officer, db)
    assert detail["ancestors"][0].document_id == "DOC-002"
    with pytest.raises(HTTPException) as not_found:
        api.get_document_details("does-not-exist", officer, db)
    assert not_found.value.status_code == 404
    db.close()


def sign_in(client, username, password="secret"):
    """Log in over HTTP and return the Authorization header for that officer."""
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['auth_token']}"}


def test_protected_routes_reject_anonymous_and_invalid_tokens(client):
    assert client.get("/api/access-requests").status_code == 401
    assert client.get("/api/documents/DOC-002/preview").status_code == 401
    assert client.get("/api/documents/DOC-002/download").status_code == 404
    assert client.get("/api/documents/DOC-002/access-check").status_code == 401
    bogus = {"Authorization": "Bearer AUTH-NOT-A-REAL-TOKEN"}
    assert client.get("/api/access-requests", headers=bogus).status_code == 401


def test_access_request_approval_expiry_and_preview(client, db, storage_dir):
    (storage_dir / "DOC-002.pdf").write_bytes(b"%PDF-1.4 forensic report")
    officer = sign_in(client, "investigator")

    denied = client.get("/api/documents/DOC-002/access-check", headers=officer).json()
    assert denied["allowed"] is False and denied["reason"] == "NO_CLEARANCE"

    created = client.post(
        "/api/access-requests",
        headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Case review"},
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request_id"]
    # The requester is bound to the token, not to anything the client sent
    assert created.json()["requester_id"] == "OFF-001"
    assert created.json()["status"] == "PENDING"

    pending = client.get("/api/documents/DOC-002/access-check", headers=officer).json()
    assert pending["reason"] == "PENDING_APPROVAL" and pending["request_id"] == request_id

    # A duplicate request is refused rather than stacking up in the queue
    assert client.post(
        "/api/access-requests", headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Case review"},
    ).status_code == 409

    # An investigator cannot approve their own request
    self_approval = client.post(f"/api/access-requests/{request_id}/approve", headers=officer)
    assert self_approval.status_code == 403

    supervisor = sign_in(client, "supervisor")
    approved = client.post(f"/api/access-requests/{request_id}/approve", headers=supervisor)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "APPROVED"
    assert approved.json()["session_token"].startswith("TOK-SECURE-")
    assert approved.json()["approver_id"] == "SUP-001"

    # Approving twice is rejected
    assert client.post(f"/api/access-requests/{request_id}/approve", headers=supervisor).status_code == 409

    granted = client.get("/api/documents/DOC-002/access-check", headers=officer).json()
    assert granted["allowed"] is True and granted["reason"] == "SUPERVISOR_GRANT"

    served = client.get("/api/documents/DOC-002/preview", headers=officer)
    assert served.status_code == 200 and served.content.startswith(b"%PDF")
    assert served.headers.get("content-disposition", "").startswith("inline")
    # The preview is recorded against the officer who opened it — never as a download
    previews = db.query(AuditLogDB).filter_by(event_type="DOCUMENT_PREVIEWED").all()
    assert [(entry.actor_id, entry.document_id) for entry in previews] == [("OFF-001", "DOC-002")]

    # Once the clearance lapses the same officer is refused again
    grant = db.query(AccessRequestDB).filter_by(request_id=request_id).one()
    grant.expires_at = (datetime.now() - timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
    db.commit()

    expired = client.get("/api/documents/DOC-002/access-check", headers=officer).json()
    assert expired["allowed"] is False and expired["reason"] == "GRANT_EXPIRED"
    assert client.get("/api/documents/DOC-002/preview", headers=officer).status_code == 403


def test_grant_is_bound_to_one_officer_and_never_leaks(client, db, factory):
    """
    The regression this suite exists for: approving a document for the investigating
    officer must confer nothing on any other user, and must not even be visible to them.
    """
    factory.user("LAB-001", username="forensic", name="Dr Forensic", role="Forensic Analyst")

    officer = sign_in(client, "investigator")
    analyst = sign_in(client, "forensic")
    supervisor = sign_in(client, "supervisor")

    request_id = client.post(
        "/api/access-requests", headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Case review"},
    ).json()["request_id"]
    client.post(f"/api/access-requests/{request_id}/approve", headers=supervisor)

    # The investigator may read it, the analyst may not
    assert client.get("/api/documents/DOC-002/access-check", headers=officer).json()["allowed"] is True
    analyst_verdict = client.get("/api/documents/DOC-002/access-check", headers=analyst).json()
    assert analyst_verdict["allowed"] is False
    assert analyst_verdict["reason"] == "NO_CLEARANCE"
    assert client.get("/api/documents/DOC-002/preview", headers=analyst).status_code == 403

    # The analyst is not even told the investigator's clearance exists
    assert client.get("/api/access-requests", headers=analyst).json() == []
    assert [r["request_id"] for r in client.get("/api/access-requests", headers=officer).json()] == [request_id]
    # Only the supervisor sees the full approval queue
    assert [r["request_id"] for r in client.get("/api/access-requests", headers=supervisor).json()] == [request_id]


def test_impact_simulation_does_not_write_integrity_flags(client, db, factory):
    factory.edge("REL-2", "DOC-001", "DOC-002")
    officer = sign_in(client, "investigator")

    before = db.query(DocumentDB).filter_by(document_id="DOC-002").one().integrity_status
    response = client.post(
        "/api/simulation/impact",
        headers=officer,
        json={"document_id": "DOC-001", "action": "INTEGRITY_FAILURE"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["simulation"] is True
    assert body["affected_summary"]["total_affected"] >= 1
    assert body["simulated_nodes"]["DOC-001"]["simulated_status"] == "INTEGRITY_ISSUE"
    assert body["simulated_nodes"]["DOC-002"]["simulated_status"] == "REVIEW_REQUIRED"

    db.expire_all()
    assert db.query(DocumentDB).filter_by(document_id="DOC-001").one().integrity_status == "VERIFIED"
    assert db.query(DocumentDB).filter_by(document_id="DOC-002").one().integrity_status == before


def test_court_copy_is_public_and_does_not_alter_the_original(client, db, factory, storage_dir):
    """
    The judge demo: an officer prepares a public copy with names and IPs removed.
    The original stays confidential. A court officer can open the copy; a forensic
    analyst who was never cleared still cannot open the original — or make a copy.
    """
    factory.access_request("AR-910", "DOC-002", "OFF-001", status="APPROVED")
    factory.user("CRT-001", username="magistrate", name="Magistrate Test", role="Court Officer")
    factory.user("LAB-001", username="forensic", name="Dr Forensic", role="Forensic Analyst")

    original_text = db.query(DocumentDB).filter_by(document_id="DOC-002").one().content_text
    officer = sign_in(client, "investigator")
    analyst = sign_in(client, "forensic")

    assert client.post(
        "/api/documents/DOC-002/redact",
        headers=analyst,
        json={"redacted_content": "Witness Suresh Patel at 192.168.1.45"},
    ).status_code == 403

    created = client.post(
        "/api/documents/DOC-002/redact",
        headers=officer,
        json={"redacted_content": "Witness Suresh Patel confirms login from IP 192.168.1.45."},
    )
    assert created.status_code == 200, created.text
    body = created.json()
    new_id = body["new_document"]["document_id"]
    court_text = body["new_document"]["content_text"]

    assert body["new_document"]["classification"] == "Public Record"
    assert body["provenance_edge"]["relationship_type"] == "redacted_from"
    assert body["provenance_edge"]["source_document_id"] == "DOC-002"
    assert "[REDACTED NAME]" in court_text
    assert "[REDACTED IP ADDRESS]" in court_text
    assert "Suresh Patel" not in court_text
    assert "192.168.1.45" not in court_text

    db.expire_all()
    source = db.query(DocumentDB).filter_by(document_id="DOC-002").one()
    copy = db.query(DocumentDB).filter_by(document_id=new_id).one()
    assert source.content_text == original_text
    assert source.classification == "Confidential"
    assert copy.classification == "Public Record"

    magistrate = sign_in(client, "magistrate")
    assert client.get(f"/api/documents/{new_id}/access-check", headers=magistrate).json()["allowed"] is True
    assert client.get(f"/api/documents/{new_id}/preview", headers=magistrate).status_code == 200
    assert client.get("/api/documents/DOC-002/access-check", headers=analyst).json()["allowed"] is False


def test_role_privilege_and_public_records_bypass_the_queue(client, db, factory):
    factory.user("CRT-001", username="magistrate", name="Magistrate Test", role="Court Officer")
    factory.user("AUD-001", username="auditor", name="Auditor Test", role="Auditor")

    # DOC-001 is a public record: open to everyone, including a role with no privileges
    auditor = sign_in(client, "auditor")
    public = client.get("/api/documents/DOC-001/access-check", headers=auditor).json()
    assert public["allowed"] is True and public["reason"] == "PUBLIC_RECORD"
    # ...but a confidential document still needs a grant
    assert client.get("/api/documents/DOC-002/access-check", headers=auditor).json()["allowed"] is False

    for username in ("supervisor", "magistrate"):
        headers = sign_in(client, username)
        verdict = client.get("/api/documents/DOC-002/access-check", headers=headers).json()
        assert verdict["allowed"] is True and verdict["reason"] == "ROLE_PRIVILEGE"


def test_logout_ends_the_session_and_revokes_that_officers_clearances(client, db, factory):
    factory.access_request("AR-900", "DOC-002", "OFF-001", status="APPROVED", token="TOK-SECURE-X")
    factory.access_request("AR-901", "DOC-003", "OFF-002", status="APPROVED", token="TOK-SECURE-Y")

    officer = sign_in(client, "investigator")
    assert client.get("/api/documents/DOC-002/access-check", headers=officer).json()["allowed"] is True

    result = client.post("/api/auth/logout", headers=officer)
    assert result.status_code == 200 and result.json()["revoked_clearances"] == 1

    # The token no longer works, and only this officer's grant was revoked
    assert client.get("/api/access-requests", headers=officer).status_code == 401
    db.expire_all()
    assert db.query(AccessRequestDB).filter_by(request_id="AR-900").one().status == "REVOKED_ON_LOGOUT"
    assert db.query(AccessRequestDB).filter_by(request_id="AR-901").one().status == "APPROVED"


def test_tamper_reset_upload_and_blockchain_validation(db_session):
    db = db_session()
    tamper = api.trigger_tamper_demo("DOC-002", db)
    assert tamper["affected_nodes"] == ["DOC-003"]
    assert db.query(DocumentDB).filter_by(document_id="DOC-003").one().integrity_status == "REVIEW_REQUIRED"
    assert api.reset_tamper_demo("DOC-002", db)["status"] == "SUCCESS"
    uploader = db.query(UserDB).filter_by(user_id="OFF-001").one()
    upload = asyncio.run(api.upload_new_document(case_id="CASE-T1", document_type="Investigation Record", title="Field note", description="New note", classification="Internal Official", content_text="field note", parent_doc_id="DOC-001", parent_doc_ids=None, relationship_type="derived_from", file=None, uploader=uploader, db=db))
    assert db.query(DocumentDB).filter_by(document_id="DOC-004").one().created_by == "OFF-001"
    assert upload["document_id"] == "DOC-004"
    assert upload["node"]["document_id"] == "DOC-004"
    assert [(e["source"], e["target"]) for e in upload["edges"]] == [("DOC-001", "DOC-004")]
    assert api.verify_blockchain_ledger(db)["verified"] is True
    db.query(BlockchainBlockDB).filter_by(block_number=2).one().previous_hash = "broken"
    db.commit()
    assert api.verify_blockchain_ledger(db)["chain_status"] == "CORRUPTED"
    db.close()
