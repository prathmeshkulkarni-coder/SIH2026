"""Supervisor reject-access-request flow and related access-check behaviour."""

from backend.database import AccessRequestDB, AuditLogDB


def sign_in(client, username, password="secret"):
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['auth_token']}"}


def test_supervisor_can_reject_pending_request_with_reason(client, db):
    officer = sign_in(client, "investigator")
    supervisor = sign_in(client, "supervisor")

    created = client.post(
        "/api/access-requests",
        headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Need forensic review"},
    )
    assert created.status_code == 200, created.text
    request_id = created.json()["request_id"]

    # Investigator cannot reject
    forbidden = client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=officer,
        json={"rejection_reason": "Not allowed"},
    )
    assert forbidden.status_code == 403

    # Reason is required
    missing = client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=supervisor,
        json={},
    )
    assert missing.status_code == 400
    assert "reason" in missing.json()["detail"].lower()

    blank = client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=supervisor,
        json={"rejection_reason": "   "},
    )
    assert blank.status_code == 400

    rejected = client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=supervisor,
        json={"rejection_reason": "Insufficient case justification"},
    )
    assert rejected.status_code == 200, rejected.text
    body = rejected.json()
    assert body["status"] == "REJECTED"
    assert body["rejection_reason"] == "Insufficient case justification"
    assert body["approver_id"] == "SUP-001"
    assert body["session_token"] is None
    assert body["expires_at"] is None

    row = db.query(AccessRequestDB).filter_by(request_id=request_id).one()
    assert row.status == "REJECTED"
    assert row.rejection_reason == "Insufficient case justification"

    audits = db.query(AuditLogDB).filter_by(event_type="ACCESS_REJECTED").all()
    assert len(audits) == 1
    assert "Insufficient case justification" in audits[0].details
    assert audits[0].actor_id == "SUP-001"


def test_reject_then_access_check_and_reapply(client, db):
    officer = sign_in(client, "investigator")
    supervisor = sign_in(client, "supervisor")

    created = client.post(
        "/api/access-requests",
        headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "First attempt"},
    )
    request_id = created.json()["request_id"]

    client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=supervisor,
        json={"rejection_reason": "Wrong document scope"},
    )

    check = client.get("/api/documents/DOC-002/access-check", headers=officer).json()
    assert check["allowed"] is False
    assert check["reason"] == "ACCESS_REJECTED"
    assert check["request_id"] == request_id
    assert "Wrong document scope" in check["message"]
    assert client.get("/api/documents/DOC-002/preview", headers=officer).status_code == 403

    # After rejection the officer may file a fresh request
    again = client.post(
        "/api/access-requests",
        headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Second attempt with clearer grounds"},
    )
    assert again.status_code == 200, again.text
    assert again.json()["status"] == "PENDING"
    assert again.json()["request_id"] != request_id


def test_cannot_reject_or_approve_non_pending_request(client, db):
    officer = sign_in(client, "investigator")
    supervisor = sign_in(client, "supervisor")

    created = client.post(
        "/api/access-requests",
        headers=officer,
        json={"document_id": "DOC-002", "purpose_reason": "Case review"},
    )
    request_id = created.json()["request_id"]

    assert client.post(
        f"/api/access-requests/{request_id}/approve", headers=supervisor
    ).status_code == 200

    # Already approved → reject and approve both conflict
    assert client.post(
        f"/api/access-requests/{request_id}/reject",
        headers=supervisor,
        json={"rejection_reason": "Too late"},
    ).status_code == 409
    assert client.post(
        f"/api/access-requests/{request_id}/approve", headers=supervisor
    ).status_code == 409


def test_reject_unknown_request_returns_404(client):
    supervisor = sign_in(client, "supervisor")
    response = client.post(
        "/api/access-requests/AR-DOES-NOT-EXIST/reject",
        headers=supervisor,
        json={"rejection_reason": "n/a"},
    )
    assert response.status_code == 404
