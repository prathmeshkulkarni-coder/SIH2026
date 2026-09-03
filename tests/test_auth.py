"""Authentication: login, logout and the token revocation that logout performs."""

import pytest

from backend.database import AccessRequestDB, UserDB


def login(client, username, password):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def auth_header(client, username, password="secret"):
    """Sign in and return the bearer header the API expects on protected routes."""
    token = login(client, username, password).json()["auth_token"]
    return {"Authorization": f"Bearer {token}"}


def test_valid_credentials_return_a_token_and_the_user_profile(client):
    response = login(client, "investigator", "secret")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUCCESS"
    assert body["auth_token"].startswith("AUTH-")
    assert body["user"] == {
        "username": "investigator",
        "user_id": "OFF-001",
        "name": "IO Test",
        "role": "Investigator",
        "department": "NCRB",
        "badge_number": "OFF-1",
    }


def test_each_login_issues_a_distinct_token(client):
    first = login(client, "investigator", "secret").json()["auth_token"]
    second = login(client, "investigator", "secret").json()["auth_token"]

    assert first != second


@pytest.mark.parametrize("username", ["INVESTIGATOR", "  Investigator  ", "iNvEsTiGaToR"])
def test_username_is_matched_case_insensitively_and_trimmed(client, username):
    assert login(client, username, "secret").status_code == 200


def test_password_is_trimmed_before_comparison(client):
    """Surrounding whitespace is stripped, so passwords cannot begin or end with a space."""
    assert login(client, "investigator", "  secret  ").status_code == 200


@pytest.mark.security
@pytest.mark.parametrize(
    "username,password",
    [
        ("investigator", "wrong-password"),
        ("investigator", ""),
        ("no-such-user", "secret"),
        ("", ""),
    ],
)
def test_bad_credentials_are_rejected_with_401(client, username, password):
    response = login(client, username, password)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


@pytest.mark.security
def test_failed_login_does_not_leak_whether_the_username_exists(client):
    unknown_user = login(client, "ghost", "secret")
    wrong_password = login(client, "investigator", "nope")

    assert unknown_user.json()["detail"] == wrong_password.json()["detail"]


def test_successful_login_is_written_to_the_audit_trail(client, audit_service):
    login(client, "supervisor", "secret")

    events = [event for event in audit_service.audit_trail if event.event_type == "USER_LOGIN"]
    assert len(events) == 1
    assert events[0].actor_id == "SUP-001"
    assert "Supervisor" in events[0].details


def test_failed_login_is_not_written_to_the_audit_trail(client, audit_service):
    login(client, "investigator", "wrong")

    assert audit_service.audit_trail == []


@pytest.mark.security
@pytest.mark.known_bug
@pytest.mark.xfail(
    reason="users.hashed_password holds the plaintext password; bcrypt/passlib are "
           "installed but never used, so a database leak exposes every credential",
    strict=False,
)
def test_stored_credential_is_not_the_plaintext_password(client, db):
    login(client, "investigator", "secret")

    stored = db.query(UserDB).filter_by(username="investigator").one()
    assert stored.hashed_password != "secret"


def test_logout_revokes_the_users_approved_access_tokens(client, db, factory):
    factory.access_request("AR-900", "DOC-002", "OFF-001", status="APPROVED", token="TOK-A")

    response = client.post("/api/auth/logout", headers=auth_header(client, "investigator"))

    assert response.status_code == 200
    revoked = db.query(AccessRequestDB).filter_by(request_id="AR-900").one()
    db.refresh(revoked)
    assert revoked.status == "REVOKED_ON_LOGOUT"
    assert revoked.session_token is None


@pytest.mark.security
def test_logout_only_revokes_the_tokens_of_the_user_logging_out(client, db, factory):
    factory.user("OFF-002", username="second", role="Investigator")
    factory.access_request("AR-901", "DOC-002", "OFF-001", status="APPROVED", token="TOK-A")
    factory.access_request("AR-902", "DOC-002", "OFF-002", status="APPROVED", token="TOK-B")

    client.post("/api/auth/logout", headers=auth_header(client, "investigator"))

    other = db.query(AccessRequestDB).filter_by(request_id="AR-902").one()
    db.refresh(other)
    assert other.status == "APPROVED"
    assert other.session_token == "TOK-B"


def test_logout_leaves_pending_requests_alone(client, db, factory):
    factory.access_request("AR-903", "DOC-002", "OFF-001", status="PENDING")

    client.post("/api/auth/logout", headers=auth_header(client, "investigator"))

    pending = db.query(AccessRequestDB).filter_by(request_id="AR-903").one()
    db.refresh(pending)
    assert pending.status == "PENDING"


@pytest.mark.security
def test_logout_requires_a_session_and_cannot_target_another_user(client, factory):
    """
    Logout acts on the account behind the token. Without one there is nothing to end, and
    naming another officer in the body cannot log them out.
    """
    factory.access_request("AR-904", "DOC-002", "OFF-001", status="APPROVED", token="TOK-A")

    assert client.post("/api/auth/logout", json={}).status_code == 401
    assert client.post("/api/auth/logout", json={"user_id": "OFF-001"}).status_code == 401


def test_logout_is_written_to_the_audit_trail(client, audit_service):
    client.post("/api/auth/logout", headers=auth_header(client, "investigator"))

    events = [event for event in audit_service.audit_trail if event.event_type == "USER_LOGOUT"]
    assert len(events) == 1
    assert events[0].actor_id == "OFF-001"


def test_a_token_stops_working_after_its_owner_logs_out(client):
    header = auth_header(client, "investigator")

    assert client.get("/api/access-requests", headers=header).status_code == 200
    assert client.post("/api/auth/logout", headers=header).status_code == 200
    assert client.get("/api/access-requests", headers=header).status_code == 401
