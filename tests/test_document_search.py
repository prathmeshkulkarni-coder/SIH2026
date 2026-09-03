"""Full-text document search: matching, wildcards and information disclosure."""

import pytest


def search(client, query):
    return client.get("/api/documents/search", params={"q": query})


def test_search_matches_on_document_id(client):
    body = search(client, "DOC-002").json()

    assert body["query"] == "DOC-002"
    assert body["total_results"] == 1
    assert body["documents"][0]["document_id"] == "DOC-002"


def test_search_matches_on_title(client):
    assert search(client, "Restricted analysis").json()["total_results"] == 1


def test_search_matches_on_content_text(client):
    assert [d["document_id"] for d in search(client, "charge text").json()["documents"]] == ["DOC-003"]


def test_search_matches_on_document_type(client):
    assert [d["document_id"] for d in search(client, "Forensic").json()["documents"]] == ["DOC-002"]


def test_search_matches_on_hash(client, db):
    from backend.database import DocumentDB

    doc_hash = db.query(DocumentDB).filter_by(document_id="DOC-001").one().current_hash

    assert [d["document_id"] for d in search(client, doc_hash).json()["documents"]] == ["DOC-001"]


def test_search_returns_a_partial_match(client):
    assert search(client, "analy").json()["total_results"] == 1


def test_search_with_no_match_returns_an_empty_result_set(client):
    body = search(client, "nothing-matches-this").json()

    assert body["total_results"] == 0
    assert body["documents"] == []


def test_search_result_carries_the_fields_the_repository_view_needs(client):
    result = search(client, "DOC-002").json()["documents"][0]

    assert result["case_id"] == "CASE-T1"
    assert result["classification"] == "Confidential"
    assert result["integrity_status"] == "VERIFIED"
    assert result["digital_signature"] is False


def test_search_flags_documents_that_carry_a_signature(client, factory):
    factory.document("DOC-100", title="Signed report", signature_json='{"is_valid": true}')

    result = next(d for d in search(client, "DOC-100").json()["documents"])

    assert result["digital_signature"] is True


def test_missing_query_parameter_is_rejected(client):
    assert client.get("/api/documents/search").status_code == 422


def test_empty_query_parameter_is_rejected(client):
    assert search(client, "").status_code == 422


def test_search_is_case_insensitive_on_sqlite(client):
    """SQLite LIKE ignores ASCII case.  PostgreSQL LIKE does not, so this behaviour
    silently changes between the development and production databases; the query
    should use ilike to be portable."""
    assert search(client, "ANALYSIS").json()["total_results"] == 1


@pytest.mark.security
def test_a_whitespace_only_query_returns_every_document(client):
    """" " survives min_length=1 but strips to "", producing the LIKE pattern '%%'."""
    assert search(client, " ").json()["total_results"] == 3


@pytest.mark.security
@pytest.mark.parametrize("wildcard", ["%", "_", "%%"])
def test_like_wildcards_are_not_escaped(client, wildcard):
    """User input is interpolated straight into a LIKE pattern, so a single
    wildcard enumerates the whole repository."""
    assert search(client, wildcard).json()["total_results"] > 0


@pytest.mark.security
@pytest.mark.known_bug
@pytest.mark.xfail(
    reason="search takes no user_id and performs no clearance check, so confidential "
           "titles, descriptions and hashes are returned to any caller",
    strict=False,
)
def test_search_does_not_disclose_confidential_documents_without_clearance(client):
    results = search(client, "%").json()["documents"]

    assert [r for r in results if r["classification"] == "Confidential"] == []


@pytest.mark.security
def test_search_is_reachable_without_authentication(client):
    """Locks in the current (unauthenticated) behaviour so adding auth is a visible change."""
    assert search(client, "DOC-001").status_code == 200


def test_search_route_is_not_shadowed_by_the_document_detail_route(client):
    """/api/documents/search must stay declared before /api/documents/{doc_id}."""
    response = search(client, "DOC-001")

    assert response.status_code == 200
    assert "total_results" in response.json()
