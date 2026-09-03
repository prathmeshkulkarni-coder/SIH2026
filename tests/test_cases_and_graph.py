"""Case listing and the provenance graph payload the D3 frontend renders."""

import pytest

from backend.database import DocumentDB


def test_case_list_aggregates_document_and_link_counts(client):
    cases = client.get("/api/cases").json()

    assert cases == [{
        "case_id": "CASE-T1",
        "title": "Test Investigation",
        "case_type": "Cyber",
        "total_documents": 3,
        "provenance_links": 1,
        "verified_documents": 3,
        "review_required_documents": 0,
        "integrity_issues": 0,
    }]


def test_case_list_reflects_integrity_status_changes(client, db):
    db.query(DocumentDB).filter_by(document_id="DOC-002").one().integrity_status = "INTEGRITY_ISSUE"
    db.query(DocumentDB).filter_by(document_id="DOC-003").one().integrity_status = "REVIEW_REQUIRED"
    db.commit()

    case = client.get("/api/cases").json()[0]

    assert case["verified_documents"] == 1
    assert case["review_required_documents"] == 1
    assert case["integrity_issues"] == 1


def test_case_with_no_documents_reports_zero_counts(client, factory):
    factory.case("CASE-EMPTY", name="Empty Case")

    empty = next(case for case in client.get("/api/cases").json() if case["case_id"] == "CASE-EMPTY")

    assert empty["total_documents"] == 0
    assert empty["provenance_links"] == 0
    assert empty["verified_documents"] == 0


def test_case_counts_do_not_leak_across_cases(client, factory):
    factory.case("CASE-T2", name="Second Investigation")
    factory.document("DOC-100", case_id="CASE-T2", status="INTEGRITY_ISSUE")

    cases = {case["case_id"]: case for case in client.get("/api/cases").json()}

    assert cases["CASE-T1"]["total_documents"] == 3
    assert cases["CASE-T2"]["total_documents"] == 1
    assert cases["CASE-T1"]["integrity_issues"] == 0
    assert cases["CASE-T2"]["integrity_issues"] == 1


def test_graph_returns_nodes_links_and_summary(client):
    graph = client.get("/api/cases/CASE-T1/graph").json()

    assert {node["id"] for node in graph["nodes"]} == {"DOC-001", "DOC-002", "DOC-003"}
    assert graph["links"] == [{
        "id": "REL-1",
        "source": "DOC-002",
        "target": "DOC-003",
        "relationship_type": "derived_from",
        "reason": "Forensic findings used in charge sheet",
        "created_at": graph["links"][0]["created_at"],
    }]
    assert graph["case"] == {
        "case_id": "CASE-T1",
        "total_documents": 3,
        "provenance_links": 1,
        "verified_documents": 3,
        "review_required_documents": 0,
        "integrity_issues": 0,
    }


def test_graph_nodes_carry_the_fields_the_frontend_draws(client):
    node = next(n for n in client.get("/api/cases/CASE-T1/graph").json()["nodes"] if n["id"] == "DOC-002")

    assert node["title"] == "Restricted analysis"
    assert node["document_type"] == "Forensic & Pathology Report"
    assert node["classification"] == "Confidential"
    assert node["integrity_status"] == "VERIFIED"
    assert node["version"] == 1
    assert len(node["current_hash"]) == 64


def test_graph_excludes_documents_and_links_from_other_cases(client, factory):
    factory.case("CASE-T2")
    factory.document("DOC-100", case_id="CASE-T2")
    factory.document("DOC-101", case_id="CASE-T2")
    factory.edge("REL-9", "DOC-100", "DOC-101", case_id="CASE-T2")

    graph = client.get("/api/cases/CASE-T1/graph").json()

    assert {node["id"] for node in graph["nodes"]} == {"DOC-001", "DOC-002", "DOC-003"}
    assert [link["id"] for link in graph["links"]] == ["REL-1"]


def test_graph_for_an_unknown_case_returns_an_empty_graph(client):
    """The endpoint does not 404; the frontend receives an empty DAG instead."""
    graph = client.get("/api/cases/CASE-DOES-NOT-EXIST/graph").json()

    assert graph["nodes"] == []
    assert graph["links"] == []
    assert graph["case"]["total_documents"] == 0


@pytest.mark.known_bug
@pytest.mark.xfail(
    reason="links are emitted straight from the edge table, so an edge pointing at a "
           "document outside the case yields a dangling link that breaks the D3 layout",
    strict=False,
)
def test_graph_never_emits_a_link_to_a_missing_node(client, factory):
    factory.edge("REL-DANGLING", "DOC-001", "DOC-999-MISSING")

    graph = client.get("/api/cases/CASE-T1/graph").json()

    node_ids = {node["id"] for node in graph["nodes"]}
    for link in graph["links"]:
        assert link["source"] in node_ids
        assert link["target"] in node_ids
