from backend.integrity import IntegrityService
from backend.models import Classification, DocumentNode, DocumentType, IntegrityStatus, ProvenanceEdge, RelationshipType
from backend.provenance import ProvenanceGraphEngine


def _document(doc_id, status=IntegrityStatus.VERIFIED):
    return DocumentNode(
        document_id=doc_id, case_id="CASE-T1", document_type=DocumentType.INVESTIGATION_RECORD,
        title=f"Document {doc_id}", description="test", classification=Classification.CONFIDENTIAL,
        creator_id="OFF-001", creator_name="Officer", creation_timestamp="2026-01-01 00:00:00",
        storage_reference=f"/documents/{doc_id}.pdf", current_hash=doc_id, integrity_status=status,
    )


def _edge(edge_id, source, target):
    return ProvenanceEdge(edge_id=edge_id, source_document_id=source, target_document_id=target,
                          relationship_type=RelationshipType.DERIVED_FROM, transformation_reason="derived",
                          created_by="OFF-001", created_at="2026-01-01 00:00:00")


def test_integrity_hash_is_deterministic_and_audit_filters_events():
    service = IntegrityService()
    assert service.compute_sha256("evidence") == service.compute_sha256("evidence")
    assert service.compute_sha256("evidence") != service.compute_sha256("changed evidence")
    first = service.log_event("VIEW", "OFF-1", "Officer", "opened", document_id="DOC-1", case_id="CASE-1")
    second = service.log_event("DOWNLOAD", "OFF-1", "Officer", "downloaded", document_id="DOC-1", case_id="CASE-1")
    service.log_event("VIEW", "OFF-2", "Officer 2", "opened", document_id="DOC-2", case_id="CASE-2")
    assert [event.event_id for event in service.get_audit_trail(document_id="DOC-1")] == [second.event_id, first.event_id]
    assert len(service.get_audit_trail(case_id="CASE-2")) == 1


def test_provenance_traces_and_explains_a_multi_hop_impact():
    documents = {doc_id: _document(doc_id, IntegrityStatus.INTEGRITY_ISSUE if doc_id == "A" else IntegrityStatus.VERIFIED)
                 for doc_id in ("A", "B", "C", "UNRELATED")}
    engine = ProvenanceGraphEngine(documents, [_edge("1", "A", "B"), _edge("2", "B", "C")])
    impact = engine.analyze_downstream_impact("A")
    assert impact["direct_dependents"] == ["B"]
    assert impact["indirect_dependents"] == ["C"]
    assert engine.trace_origin("C")["ancestor_document_ids"] == ["B", "A"]
    explanation = engine.explain_impact("C")
    assert explanation["path_nodes"] == ["A", "B", "C"]
    assert "REVIEW REQUIRED" in explanation["human_explanation"]
    assert engine.analyze_downstream_impact("missing") == {"error": "Document not found"}


def test_simulation_does_not_change_document_integrity_state():
    source, child = _document("A"), _document("B")
    engine = ProvenanceGraphEngine({"A": source, "B": child}, [_edge("1", "A", "B")])
    simulation = engine.simulate_impact("A")
    assert simulation["simulated_nodes"]["A"]["simulated_status"] == "INTEGRITY_ISSUE"
    assert simulation["simulated_nodes"]["B"]["simulated_status"] == "REVIEW_REQUIRED"
    assert source.integrity_status == IntegrityStatus.VERIFIED
    assert child.integrity_status == IntegrityStatus.VERIFIED
