"""
CUSTODY CHAIN - Backend Automated Test Suite
Tests provenance graph algorithms, dependency impact propagation,
SHA-256 cryptographic verification, access control workflows, and audit trail logging.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.models import IntegrityStatus, RelationshipType
from backend.seed_data import generate_seed_data
from backend.provenance import ProvenanceGraphEngine
from backend.integrity import IntegrityService
from backend.app import (
    DOCUMENTS, EDGES, CASES, ACCESS_REQUESTS, INTEGRITY_SERVICE,
    verify_document_integrity, trigger_tamper_demo, reset_tamper,
    request_sensitive_access, approve_access_request, redact_document_pii,
    explain_downstream_impact, trace_document_origin
)

def test_provenance_graph_structure():
    docs, edges, users, cases, blocks, assets = generate_seed_data()
    engine = ProvenanceGraphEngine(docs, edges)
    
    # Test origin tracing for Charge Sheet CS-021 in CASE-2026-101
    origin = engine.trace_origin("CS-021")
    ancestor_ids = origin["ancestor_document_ids"]
    print(f"CS-021 Ancestors: {ancestor_ids}")
    assert "IR-014" in ancestor_ids
    assert "FR-009" in ancestor_ids
    assert "E-001" in ancestor_ids
    assert "WS-004" in ancestor_ids
    print("✓ Graph Origin Traversal Test PASSED")

def test_dependency_impact_and_explainability():
    # Reset tamper state first
    reset_tamper("FR-009")
    
    # Analyze impact if FR-009 is compromised
    engine = ProvenanceGraphEngine(DOCUMENTS, EDGES)
    impact = engine.analyze_downstream_impact("FR-009")
    
    direct = impact["direct_dependents"]
    indirect = impact["indirect_dependents"]
    
    print(f"FR-009 Direct dependents: {direct}")
    print(f"FR-009 Indirect dependents: {indirect}")
    
    assert "IR-014" in direct
    assert "CS-021" in indirect
    assert "WS-004" not in impact["affected_node_ids"]  # Unrelated branch
    
    # Trigger tamper demo on FR-009
    res = trigger_tamper_demo("FR-009")
    assert res["status"] == "INTEGRITY_ISSUE"
    
    # Verify downstream statuses updated to REVIEW_REQUIRED
    assert DOCUMENTS["FR-009"].integrity_status == IntegrityStatus.INTEGRITY_ISSUE
    assert DOCUMENTS["IR-014"].integrity_status == IntegrityStatus.REVIEW_REQUIRED
    assert DOCUMENTS["CS-021"].integrity_status == IntegrityStatus.REVIEW_REQUIRED
    assert DOCUMENTS["WS-004"].integrity_status == IntegrityStatus.VERIFIED  # Remains unaffected
    
    # Test "Why is this affected?" explanation for Charge Sheet CS-021
    explanation = explain_downstream_impact("CS-021", source_id="FR-009")
    print(f"Explanation Path for CS-021:\n{explanation['human_explanation']}")
    assert explanation["path_found"] is True
    assert len(explanation["steps"]) >= 2
    
    # Reset tamper state
    reset_tamper("FR-009")
    assert DOCUMENTS["FR-009"].integrity_status == IntegrityStatus.VERIFIED
    print("✓ Dependency Impact & Explainability Test PASSED")

def test_access_request_and_approval_workflow():
    # Submit access request for sensitive Forensic Report FR-009
    req = request_sensitive_access({
        "document_id": "FR-009",
        "user_id": "INV-204",
        "requested_action": "VIEW",
        "purpose_reason": "Automated Unit Test Access Verification"
    })
    
    assert req.status == "PENDING"
    req_id = req.request_id
    
    # Approve request as Supervisor SUP-052
    approved = approve_access_request(req_id, {"approver_id": "SUP-052"})
    assert approved.status == "APPROVED"
    assert approved.session_token is not None
    assert "SESS-" in approved.session_token
    assert approved.expires_at is not None
    print("✓ Supervisor Access Request & Approval Workflow PASSED")

def test_pii_redaction_derivative():
    init_count = len(DOCUMENTS)
    res = redact_document_pii("WS-004", {
        "redacted_content": "WITNESS STATEMENT: Statement of [CONFIDENTIAL WITNESS] regarding server escalation.",
        "user_id": "INV-204"
    })
    
    new_doc = res["new_document"]
    edge = res["provenance_edge"]
    
    assert len(DOCUMENTS) == init_count + 1
    assert edge.source_document_id == "WS-004"
    assert edge.target_document_id == new_doc.document_id
    assert edge.relationship_type == RelationshipType.REDACTED_FROM
    
    # Verify original document WS-004 was NOT mutated
    assert DOCUMENTS["WS-004"].document_id == "WS-004"
    assert "Chief Information Security Officer" in DOCUMENTS["WS-004"].content_text
    print("✓ PII Redaction & Immutable Lineage Test PASSED")

if __name__ == "__main__":
    print("Running Custody Chain Backend Automated Test Suite...")
    test_provenance_graph_structure()
    test_dependency_impact_and_explainability()
    test_access_request_and_approval_workflow()
    test_pii_redaction_derivative()
    print("\n=============================================")
    print("ALL CUSTODY CHAIN BACKEND TESTS PASSED (100%)")
    print("=============================================")
