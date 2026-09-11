"""
CUSTODY CHAIN / NCRB SECURE DMS - Data Models (SIH26190)
Complete data models for Legal & Investigation Document Management System,
Digital Signatures (eSign/PKI), Blockchain Verification Ledger, Asset Tracking, and Provenance.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class DocumentType(str, Enum):
    FIR_POLICE_REPORT = "FIR / Police Report"
    INVESTIGATION_RECORD = "Investigation Record"
    WITNESS_STATEMENT = "Witness Statement"
    CHARGE_SHEET = "Charge Sheet"
    COURT_SUBMISSION = "Court Filing / Order"
    EVIDENCE_RECORD = "Evidence & Seizure Memo"
    FORENSIC_REPORT = "Forensic & Pathology Report"
    LEGAL_NOTICE = "Legal Notice / Judgment"

class RelationshipType(str, Enum):
    DERIVED_FROM = "derived_from"
    MERGED_FROM = "merged_from"
    REDACTED_FROM = "redacted_from"
    TRANSLATED_FROM = "translated_from"
    SUMMARIZED_FROM = "summarized_from"
    REVISED_FROM = "revised_from"
    REFERENCED_FROM = "referenced_from"

class IntegrityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    INTEGRITY_ISSUE = "INTEGRITY_ISSUE"

class Classification(str, Enum):
    PUBLIC = "Public Record"
    INTERNAL = "Internal Official"
    CONFIDENTIAL = "Confidential"
    HIGHLY_CONFIDENTIAL = "Highly Confidential (Restricted)"

class UserRole(str, Enum):
    INVESTIGATOR = "Investigating Officer (IO)"
    SUPERVISOR = "Superintendent of Police (SP)"
    FORENSIC_OFFICER = "Forensic Science Expert (CFSL)"
    PROSECUTOR = "Public Prosecutor"
    JUDICIAL_MAGISTRATE = "Judicial Magistrate"
    AUDITOR = "NCRB / Judicial Auditor"

class User(BaseModel):
    user_id: str
    name: str
    role: UserRole
    department: str
    badge_number: str
    assigned_cases: List[str] = []

class DigitalSignature(BaseModel):
    signature_id: str
    signer_id: str
    signer_name: str
    signer_role: str
    certificate_issuer: str  # e.g., "CCA India - C-DAC eSign CA 2026"
    certificate_serial: str
    signed_at: str
    signed_hash: str
    is_valid: bool = True

class BlockchainBlock(BaseModel):
    block_number: int
    block_hash: str
    previous_hash: str
    timestamp: str
    document_id: str
    action: str  # CREATED, SIGNED, TRANSFORMED, VERIFIED
    merkle_root: str
    tx_id: str

class DocumentVersion(BaseModel):
    version_id: str
    document_id: str
    version_number: int
    hash_value: str
    created_by: str
    created_at: str
    change_reason: str
    content_summary: str
    file_size_bytes: int = 2048
    signature_reference: Optional[str] = None

class ProvenanceEdge(BaseModel):
    edge_id: str
    source_document_id: str
    target_document_id: str
    relationship_type: RelationshipType
    transformation_reason: str
    created_by: str
    created_at: str
    approved_by: Optional[str] = None
    approval_status: str = "APPROVED"

class DocumentNode(BaseModel):
    document_id: str
    case_id: str
    document_type: DocumentType
    title: str
    description: str
    classification: Classification
    creator_id: str
    creator_name: str
    creation_timestamp: str
    current_version: int = 1
    integrity_status: IntegrityStatus = IntegrityStatus.VERIFIED
    approval_status: str = "APPROVED"
    storage_reference: str
    current_hash: str
    digital_signature: Optional[DigitalSignature] = None
    blockchain_block_id: Optional[int] = None
    external_system_source: Optional[str] = None  # CCTNS, eSakshya, ICJS, eCourts
    external_reference: Optional[str] = None
    content_text: str = ""
    sensitive_flag: bool = False

class AccessRequest(BaseModel):
    request_id: str
    document_id: str
    requester_id: str
    requester_name: str
    requester_role: str
    requested_action: str
    purpose_reason: str
    status: str
    requested_at: str
    approver_id: Optional[str] = None
    approved_at: Optional[str] = None
    session_token: Optional[str] = None
    expires_at: Optional[str] = None
    rejection_reason: Optional[str] = None

class AuditEvent(BaseModel):
    event_id: str
    event_type: str
    actor_id: str
    actor_name: str
    document_id: Optional[str] = None
    case_id: Optional[str] = None
    timestamp: str
    details: str
    integrity_reference: Optional[str] = None

class CaseSummary(BaseModel):
    case_id: str
    case_number: str
    title: str
    description: str
    investigator_id: str
    investigator_name: str
    status: str
    created_at: str
    total_documents: int = 0
    provenance_links: int = 0
    verified_documents: int = 0
    review_required_documents: int = 0
    integrity_issues: int = 0

class PoliceAsset(BaseModel):
    asset_id: str
    asset_name: str
    category: str  # EVIDENCE, WEAPON, DIGITAL_DRIVE, SEIZED_VEHICLE
    serial_number: str
    case_id: str
    custodian_id: str
    location: str
    status: str  # VAULT_SEALED, FORENSIC_LAB, COURT_PRODUCED
    linked_document_ids: List[str] = []
