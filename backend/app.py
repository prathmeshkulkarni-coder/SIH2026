"""
CUSTODY CHAIN / NCRB SECURE DMS - FastAPI Server (SIH26190)
Complete Database-Driven REST API for Law Enforcement, Courts, and Investigative Departments:
Centralized Document Storage, Intelligent Full-Text Search, Digital Signatures (eSign PKI),
Blockchain Ledger Verification, Provenance Lineage, Access Control, and Asset Tracking.
Backed directly by Database (SQLAlchemy / PostgreSQL / SQLite) & Physical File Management.
"""

from fastapi import FastAPI, HTTPException, Query, Body, UploadFile, File, Form, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import os
import re
import uuid
import hashlib
import json
from dotenv import load_dotenv
from sqlalchemy.orm import Session

# Load environment variables
load_dotenv()

try:
    import pypdf
except ImportError:
    pypdf = None

from backend.models import (
    DocumentNode, ProvenanceEdge, DocumentVersion, AccessRequest,
    AuditEvent, IntegrityStatus, CaseSummary, User, RelationshipType, Classification,
    DocumentType, DigitalSignature, BlockchainBlock, PoliceAsset
)
from backend.provenance import ProvenanceGraphEngine
from backend.integrity import IntegrityService
from backend.database import (
    init_db, SessionLocal, CaseDB, DocumentDB, ProvenanceEdgeDB,
    UserDB, AccessRequestDB, AuditLogDB, BlockchainBlockDB, PoliceAssetDB,
    VersionDB, IntegrityEventDB, AuthSessionDB
)

app = FastAPI(
    title="TraceX API",
    description="Secure Digital Document Management System for Legal and Investigation Documents (SIH Problem Statement SIH26190)",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database Schema & Load CSV Dataset if empty
try:
    init_db()
except Exception as e:
    print(f"Database Init Notice: {e}")

# Physical Document Storage directory — NOT publicly mounted (access controlled via API)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_STORAGE_DIR = os.path.join(BASE_DIR, "dataset", "documents")
os.makedirs(DOCS_STORAGE_DIR, exist_ok=True)

# Database Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

INTEGRITY_SERVICE = IntegrityService()

TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"


def now_stamp() -> str:
    return datetime.now().strftime(TIMESTAMP_FMT)


def parse_stamp(value: Optional[str]) -> Optional[datetime]:
    """Parse a stored timestamp, tolerating nulls and any legacy format in the CSV seed."""
    if not value:
        return None
    for fmt in (TIMESTAMP_FMT, "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


# --- ROLES & AUTHENTICATION ---
# Role names are the ones stored in the users table. Anything role-dependent reads the
# role from that table via the session token, never from a client-supplied value.

ROLE_SUPERVISOR = "Supervisor"
ROLE_COURT_OFFICER = "Court Officer"
ROLE_AUDITOR = "Auditor"

# Roles that may read any document in a case without a per-document supervisor grant
PRIVILEGED_READ_ROLES = {ROLE_SUPERVISOR, ROLE_COURT_OFFICER}

SESSION_TTL_HOURS = 8
GRANT_TTL_HOURS = 2


def create_auth_session(db: Session, user: UserDB) -> str:
    """Issue a bearer token and record it server-side so it can be validated later."""
    token = f"AUTH-{uuid.uuid4().hex.upper()}"
    issued = datetime.now()
    db.add(AuthSessionDB(
        token=token,
        user_id=user.user_id,
        created_at=issued.strftime(TIMESTAMP_FMT),
        expires_at=(issued + timedelta(hours=SESSION_TTL_HOURS)).strftime(TIMESTAMP_FMT)
    ))
    return token


def _bearer_token(authorization: Optional[str]) -> Optional[str]:
    header = (authorization or "").strip()
    if not header:
        return None
    if header.lower().startswith("bearer "):
        return header[7:].strip() or None
    return header


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> UserDB:
    """
    Resolve the caller from their bearer token.

    This is the only way a route learns who is calling. Because the user id and role are
    read back from the database via the token, a client cannot claim to be another officer
    or to hold a role it does not have.
    """
    header = (authorization or "").strip()
    token = header[7:].strip() if header.lower().startswith("bearer ") else header
    if not token:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Please sign in."
        )

    session = db.query(AuthSessionDB).filter(AuthSessionDB.token == token).first()
    if not session:
        raise HTTPException(
            status_code=401,
            detail="Session is not valid. Please sign in again."
        )

    expiry = parse_stamp(session.expires_at)
    if expiry and datetime.now() > expiry:
        db.delete(session)
        db.commit()
        raise HTTPException(
            status_code=401,
            detail="Session has expired. Please sign in again."
        )

    user = db.query(UserDB).filter(UserDB.user_id == session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=401,
            detail="The account for this session no longer exists."
        )
    return user


def require_supervisor(user: UserDB = Depends(get_current_user)) -> UserDB:
    """Guard for actions reserved to the Superintendent of Police."""
    if user.role != ROLE_SUPERVISOR:
        raise HTTPException(
            status_code=403,
            detail=(
                f"FORBIDDEN: only a {ROLE_SUPERVISOR} may approve access requests. "
                f"You are signed in as {user.name} ({user.role})."
            )
        )
    return user


def serialize_access_request(req: AccessRequestDB) -> Dict[str, Any]:
    """
    Explicit response shape for an access request.

    Returning the ORM row directly serializes to `{}` once the session has been committed,
    because the commit expires the loaded attributes.
    """
    return {
        "request_id": req.request_id,
        "document_id": req.document_id,
        "requester_id": req.requester_id,
        "requester_name": req.requester_name,
        "requester_role": req.requester_role,
        "requested_action": req.requested_action,
        "purpose_reason": req.purpose_reason,
        "status": req.status,
        "approver_id": req.approver_id,
        "session_token": req.session_token,
        "requested_at": req.requested_at,
        "approved_at": req.approved_at,
        "expires_at": req.expires_at
    }


# --- DOCUMENT AUTHORIZATION ---

def evaluate_document_access(db: Session, doc: DocumentDB, user: UserDB) -> Dict[str, Any]:
    """
    The single authority on whether a user may read a document.

    Every route that exposes document content goes through here, so the viewer, the
    download and the repository badges can never disagree.

    A grant is bound to one officer id: an approval for the investigating officer confers
    nothing on the forensic analyst, even for the same document.
    """
    verdict = {
        "document_id": doc.document_id,
        "user_id": user.user_id,
        "user_role": user.role,
        "classification": doc.classification,
        "allowed": False,
        "reason": "NO_CLEARANCE",
        "message": "",
        "request_id": None,
        "expires_at": None
    }

    if user.role in PRIVILEGED_READ_ROLES:
        verdict.update({
            "allowed": True,
            "reason": "ROLE_PRIVILEGE",
            "message": f"Granted by role: {user.role} has standing access to case material."
        })
        return verdict

    if doc.classification == Classification.PUBLIC.value:
        verdict.update({
            "allowed": True,
            "reason": "PUBLIC_RECORD",
            "message": "This document is a public record."
        })
        return verdict

    grant = db.query(AccessRequestDB).filter(
        AccessRequestDB.document_id == doc.document_id,
        AccessRequestDB.requester_id == user.user_id,
        AccessRequestDB.status == "APPROVED"
    ).first()

    if not grant:
        pending = db.query(AccessRequestDB).filter(
            AccessRequestDB.document_id == doc.document_id,
            AccessRequestDB.requester_id == user.user_id,
            AccessRequestDB.status == "PENDING"
        ).first()

        if pending:
            verdict.update({
                "reason": "PENDING_APPROVAL",
                "request_id": pending.request_id,
                "message": (
                    f"Request {pending.request_id} is awaiting {ROLE_SUPERVISOR} approval."
                )
            })
        else:
            verdict["message"] = (
                f"No approved clearance exists for {user.name} ({user.user_id}) on "
                f"{doc.document_id}. Submit an access request to the {ROLE_SUPERVISOR}."
            )
        return verdict

    # A null expiry means the grant does not lapse (seeded standing clearances)
    expiry = parse_stamp(grant.expires_at)
    if expiry and datetime.now() > expiry:
        verdict.update({
            "reason": "GRANT_EXPIRED",
            "request_id": grant.request_id,
            "expires_at": grant.expires_at,
            "message": (
                f"Clearance {grant.request_id} lapsed at {grant.expires_at}. "
                "Request a fresh approval."
            )
        })
        return verdict

    verdict.update({
        "allowed": True,
        "reason": "SUPERVISOR_GRANT",
        "request_id": grant.request_id,
        "expires_at": grant.expires_at,
        "message": f"Clearance {grant.request_id} approved for {user.name}."
    })
    return verdict


def record_audit(
    db: Session,
    event_type: str,
    actor: UserDB,
    details: str,
    document_id: Optional[str] = None,
    case_id: Optional[str] = None
) -> None:
    db.add(AuditLogDB(
        event_id=next_reference(db, AuditLogDB.event_id, "E"),
        timestamp=now_stamp(),
        event_type=event_type,
        actor_id=actor.user_id,
        actor_name=actor.name,
        document_id=document_id,
        case_id=case_id,
        details=details
    ))


# Physical upload constraints
ALLOWED_UPLOAD_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".docx"}
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


# --- CANONICAL VOCABULARY ---
# The upload form, the seeded CSV dataset, and the external adapters (CCTNS / ICJS / eCourts)
# all spell the same document type differently. Everything is folded onto the DocumentType,
# Classification and RelationshipType enums before it is written, so the provenance graph,
# the node colour legend, and the access rules never disagree about a document's type.

_DOCUMENT_TYPE_KEYWORDS = [
    (("fir", "police report", "first information"), DocumentType.FIR_POLICE_REPORT),
    (("witness", "statement", "deposition"), DocumentType.WITNESS_STATEMENT),
    (("charge",), DocumentType.CHARGE_SHEET),
    (("court", "filing", "order", "judicial", "tribunal"), DocumentType.COURT_SUBMISSION),
    (("forensic", "pathology", "autopsy", "ballistic", "lab"), DocumentType.FORENSIC_REPORT),
    (("evidence", "seizure", "memo", "panchnama"), DocumentType.EVIDENCE_RECORD),
    (("notice", "judgment", "judgement", "summons", "warrant"), DocumentType.LEGAL_NOTICE),
    (("investigation", "case diary"), DocumentType.INVESTIGATION_RECORD),
]


def normalize_document_type(raw: str) -> str:
    """Fold any incoming spelling onto a canonical DocumentType value."""
    text = (raw or "").strip()
    if not text:
        return DocumentType.INVESTIGATION_RECORD.value

    for doc_type in DocumentType:
        if text.lower() == doc_type.value.lower():
            return doc_type.value

    lowered = text.lower()
    for keywords, doc_type in _DOCUMENT_TYPE_KEYWORDS:
        if any(keyword in lowered for keyword in keywords):
            return doc_type.value

    return DocumentType.INVESTIGATION_RECORD.value


def normalize_classification(raw: str) -> str:
    """Fold any incoming spelling onto a canonical Classification value."""
    text = (raw or "").strip()
    for level in Classification:
        if text.lower() == level.value.lower():
            return level.value

    lowered = text.lower()
    if "public" in lowered:
        return Classification.PUBLIC.value
    if "internal" in lowered:
        return Classification.INTERNAL.value
    if any(word in lowered for word in ("highly", "restricted", "secret", "top")):
        return Classification.HIGHLY_CONFIDENTIAL.value
    return Classification.CONFIDENTIAL.value


PII_SCRUBBERS = [
    (re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I), "[REDACTED EMAIL]"),
    (re.compile(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b"), "[REDACTED PHONE]"),
    (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "[REDACTED AADHAAR]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED IP ADDRESS]"),
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), "[REDACTED MAC]"),
    (re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"), "[REDACTED PAN]"),
    (
        re.compile(
            r"\b(Witness|Suspect|Accused|Complainant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+"
        ),
        r"\1 [REDACTED NAME]",
    ),
]


def scrub_pii(text: str) -> str:
    """Replace common personal identifiers with court-safe placeholders."""
    cleaned = text or ""
    for pattern, replacement in PII_SCRUBBERS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def wrap_court_copy(source: DocumentDB, scrubbed_body: str) -> str:
    """Frame the redacted text so a judge can see it is a public copy, not the original."""
    return (
        "COURT-SAFE COPY — PUBLIC RECORD\n"
        "================================================\n"
        f"Source document : {source.document_id} — {source.title}\n"
        f"Source remains  : {source.classification} (unchanged, not attached)\n"
        "Personal identifiers have been removed so this copy may be shown in court.\n"
        "================================================\n\n"
        f"{scrubbed_body}\n\n"
        "================================================\n"
        "The original document was not edited. This copy is linked on the provenance "
        "graph as redacted_from the source above."
    )


def resolve_relationship_type(raw: str) -> str:
    """
    Relationship types come from a fixed dropdown, so an unrecognised value is a caller
    error rather than something to guess at.
    """
    text = (raw or "").strip().lower().replace(" ", "_").replace("-", "_")
    if not text:
        return RelationshipType.DERIVED_FROM.value

    for rel_type in RelationshipType:
        if text == rel_type.value.lower():
            return rel_type.value

    allowed = ", ".join(rel_type.value for rel_type in RelationshipType)
    raise HTTPException(
        status_code=422,
        detail=f"Unknown relationship_type '{raw}'. Allowed values: {allowed}."
    )


def next_reference(db: Session, column, prefix: str, width: int = 3) -> str:
    """
    Allocate the next free `<prefix><number>` primary key.

    Derived from the highest number already present rather than from a row count, so
    references stay unique even when rows have been deleted or seeded out of order.
    """
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+)$")
    taken = set()
    highest = 0

    for (value,) in db.query(column).all():
        text = str(value or "")
        taken.add(text)
        match = pattern.match(text)
        if match:
            highest = max(highest, int(match.group(1)))

    number = highest + 1
    while f"{prefix}{number:0{width}d}" in taken:
        number += 1
    return f"{prefix}{number:0{width}d}"


def build_storage_filename(doc_id: str, title: str, original_name: Optional[str]) -> str:
    """Build a collision-free, traversal-safe filename that keeps the uploaded extension."""
    extension = os.path.splitext(original_name or "")[1].lower()
    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        extension = ".pdf"
    slug = re.sub(r"[^A-Za-z0-9]+", "_", title).strip("_")[:60] or "document"
    return f"{doc_id}_{slug}{extension}"


def parse_parent_ids(parent_doc_ids: Optional[str], parent_doc_id: Optional[str]) -> List[str]:
    """
    Accept parents as a JSON array, a comma-separated list, or the legacy single
    `parent_doc_id` field. Returns de-duplicated ids in the order they were supplied.
    """
    raw_values: List[str] = []

    if parent_doc_ids:
        text = parent_doc_ids.strip()
        if text.startswith("["):
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=422,
                    detail="parent_doc_ids must be a JSON array or a comma-separated list."
                )
            if not isinstance(decoded, list):
                raise HTTPException(
                    status_code=422,
                    detail="parent_doc_ids must be a JSON array or a comma-separated list."
                )
            raw_values.extend(str(value) for value in decoded)
        else:
            raw_values.extend(text.split(","))

    if parent_doc_id:
        raw_values.append(parent_doc_id)

    ordered: List[str] = []
    for value in raw_values:
        cleaned = value.strip()
        if cleaned and cleaned not in ordered:
            ordered.append(cleaned)
    return ordered

def load_graph_engine_from_db(db: Session, case_id: str = "CASE-001") -> ProvenanceGraphEngine:
    db_docs = db.query(DocumentDB).filter(DocumentDB.case_id == case_id).all()
    db_edges = db.query(ProvenanceEdgeDB).filter(ProvenanceEdgeDB.case_id == case_id).all()
    
    docs_dict: Dict[str, DocumentNode] = {}
    for d in db_docs:
        # Same normalisers the upload endpoint writes with, so a document's type and
        # classification read back identically to how they were stored.
        dt = DocumentType(normalize_document_type(d.document_type))
        cl = Classification(normalize_classification(d.classification))

        # Map DB status
        st_raw = str(d.integrity_status).upper()
        if "ISSUE" in st_raw or "FAIL" in st_raw: st = IntegrityStatus.INTEGRITY_ISSUE
        elif "REQUIRED" in st_raw or "WARN" in st_raw: st = IntegrityStatus.REVIEW_REQUIRED
        else: st = IntegrityStatus.VERIFIED

        sig = None
        if d.digital_signature_json:
            try:
                sig_data = json.loads(d.digital_signature_json)
                sig = DigitalSignature(
                    signature_id=f"SIG-{d.document_id}",
                    signer_id=d.created_by,
                    signer_name="Officer " + d.created_by,
                    signer_role="Investigator",
                    certificate_issuer=sig_data.get("certificate_issuer", "C-DAC eSign CA"),
                    certificate_serial="IN-CDAC-9981",
                    signed_at=d.created_at,
                    signed_hash=d.current_hash,
                    is_valid=True
                )
            except:
                pass

        docs_dict[d.document_id] = DocumentNode(
            document_id=d.document_id,
            case_id=d.case_id,
            document_type=dt,
            title=d.title,
            description=d.description or d.title,
            classification=cl,
            creator_id=d.created_by,
            creator_name="Officer " + d.created_by,
            creation_timestamp=d.created_at,
            current_version=d.version or 1,
            integrity_status=st,
            storage_reference=d.file_path or f"/documents/{d.document_id}.pdf",
            current_hash=d.current_hash,
            digital_signature=sig,
            blockchain_block_id=1,
            external_system_source=d.external_system_source,
            content_text=d.content_text
        )

    edges_list: List[ProvenanceEdge] = []
    for e in db_edges:
        try:
            rtype = RelationshipType(e.relationship_type)
        except:
            rtype = RelationshipType.DERIVED_FROM

        edges_list.append(ProvenanceEdge(
            edge_id=e.id,
            source_document_id=e.source_doc_id,
            target_document_id=e.target_doc_id,
            relationship_type=rtype,
            transformation_reason=e.description or rtype.value,
            created_by="SYS",
            created_at=e.created_at
        ))

    return ProvenanceGraphEngine(docs_dict, edges_list)


# --- AUTHENTICATION ENDPOINTS ---

@app.post("/api/auth/login")
def login_user(body: Dict[str, str] = Body(...), db: Session = Depends(get_db)):
    username = body.get("username", "").strip().lower()
    password = body.get("password", "").strip()
    
    user_db = db.query(UserDB).filter(UserDB.username == username).first()
    if not user_db or user_db.hashed_password != password:
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    # Record the session server-side; the client must present this token on every call
    auth_token = create_auth_session(db, user_db)
    db.commit()

    INTEGRITY_SERVICE.log_event(
        event_type="USER_LOGIN",
        actor_id=user_db.user_id,
        actor_name=user_db.name,
        details=f"User {user_db.name} ({user_db.role}) authenticated successfully."
    )
    
    return {
        "status": "SUCCESS",
        "auth_token": auth_token,
        "user": {
            "username": user_db.username,
            "user_id": user_db.user_id,
            "name": user_db.name,
            "role": user_db.role,
            "department": user_db.department,
            "badge_number": user_db.badge_number
        }
    }

@app.post("/api/auth/logout")
def logout_user(
    authorization: Optional[str] = Header(None),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    End the caller's session and revoke the temporary document clearances issued to them.
    The account acted on is the one behind the token, so nobody can log another user out.
    """
    header = (authorization or "").strip()
    token = header[7:].strip() if header.lower().startswith("bearer ") else header
    db.query(AuthSessionDB).filter(AuthSessionDB.token == token).delete(synchronize_session=False)

    revoked = db.query(AccessRequestDB).filter(
        AccessRequestDB.requester_id == user.user_id,
        AccessRequestDB.status == "APPROVED"
    ).all()
    for grant in revoked:
        grant.status = "REVOKED_ON_LOGOUT"
        grant.session_token = None

    db.commit()

    INTEGRITY_SERVICE.log_event(
        event_type="USER_LOGOUT",
        actor_id=user.user_id,
        actor_name=user.name,
        details=(
            f"User {user.name} logged out. {len(revoked)} active document clearance(s) revoked."
        )
    )
    return {
        "status": "SUCCESS",
        "revoked_clearances": len(revoked),
        "message": "Session terminated and active access tokens revoked."
    }


# --- CASE MANAGEMENT ENDPOINTS ---

@app.get("/api/cases")
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(CaseDB).all()
    res = []
    for c in cases:
        total_docs = db.query(DocumentDB).filter(DocumentDB.case_id == c.case_id).count()
        verified = db.query(DocumentDB).filter(DocumentDB.case_id == c.case_id, DocumentDB.integrity_status == "VERIFIED").count()
        warning = db.query(DocumentDB).filter(DocumentDB.case_id == c.case_id, DocumentDB.integrity_status == "REVIEW_REQUIRED").count()
        critical = db.query(DocumentDB).filter(DocumentDB.case_id == c.case_id, DocumentDB.integrity_status == "INTEGRITY_ISSUE").count()
        links = db.query(ProvenanceEdgeDB).filter(ProvenanceEdgeDB.case_id == c.case_id).count()

        res.append({
            "case_id": c.case_id,
            "title": c.case_name,
            "case_type": c.case_type,
            "total_documents": total_docs,
            "provenance_links": links,
            "verified_documents": verified,
            "review_required_documents": warning,
            "integrity_issues": critical
        })
    return res

@app.get("/api/cases/{case_id}/graph")
def get_case_provenance_graph(case_id: str, db: Session = Depends(get_db)):
    """Fetch DAG nodes, edges, and case summary for dynamic tree layout."""
    engine = load_graph_engine_from_db(db, case_id)
    return engine.get_graph_data(case_id)


# --- DOCUMENT REPOSITORY & PHYSICAL FILE UPLOAD ---

@app.get("/api/documents/search")
def search_documents(
    q: str = Query(..., min_length=1),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Search the repository.

    Catalogue fields (id, title, type, classification) are searchable for everyone, so an
    officer can see that a restricted document exists and request clearance for it. The
    document body and hash are only searched for documents the caller may actually read —
    otherwise a keyword search would be an oracle over content they are not cleared for.
    """
    query_str = f"%{q.strip()}%"

    catalogue_match = db.query(DocumentDB).filter(
        (DocumentDB.document_id.like(query_str)) |
        (DocumentDB.title.like(query_str)) |
        (DocumentDB.description.like(query_str)) |
        (DocumentDB.document_type.like(query_str))
    ).all()

    body_match = db.query(DocumentDB).filter(
        (DocumentDB.content_text.like(query_str)) |
        (DocumentDB.current_hash.like(query_str))
    ).all()

    results: Dict[str, Dict[str, Any]] = {}
    for doc in catalogue_match + body_match:
        if doc.document_id in results:
            continue

        verdict = evaluate_document_access(db, doc, user)
        matched_catalogue = doc in catalogue_match
        if not matched_catalogue and not verdict["allowed"]:
            # Only the protected body matched, and this caller may not read it
            continue

        results[doc.document_id] = {
            "document_id": doc.document_id,
            "case_id": doc.case_id,
            "document_type": doc.document_type,
            "title": doc.title,
            "description": doc.description,
            "classification": doc.classification,
            "current_hash": doc.current_hash if verdict["allowed"] else None,
            "integrity_status": doc.integrity_status,
            "created_at": doc.created_at,
            "file_path": doc.file_path,
            "digital_signature": True if doc.digital_signature_json else False,
            "access_allowed": verdict["allowed"],
            "access_reason": verdict["reason"]
        }

    documents = sorted(results.values(), key=lambda row: row["document_id"])
    return {
        "query": q,
        "total_results": len(documents),
        "documents": documents
    }

@app.get("/api/documents/{doc_id}")
def get_document_details(
    doc_id: str,
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Full record for the document drawer.

    The provenance, custody and integrity metadata is what makes this system useful and is
    returned to any signed-in officer. The document body is withheld unless the caller is
    cleared for it, so the drawer cannot be used to read around the permission gate.
    """
    d = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not d:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    access = evaluate_document_access(db, d, user)

    engine = load_graph_engine_from_db(db, d.case_id)
    origin_info = engine.trace_origin(doc_id)
    impact_info = engine.analyze_downstream_impact(doc_id)
    
    block = db.query(BlockchainBlockDB).filter(BlockchainBlockDB.document_id == doc_id).first()
    audit_logs = db.query(AuditLogDB).filter(AuditLogDB.document_id == doc_id).order_by(AuditLogDB.timestamp.desc()).all()
    versions = db.query(VersionDB).filter(VersionDB.document_id == doc_id).all()

    return {
        "document": {
            "document_id": d.document_id,
            "case_id": d.case_id,
            "document_type": d.document_type,
            "title": d.title,
            "description": d.description,
            "classification": d.classification,
            "content_text": d.content_text if access["allowed"] else None,
            "current_hash": d.current_hash if access["allowed"] else None,
            "integrity_status": d.integrity_status,
            "created_at": d.created_at,
            "created_by": d.created_by,
            "version": d.version,
            "file_path": d.file_path,
            "digital_signature": json.loads(d.digital_signature_json) if d.digital_signature_json else None
        },
        "blockchain_block": block,
        "versions": versions,
        "ancestors": origin_info.get("ancestors", []),
        "direct_dependents": impact_info.get("direct_dependents", []),
        "indirect_dependents": impact_info.get("indirect_dependents", []),
        "total_affected_count": impact_info.get("total_affected_count", 0),
        "audit_logs": audit_logs,
        "access": access
    }

@app.get("/api/vocabulary")
def get_controlled_vocabulary():
    """
    Controlled vocabulary for the upload form and the graph legend, so the UI dropdowns
    and the server-side normalisation are driven by the same list.
    """
    return {
        "document_types": [doc_type.value for doc_type in DocumentType],
        "classifications": [level.value for level in Classification],
        "relationship_types": [rel_type.value for rel_type in RelationshipType],
        "allowed_file_extensions": sorted(ALLOWED_UPLOAD_EXTENSIONS),
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        # Published so the UI can label documents consistently with the server's rules
        # instead of keeping its own copy of the role list.
        "privileged_read_roles": sorted(PRIVILEGED_READ_ROLES),
        "public_classification": Classification.PUBLIC.value
    }


@app.get("/api/cases/{case_id}/documents")
def list_case_documents(case_id: str, db: Session = Depends(get_db)):
    """Lightweight document list for the parent-document picker on the upload form."""
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    docs = db.query(DocumentDB).filter(
        DocumentDB.case_id == case_id
    ).order_by(DocumentDB.document_id.asc()).all()

    return [
        {
            "document_id": d.document_id,
            "title": d.title,
            "document_type": d.document_type,
            "classification": d.classification,
            "integrity_status": d.integrity_status
        } for d in docs
    ]


@app.post("/api/documents/upload")
async def upload_new_document(
    case_id: str = Form(...),
    document_type: str = Form(...),
    title: str = Form(""),
    description: str = Form(""),
    classification: str = Form("Confidential"),
    content_text: Optional[str] = Form(None),
    parent_doc_id: Optional[str] = Form(None),
    parent_doc_ids: Optional[str] = Form(None),
    relationship_type: str = Form("derived_from"),
    file: Optional[UploadFile] = File(None),
    uploader: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Digitise a document and attach it to the case provenance graph as a new node.

    Performs, in one transaction:
      - validation of the case, the controlled vocabulary, and every parent document
      - SHA-256 hashing of the uploaded bytes (or of the typed text when no file is sent)
      - physical storage under dataset/documents/ with a traversal-safe filename
      - an eSign PKI signature record and a new block on the verification ledger
      - one provenance edge per parent, giving the new node its place in the DAG
      - an audit trail entry

    Returns the created document together with the graph node and edges in exactly the
    shape /api/cases/{case_id}/graph uses, so the client can draw the new node
    without refetching the whole case.
    """
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found.")

    # --- Validate the controlled vocabulary ---
    canonical_type = normalize_document_type(document_type)
    canonical_class = normalize_classification(classification)
    canonical_relationship = resolve_relationship_type(relationship_type)

    # --- Resolve the title (falls back to the uploaded filename) ---
    clean_title = (title or "").strip()
    if not clean_title and file and file.filename:
        clean_title = os.path.splitext(os.path.basename(file.filename))[0].strip()
    if not clean_title:
        raise HTTPException(
            status_code=422,
            detail="A document title is required when no file is attached."
        )

    # --- Validate parents: they must exist and belong to this same case ---
    parent_ids = parse_parent_ids(parent_doc_ids, parent_doc_id)
    parents_by_id: Dict[str, DocumentDB] = {}
    if parent_ids:
        found = db.query(DocumentDB).filter(DocumentDB.document_id.in_(parent_ids)).all()
        parents_by_id = {d.document_id: d for d in found}

        missing = [pid for pid in parent_ids if pid not in parents_by_id]
        if missing:
            raise HTTPException(
                status_code=422,
                detail=f"Parent document(s) not found: {', '.join(missing)}."
            )

        foreign = [pid for pid in parent_ids if parents_by_id[pid].case_id != case_id]
        if foreign:
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Parent document(s) {', '.join(foreign)} belong to a different case. "
                    "Provenance edges cannot cross case boundaries."
                )
            )

    # --- Read and validate the physical file ---
    file_bytes: Optional[bytes] = None
    if file and file.filename:
        extension = os.path.splitext(file.filename)[1].lower()
        if extension not in ALLOWED_UPLOAD_EXTENSIONS:
            raise HTTPException(
                status_code=415,
                detail=(
                    f"Unsupported file type '{extension}'. "
                    f"Allowed: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}."
                )
            )
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(status_code=422, detail="The attached file is empty.")
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit."
            )

    doc_id = next_reference(db, DocumentDB.document_id, "DOC-")
    saved_file_name = build_storage_filename(
        doc_id, clean_title, file.filename if file else None
    )
    saved_file_path = os.path.join(DOCS_STORAGE_DIR, saved_file_name)
    relative_path = f"/documents/{saved_file_name}"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    extracted_text = (content_text or "").strip()

    if file_bytes is not None:
        content_hash = hashlib.sha256(file_bytes).hexdigest()
        with open(saved_file_path, "wb") as f_out:
            f_out.write(file_bytes)

        # Prefer text extracted from the PDF over the typed override
        if file.filename.lower().endswith(".pdf") and pypdf:
            try:
                reader = pypdf.PdfReader(saved_file_path)
                pdf_text = "\n".join(
                    page.extract_text() for page in reader.pages if page.extract_text()
                )
                if pdf_text.strip():
                    extracted_text = pdf_text
            except Exception as pdf_error:
                print(f"PDF text extraction note: {pdf_error}")
    else:
        extracted_text = extracted_text or f"Official legal record for {clean_title}. Case ID: {case_id}."
        content_hash = hashlib.sha256(extracted_text.encode()).hexdigest()
        with open(saved_file_path, "w") as f_out:
            f_out.write(extracted_text)

    # The uploader is the authenticated caller, so the custody chain and the eSign
    # signature always name the officer who actually filed the document.
    user_id = uploader.user_id
    officer_name = uploader.name

    # --- eSign PKI signature ---
    sig_json = json.dumps({
        "signature_id": f"SIG-{doc_id}",
        "signer_id": user_id,
        "signer_name": officer_name,
        "certificate_issuer": "National Informatics Centre (NIC) eSign Portal",
        "certificate_serial": f"IN-NIC-{uuid.uuid4().hex[:8].upper()}",
        "signed_at": timestamp,
        "signed_hash": content_hash,
        "is_valid": True
    })

    # --- Blockchain commitment ---
    last_block = db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.desc()).first()
    prev_hash = last_block.block_hash if last_block else "0" * 64
    block_num = (last_block.block_number + 1) if last_block else 1
    block_hash = hashlib.sha256((prev_hash + content_hash + str(block_num)).encode()).hexdigest()

    db.add(BlockchainBlockDB(
        block_number=block_num,
        tx_id=f"TX-NCRB-{block_num:04d}",
        timestamp=timestamp,
        action="DOCUMENT_ESIGNED_UPLOAD",
        document_id=doc_id,
        previous_hash=prev_hash,
        block_hash=block_hash,
        merkle_root=content_hash[:32]
    ))

    db.add(DocumentDB(
        document_id=doc_id,
        case_id=case_id,
        document_type=canonical_type,
        title=clean_title,
        description=(description or "").strip() or clean_title,
        classification=canonical_class,
        content_text=extracted_text,
        current_hash=content_hash,
        integrity_status="VERIFIED",
        created_at=timestamp,
        created_by=user_id,
        version=1,
        file_path=relative_path,
        hash_algorithm="SHA-256",
        external_system_source="NCRB Portal Upload",
        digital_signature_json=sig_json
    ))

    db.add(VersionDB(
        version_id=f"V-{doc_id}-v1",
        document_id=doc_id,
        version=1,
        hash=content_hash,
        created_by=user_id,
        created_at=timestamp,
        status="Current",
        file_path=relative_path
    ))
    db.flush()

    # --- One provenance edge per parent: this is what places the node in the DAG ---
    created_edge_ids: List[str] = []
    for parent_id in parent_ids:
        edge_id = next_reference(db, ProvenanceEdgeDB.id, "R")
        db.add(ProvenanceEdgeDB(
            id=edge_id,
            case_id=case_id,
            source_doc_id=parent_id,
            target_doc_id=doc_id,
            relationship_type=canonical_relationship,
            description=(
                f"{clean_title} recorded as {canonical_relationship.replace('_', ' ')} "
                f"{parent_id} ({parents_by_id[parent_id].title})."
            ),
            created_at=timestamp
        ))
        db.flush()
        created_edge_ids.append(edge_id)

    lineage_note = (
        f" Linked as {canonical_relationship} of {', '.join(parent_ids)}."
        if parent_ids else " Recorded as a new root document with no parent."
    )
    db.add(AuditLogDB(
        event_id=next_reference(db, AuditLogDB.event_id, "E"),
        timestamp=timestamp,
        event_type="UPLOADED",
        actor_id=user_id,
        actor_name=officer_name,
        document_id=doc_id,
        case_id=case_id,
        details=(
            f"Uploaded & eSigned {canonical_type} '{clean_title}' as {saved_file_name}. "
            f"Blockchain block #{block_num} committed.{lineage_note}"
        )
    ))

    db.commit()

    # Read the node and its edges back through the graph engine so the payload is
    # byte-for-byte the same shape the graph endpoint returns.
    graph = load_graph_engine_from_db(db, case_id).get_graph_data(case_id)
    new_node = next((n for n in graph["nodes"] if n["document_id"] == doc_id), None)
    new_edges = [link for link in graph["links"] if link["id"] in created_edge_ids]

    return {
        "status": "SUCCESS",
        "document_id": doc_id,
        "document_type": canonical_type,
        "classification": canonical_class,
        "title": clean_title,
        "file_path": relative_path,
        "hash": content_hash,
        "blockchain_block": block_num,
        "parent_document_ids": parent_ids,
        "relationship_type": canonical_relationship,
        "node": new_node,
        "edges": new_edges,
        "case": graph["case"]
    }


@app.post("/api/documents/{doc_id}/redact")
def create_court_copy(
    doc_id: str,
    body: Dict[str, Any] = Body(default={}),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a public court copy of a confidential document.

    The original is never edited. A new Public Record node is added to the same case and
    linked with redacted_from, so a judge can open the copy without seeing names, phones,
    IP addresses or other personal identifiers.
    """
    source = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not source:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    verdict = evaluate_document_access(db, source, user)
    if not verdict["allowed"]:
        raise HTTPException(
            status_code=403,
            detail=(
                f"FORBIDDEN: {verdict['message']} "
                "You must be cleared for the original before you can prepare a court copy."
            )
        )

    submitted = (body.get("redacted_content") or "").strip()
    working_text = submitted or (source.content_text or "")
    scrubbed = scrub_pii(working_text)
    if not scrubbed:
        raise HTTPException(
            status_code=422,
            detail="There is no text to place in the court copy."
        )

    court_text = wrap_court_copy(source, scrubbed)
    timestamp = now_stamp()
    new_id = next_reference(db, DocumentDB.document_id, "DOC-")
    title = f"Court Copy — {source.title}"
    saved_file_name = build_storage_filename(new_id, title, f"{new_id}.txt")
    saved_file_path = os.path.join(DOCS_STORAGE_DIR, saved_file_name)
    relative_path = f"/documents/{saved_file_name}"
    content_hash = hashlib.sha256(court_text.encode()).hexdigest()

    with open(saved_file_path, "w") as f_out:
        f_out.write(court_text)

    sig_json = json.dumps({
        "signature_id": f"SIG-{new_id}",
        "signer_id": user.user_id,
        "signer_name": user.name,
        "certificate_issuer": "National Informatics Centre (NIC) eSign Portal",
        "certificate_serial": f"IN-NIC-{uuid.uuid4().hex[:8].upper()}",
        "signed_at": timestamp,
        "signed_hash": content_hash,
        "is_valid": True
    })

    last_block = db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.desc()).first()
    prev_hash = last_block.block_hash if last_block else "0" * 64
    block_num = (last_block.block_number + 1) if last_block else 1
    block_hash = hashlib.sha256((prev_hash + content_hash + str(block_num)).encode()).hexdigest()

    db.add(BlockchainBlockDB(
        block_number=block_num,
        tx_id=f"TX-NCRB-{block_num:04d}",
        timestamp=timestamp,
        action="PII_REDACTED_COURT_COPY",
        document_id=new_id,
        previous_hash=prev_hash,
        block_hash=block_hash,
        merkle_root=content_hash[:32]
    ))

    db.add(DocumentDB(
        document_id=new_id,
        case_id=source.case_id,
        document_type=source.document_type,
        title=title,
        description=(
            f"Public court copy of {source.document_id}. Personal identifiers removed. "
            f"Original remains {source.classification}."
        ),
        classification=Classification.PUBLIC.value,
        content_text=court_text,
        current_hash=content_hash,
        integrity_status="VERIFIED",
        created_at=timestamp,
        created_by=user.user_id,
        version=1,
        file_path=relative_path,
        hash_algorithm="SHA-256",
        external_system_source="Court Copy / PII Redaction",
        digital_signature_json=sig_json
    ))

    db.add(VersionDB(
        version_id=f"V-{new_id}-v1",
        document_id=new_id,
        version=1,
        hash=content_hash,
        created_by=user.user_id,
        created_at=timestamp,
        status="Current",
        file_path=relative_path
    ))
    db.flush()

    edge_id = next_reference(db, ProvenanceEdgeDB.id, "R")
    db.add(ProvenanceEdgeDB(
        id=edge_id,
        case_id=source.case_id,
        source_doc_id=source.document_id,
        target_doc_id=new_id,
        relationship_type=RelationshipType.REDACTED_FROM.value,
        description=(
            f"Court-safe public copy of {source.document_id}. "
            "Personal identifiers removed; original not altered."
        ),
        created_at=timestamp
    ))

    record_audit(
        db,
        event_type="COURT_COPY_CREATED",
        actor=user,
        document_id=new_id,
        case_id=source.case_id,
        details=(
            f"{user.name} prepared public court copy {new_id} from {source.document_id}. "
            f"Linked as redacted_from. Original classification {source.classification} unchanged."
        )
    )
    db.commit()

    graph = load_graph_engine_from_db(db, source.case_id).get_graph_data(source.case_id)
    new_node = next((n for n in graph["nodes"] if n["document_id"] == new_id), None)
    new_edges = [link for link in graph["links"] if link["id"] == edge_id]

    return {
        "status": "SUCCESS",
        "message": (
            f"Public court copy {new_id} created. A judge can open it without clearance. "
            f"The original {source.document_id} is unchanged."
        ),
        "source_document_id": source.document_id,
        "new_document": {
            "document_id": new_id,
            "title": title,
            "classification": Classification.PUBLIC.value,
            "content_text": court_text
        },
        "provenance_edge": {
            "id": edge_id,
            "source_document_id": source.document_id,
            "target_document_id": new_id,
            "relationship_type": RelationshipType.REDACTED_FROM.value
        },
        "node": new_node,
        "edges": new_edges,
        "case": graph["case"]
    }


# --- WHAT-IF IMPACT (does not write to the database) ---

@app.post("/api/simulation/impact")
def simulate_counterfactual_impact(
    body: Dict[str, Any] = Body(...),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Preview what would happen if this document were compromised.

    Walks the provenance graph downstream and reports which later documents would need
    review. Nothing is written: real integrity flags stay as they are.
    """
    doc_id = (body.get("document_id") or "").strip()
    action = (body.get("action") or "INTEGRITY_FAILURE").strip() or "INTEGRITY_FAILURE"

    source = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not source:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    engine = load_graph_engine_from_db(db, source.case_id)
    simulation = engine.simulate_impact(doc_id, action)
    if simulation.get("error"):
        raise HTTPException(status_code=404, detail=simulation["error"])

    titles = {doc.document_id: doc.title for doc in engine.documents.values()}
    enriched = {}
    for node_id, info in simulation.get("simulated_nodes", {}).items():
        row = dict(info)
        row["title"] = titles.get(node_id, node_id)
        row["document_id"] = node_id
        enriched[node_id] = row
    simulation["simulated_nodes"] = enriched
    simulation["source_title"] = source.title
    simulation["source_classification"] = source.classification
    simulation["message"] = (
        f"If {doc_id} were compromised, {simulation['affected_summary']['total_affected']} "
        "later document(s) would need review. No records were changed."
    )
    return simulation


@app.get("/api/documents/{doc_id}/explain-impact")
def explain_document_impact(
    doc_id: str,
    source_id: Optional[str] = Query(None),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Explain why a document is flagged, by walking back to the compromised source."""
    target = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not target:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    engine = load_graph_engine_from_db(db, target.case_id)
    return engine.explain_impact(doc_id, source_id)


# --- TAMPER SIMULATION & INTEGRITY ENDPOINTS ---

@app.post("/api/documents/{doc_id}/trigger-tamper")
def trigger_tamper_demo(doc_id: str, db: Session = Depends(get_db)):
    d = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Document not found")
        
    # Inject tamper bytes into content hash
    d.current_hash = hashlib.sha256((d.content_text + "_TAMPERED_MALICIOUS_BYTES").encode()).hexdigest()
    d.integrity_status = "INTEGRITY_ISSUE"
    db.commit()

    # Traverse downstream lineage using Graph Engine
    engine = load_graph_engine_from_db(db, d.case_id)
    impact = engine.analyze_downstream_impact(doc_id)
    
    affected_ids = impact.get("affected_node_ids", [])
    for aff_id in affected_ids:
        aff_doc = db.query(DocumentDB).filter(DocumentDB.document_id == aff_id).first()
        if aff_doc and aff_doc.integrity_status != "INTEGRITY_ISSUE":
            aff_doc.integrity_status = "REVIEW_REQUIRED"
    db.commit()

    db.add(IntegrityEventDB(
        event_id=f"INT-{uuid.uuid4().hex[:6].upper()}",
        document_id=doc_id,
        expected_hash=d.current_hash,
        actual_hash="TAMPERED_UNAUTHORIZED_HASH",
        result="FAIL",
        detected_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "tampered_doc": doc_id,
        "affected_downstream_count": len(affected_ids),
        "affected_nodes": affected_ids
    }

@app.post("/api/documents/{doc_id}/reset-tamper")
def reset_tamper_demo(doc_id: str, db: Session = Depends(get_db)):
    d = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Document not found")
        
    d.current_hash = hashlib.sha256(d.content_text.encode()).hexdigest()
    d.integrity_status = "VERIFIED"
    
    # Reset downstream documents if no other compromised parent
    case_docs = db.query(DocumentDB).filter(DocumentDB.case_id == d.case_id).all()
    for cd in case_docs:
        cd.integrity_status = "VERIFIED"
        cd.current_hash = hashlib.sha256(cd.content_text.encode()).hexdigest()
        
    db.commit()
    return {"status": "SUCCESS", "message": f"Document {doc_id} and downstream lineage restored to pristine verified state."}


# --- ACCESS CONTROL & SUPERVISOR QUEUE ---

@app.get("/api/access-requests")
def list_access_requests(
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List access requests scoped to the caller.

    A Supervisor sees the whole approval queue because that is their job. Everyone else
    sees only their own requests — an officer must never receive another officer's
    clearances, or the UI would show one user's approval as if it were their own.
    """
    query = db.query(AccessRequestDB)
    if user.role != ROLE_SUPERVISOR:
        query = query.filter(AccessRequestDB.requester_id == user.user_id)
    return [serialize_access_request(req) for req in query.order_by(AccessRequestDB.request_id.asc()).all()]


@app.post("/api/access-requests")
def request_sensitive_access(
    body: Dict[str, Any] = Body(...),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Raise a clearance request for a document. The requester is taken from the session
    token, so a caller cannot file a request in another officer's name.
    """
    doc_id = body.get("document_id")
    doc = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    action = body.get("requested_action", "VIEW")
    purpose = (body.get("purpose_reason") or "").strip() or "Official case investigation review"

    existing = db.query(AccessRequestDB).filter(
        AccessRequestDB.document_id == doc_id,
        AccessRequestDB.requester_id == user.user_id,
        AccessRequestDB.status.in_(["PENDING", "APPROVED"])
    ).first()
    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"You already have a {existing.status.lower()} request "
                f"({existing.request_id}) for {doc_id}."
            )
        )

    new_req = AccessRequestDB(
        request_id=next_reference(db, AccessRequestDB.request_id, "AR-"),
        document_id=doc_id,
        requester_id=user.user_id,
        requester_name=user.name,
        requester_role=user.role,
        requested_action=action,
        purpose_reason=purpose,
        status="PENDING",
        requested_at=now_stamp()
    )
    db.add(new_req)
    db.flush()

    record_audit(
        db,
        event_type="ACCESS_REQUESTED",
        actor=user,
        document_id=doc_id,
        case_id=doc.case_id,
        details=(
            f"{user.name} ({user.role}) requested {action} access to {doc_id}. "
            f"Purpose: {purpose}"
        )
    )
    db.commit()
    return serialize_access_request(new_req)


@app.post("/api/access-requests/{req_id}/approve")
def approve_access_request(
    req_id: str,
    approver: UserDB = Depends(require_supervisor),
    db: Session = Depends(get_db)
):
    """
    Approve a clearance. Reserved to the Supervisor by dependency, so the check cannot be
    bypassed by posting a different approver id in the body.
    """
    req = db.query(AccessRequestDB).filter(AccessRequestDB.request_id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail=f"Access request '{req_id}' not found.")

    if req.status == "APPROVED":
        raise HTTPException(
            status_code=409,
            detail=f"Request {req_id} has already been approved."
        )

    granted_at = datetime.now()
    req.status = "APPROVED"
    req.approver_id = approver.user_id
    req.approved_at = granted_at.strftime(TIMESTAMP_FMT)
    req.session_token = f"TOK-SECURE-{uuid.uuid4().hex[:12].upper()}"
    req.expires_at = (granted_at + timedelta(hours=GRANT_TTL_HOURS)).strftime(TIMESTAMP_FMT)

    record_audit(
        db,
        event_type="ACCESS_APPROVED",
        actor=approver,
        document_id=req.document_id,
        details=(
            f"{approver.name} approved {req_id}, granting {req.requester_name} "
            f"({req.requester_id}) access to {req.document_id} until {req.expires_at}. "
            "This clearance applies to that officer only."
        )
    )
    db.commit()
    return serialize_access_request(req)


from fastapi.responses import FileResponse, Response
from backend.watermark import stamp_file_for_preview


@app.get("/api/documents/{doc_id}/access-check")
def check_document_access(
    doc_id: str,
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Report whether the caller may read this document. The client uses this to decide what
    to show, but it is advisory only — the preview route re-checks independently.
    """
    doc = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")
    return evaluate_document_access(db, doc, user)


INLINE_MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".txt": "text/plain; charset=utf-8"
}


@app.get("/api/documents/{doc_id}/preview")
def preview_document(
    doc_id: str,
    authorization: Optional[str] = Header(None),
    user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Stream a *session-watermarked* copy of the document for the secure viewer.

    The stored original on disk is never modified. The stamp (officer, badge, case,
    session / grant id, timestamp) is burned into the PDF/image bytes before they
    leave the server, so DevTools cannot strip a DOM overlay and a photographed or
    downloaded preview remains attributable. Access is re-checked on every call.
    """
    doc = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail=f"Document '{doc_id}' not found.")

    verdict = evaluate_document_access(db, doc, user)
    if not verdict["allowed"]:
        record_audit(
            db,
            event_type="PREVIEW_DENIED",
            actor=user,
            document_id=doc_id,
            case_id=doc.case_id,
            details=(
                f"Secure preview of {doc_id} refused for {user.name} ({user.role}). "
                f"Reason: {verdict['reason']}."
            )
        )
        db.commit()
        raise HTTPException(status_code=403, detail=f"FORBIDDEN: {verdict['message']}")

    file_name = os.path.basename(doc.file_path) if doc.file_path else f"{doc_id}.pdf"
    physical_path = os.path.join(DOCS_STORAGE_DIR, file_name)

    if not os.path.exists(physical_path):
        raise HTTPException(
            status_code=404,
            detail=(
                f"No original file is stored on the server for {doc_id}. "
                "The secure viewer will show the extracted text instead."
            )
        )

    extension = os.path.splitext(physical_path)[1].lower()
    try:
        payload, media_type, stamped_name = stamp_file_for_preview(
            physical_path=physical_path,
            extension=extension,
            user=user,
            doc=doc,
            verdict=verdict,
            session_token=_bearer_token(authorization),
        )
    except ValueError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to apply TraceX session watermark: {exc}"
        ) from exc

    record_audit(
        db,
        event_type="DOCUMENT_PREVIEWED",
        actor=user,
        document_id=doc_id,
        case_id=doc.case_id,
        details=(
            f"{user.name} ({user.role}) opened {doc_id} ({doc.title}) in the controlled "
            f"secure viewer with server-side session watermark. "
            f"Authorised by: {verdict['reason']}."
        )
    )
    db.commit()

    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{stamped_name}"',
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "X-TraceX-Watermark": "session-bound",
            "X-Content-Type-Options": "nosniff",
        },
    )


# --- INTEGRITY VERIFICATION ---

@app.post("/api/documents/{doc_id}/verify-integrity")
def verify_document_integrity(doc_id: str, db: Session = Depends(get_db)):
    """Recalculates the SHA-256 hash of the stored content and compares to the recorded hash."""
    doc = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    calculated = hashlib.sha256(doc.content_text.encode()).hexdigest()
    match = (calculated == doc.current_hash)

    if match:
        doc.integrity_status = "VERIFIED"
    else:
        doc.integrity_status = "INTEGRITY_ISSUE"
    db.commit()

    return {
        "status": "VERIFIED" if match else "MISMATCH",
        "document_id": doc_id,
        "calculated_hash": calculated,
        "recorded_hash": doc.current_hash,
        "integrity_match": match
    }


@app.get("/api/blockchain")
def list_blockchain_ledger(db: Session = Depends(get_db)):
    return db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.asc()).all()


@app.get("/api/blockchain/verify")
def verify_blockchain_ledger(db: Session = Depends(get_db)):
    """
    Walk the ledger and confirm every block still points at its predecessor's hash.
    A single edited row breaks the link and is reported with the offending block number.
    """
    blocks = db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.asc()).all()

    broken_links: List[Dict[str, Any]] = []
    previous = None
    for block in blocks:
        if previous is not None and block.previous_hash != previous.block_hash:
            broken_links.append({
                "block_number": block.block_number,
                "document_id": block.document_id,
                "expected_previous_hash": previous.block_hash,
                "recorded_previous_hash": block.previous_hash
            })
        previous = block

    verified = not broken_links
    return {
        "verified": verified,
        "chain_status": "INTACT" if verified else "CORRUPTED",
        "total_blocks": len(blocks),
        "broken_links": broken_links,
        "message": (
            f"All {len(blocks)} blocks are correctly chained."
            if verified else
            f"{len(broken_links)} block(s) no longer match the preceding hash."
        )
    }

@app.get("/api/assets")
def list_police_assets(db: Session = Depends(get_db)):
    return db.query(PoliceAssetDB).all()

@app.get("/api/audit")
def list_audit_trail(db: Session = Depends(get_db)):
    return db.query(AuditLogDB).order_by(AuditLogDB.timestamp.desc()).all()


# --- STATIC FILES & HTML FRONTEND MOUNT ---
STATIC_DIR = os.path.join(BASE_DIR, "static")
if os.path.exists(STATIC_DIR):
    app.mount("/css", StaticFiles(directory=os.path.join(STATIC_DIR, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(STATIC_DIR, "js")), name="js")
    
    @app.get("/")
    def read_root():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"))

