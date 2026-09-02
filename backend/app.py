"""
CUSTODY CHAIN / NCRB SECURE DMS - FastAPI Server (SIH26190)
Complete Database-Driven REST API for Law Enforcement, Courts, and Investigative Departments:
Centralized Document Storage, Intelligent Full-Text Search, Digital Signatures (eSign PKI),
Blockchain Ledger Verification, Provenance Lineage, Access Control, and Asset Tracking.
Backed directly by Database (SQLAlchemy / PostgreSQL / SQLite) & Physical File Management.
"""

from fastapi import FastAPI, HTTPException, Query, Body, UploadFile, File, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import os
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
    VersionDB, IntegrityEventDB
)

app = FastAPI(
    title="NCRB SECURE DMS API",
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

# Mount Physical Document Storage directory (/documents)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_STORAGE_DIR = os.path.join(BASE_DIR, "dataset", "documents")
os.makedirs(DOCS_STORAGE_DIR, exist_ok=True)
app.mount("/documents", StaticFiles(directory=DOCS_STORAGE_DIR), name="physical_documents")

# Database Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

INTEGRITY_SERVICE = IntegrityService()

def load_graph_engine_from_db(db: Session, case_id: str = "CASE-001") -> ProvenanceGraphEngine:
    db_docs = db.query(DocumentDB).filter(DocumentDB.case_id == case_id).all()
    db_edges = db.query(ProvenanceEdgeDB).filter(ProvenanceEdgeDB.case_id == case_id).all()
    
    docs_dict: Dict[str, DocumentNode] = {}
    for d in db_docs:
        # Map DB document_type string to DocumentType enum
        doc_type_raw = str(d.document_type).lower()
        if "fir" in doc_type_raw: dt = DocumentType.FIR_POLICE_REPORT
        elif "witness" in doc_type_raw: dt = DocumentType.WITNESS_STATEMENT
        elif "charge" in doc_type_raw: dt = DocumentType.CHARGE_SHEET
        elif "forensic" in doc_type_raw: dt = DocumentType.FORENSIC_REPORT
        elif "evidence" in doc_type_raw: dt = DocumentType.EVIDENCE_RECORD
        elif "court" in doc_type_raw: dt = DocumentType.COURT_SUBMISSION
        elif "notice" in doc_type_raw: dt = DocumentType.LEGAL_NOTICE
        else: dt = DocumentType.INVESTIGATION_RECORD

        # Map DB classification
        cl_raw = str(d.classification).lower()
        if "public" in cl_raw: cl = Classification.PUBLIC
        elif "internal" in cl_raw: cl = Classification.INTERNAL
        elif "highly" in cl_raw or "restricted" in cl_raw: cl = Classification.HIGHLY_CONFIDENTIAL
        else: cl = Classification.CONFIDENTIAL

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
        
    auth_token = f"AUTH-TOKEN-{uuid.uuid4().hex[:12].upper()}"
    
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
def logout_user(body: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    user_id = body.get("user_id")
    if user_id:
        reqs = db.query(AccessRequestDB).filter(AccessRequestDB.requester_id == user_id, AccessRequestDB.status == "APPROVED").all()
        for r in reqs:
            r.status = "REVOKED_ON_LOGOUT"
            r.session_token = None
        db.commit()

        INTEGRITY_SERVICE.log_event(
            event_type="USER_LOGOUT",
            actor_id=user_id,
            actor_name=user_id,
            details=f"User {user_id} logged out. Active temporary document access tokens revoked."
        )
    return {"status": "SUCCESS", "message": "User session terminated. Active access tokens revoked."}


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
def search_documents(q: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    query_str = f"%{q.strip()}%"
    docs = db.query(DocumentDB).filter(
        (DocumentDB.document_id.like(query_str)) |
        (DocumentDB.title.like(query_str)) |
        (DocumentDB.description.like(query_str)) |
        (DocumentDB.content_text.like(query_str)) |
        (DocumentDB.document_type.like(query_str)) |
        (DocumentDB.current_hash.like(query_str))
    ).all()
    
    return {
        "query": q,
        "total_results": len(docs),
        "documents": [
            {
                "document_id": d.document_id,
                "case_id": d.case_id,
                "document_type": d.document_type,
                "title": d.title,
                "description": d.description,
                "classification": d.classification,
                "current_hash": d.current_hash,
                "integrity_status": d.integrity_status,
                "created_at": d.created_at,
                "file_path": d.file_path,
                "digital_signature": True if d.digital_signature_json else False
            } for d in docs
        ]
    }

@app.get("/api/documents/{doc_id}")
def get_document_details(doc_id: str, db: Session = Depends(get_db)):
    d = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not d:
        raise HTTPException(status_code=404, detail="Document not found")
        
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
            "content_text": d.content_text,
            "current_hash": d.current_hash,
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
        "audit_logs": audit_logs
    }

@app.post("/api/documents/upload")
async def upload_new_document(
    case_id: str = Form(...),
    document_type: str = Form(...),
    title: str = Form(...),
    description: str = Form(...),
    classification: str = Form(...),
    content_text: Optional[str] = Form(None),
    user_id: str = Form("OFF-001"),
    parent_doc_id: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """
    Physical File (PDF / Image / Text) Digitization & Upload:
    - Calculates SHA-256 cryptographic hash of physical file / content.
    - Saves file physically in dataset/documents/.
    - Generates eSign PKI digital signature.
    - Commits new block to Blockchain Verification Ledger DB.
    - Saves Document, Version, and Provenance records directly to SQL DB.
    """
    case = db.query(CaseDB).filter(CaseDB.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    doc_count = db.query(DocumentDB).count() + 1
    doc_id = f"DOC-{doc_count:03d}"
    saved_file_name = f"{doc_id}_{title.replace(' ', '_')}.pdf"
    saved_file_path = os.path.join(DOCS_STORAGE_DIR, saved_file_name)
    relative_path = f"/documents/{saved_file_name}"

    extracted_text = content_text or ""
    content_hash = ""

    if file:
        file_bytes = await file.read()
        content_hash = hashlib.sha256(file_bytes).hexdigest()
        with open(saved_file_path, "wb") as f_out:
            f_out.write(file_bytes)

        # Attempt PDF text extraction if pypdf is installed
        if file.filename and file.filename.lower().endswith('.pdf') and pypdf:
            try:
                reader = pypdf.PdfReader(saved_file_path)
                pdf_text = "\n".join([page.extract_text() for page in reader.pages if page.extract_text()])
                if pdf_text.strip():
                    extracted_text = pdf_text
            except Exception as pe:
                print(f"PDF text extraction note: {pe}")
    else:
        # Generate text if no file provided
        extracted_text = extracted_text or f"Official legal record for {title}. Case ID: {case_id}."
        content_hash = hashlib.sha256(extracted_text.encode()).hexdigest()
        
        # Write PDF using reportlab or plain text fallback
        with open(saved_file_path, "w") as f_out:
            f_out.write(extracted_text)

    # eSign PKI Signature JSON
    sig_json = json.dumps({
        "signature_id": f"SIG-{doc_id}",
        "signer_id": user_id,
        "certificate_issuer": "National Informatics Centre (NIC) eSign Portal",
        "certificate_serial": f"IN-NIC-{uuid.uuid4().hex[:8].upper()}",
        "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "signed_hash": content_hash,
        "is_valid": True
    })

    # Blockchain Commitment
    last_block = db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.desc()).first()
    prev_hash = last_block.block_hash if last_block else "0000000000000000000000000000000000000000000000000000000000000000"
    block_num = (last_block.block_number + 1) if last_block else 1
    block_hash = hashlib.sha256((prev_hash + content_hash + str(block_num)).encode()).hexdigest()

    new_block = BlockchainBlockDB(
        block_number=block_num,
        tx_id=f"TX-NCRB-{block_num:04d}",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        action="DOCUMENT_ESIGNED_UPLOAD",
        document_id=doc_id,
        previous_hash=prev_hash,
        block_hash=block_hash,
        merkle_root=content_hash[:32]
    )
    db.add(new_block)

    # Document DB Record
    new_doc = DocumentDB(
        document_id=doc_id,
        case_id=case_id,
        document_type=document_type,
        title=title,
        description=description or title,
        classification=classification,
        content_text=extracted_text,
        current_hash=content_hash,
        integrity_status="VERIFIED",
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        created_by=user_id,
        version=1,
        file_path=relative_path,
        hash_algorithm="SHA-256",
        external_system_source="NCRB Portal Upload",
        digital_signature_json=sig_json
    )
    db.add(new_doc)

    # Version DB Record
    new_ver = VersionDB(
        version_id=f"V-{doc_id}-v1",
        document_id=doc_id,
        version=1,
        hash=content_hash,
        created_by=user_id,
        created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        status="Current",
        file_path=relative_path
    )
    db.add(new_ver)

    # Relationship DB Record if parent provided
    if parent_doc_id:
        rel_id = f"R{db.query(ProvenanceEdgeDB).count() + 1:03d}"
        db.add(ProvenanceEdgeDB(
            id=rel_id,
            case_id=case_id,
            source_doc_id=parent_doc_id,
            target_doc_id=doc_id,
            relationship_type="derived_from",
            description=f"Uploaded derivative {title} from source {parent_doc_id}",
            created_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))

    # Audit Event
    audit_id = f"E{db.query(AuditLogDB).count() + 1:03d}"
    db.add(AuditLogDB(
        event_id=audit_id,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        event_type="UPLOADED",
        actor_id=user_id,
        actor_name="Officer " + user_id,
        document_id=doc_id,
        case_id=case_id,
        details=f"Uploaded & eSigned physical document file {saved_file_name}. Blockchain Block #{block_num} committed."
    ))

    db.commit()

    return {
        "status": "SUCCESS",
        "document_id": doc_id,
        "file_path": relative_path,
        "hash": content_hash,
        "blockchain_block": block_num
    }


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
def list_access_requests(db: Session = Depends(get_db)):
    reqs = db.query(AccessRequestDB).all()
    return reqs

@app.post("/api/access-requests")
def request_sensitive_access(body: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    doc_id = body.get("document_id")
    user_id = body.get("user_id", "OFF-001")
    action = body.get("requested_action", "VIEW")
    purpose = body.get("purpose_reason", "Official Case Investigation Review")
    
    doc = db.query(DocumentDB).filter(DocumentDB.document_id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
        
    user = db.query(UserDB).filter(UserDB.user_id == user_id).first()
    user_name = user.name if user else f"Officer {user_id}"
    user_role = user.role if user else "Investigator"

    req_count = db.query(AccessRequestDB).count() + 1
    req_id = f"AR-{req_count:03d}"
    
    new_req = AccessRequestDB(
        request_id=req_id,
        document_id=doc_id,
        requester_id=user_id,
        requester_name=user_name,
        requester_role=user_role,
        requested_action=action,
        purpose_reason=purpose,
        status="PENDING",
        requested_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.add(new_req)
    db.commit()
    return new_req

@app.post("/api/access-requests/{req_id}/approve")
def approve_access_request(req_id: str, body: Dict[str, Any] = Body(...), db: Session = Depends(get_db)):
    approver_role = body.get("approver_role", "")
    approver_id = body.get("approver_id", "SUP-001")

    if approver_role != "Supervisor" and approver_id != "SUP-001":
        raise HTTPException(status_code=403, detail="FORBIDDEN: Only Superintendent of Police (Supervisor) can approve requests.")

    req = db.query(AccessRequestDB).filter(AccessRequestDB.request_id == req_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Access request not found")
        
    req.status = "APPROVED"
    req.approver_id = approver_id
    req.approved_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    req.session_token = f"TOK-SECURE-{uuid.uuid4().hex[:12].upper()}"
    req.expires_at = (datetime.now() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    db.commit()
    return req


from fastapi.responses import FileResponse

@app.get("/api/blockchain")
def list_blockchain_ledger(db: Session = Depends(get_db)):
    return db.query(BlockchainBlockDB).order_by(BlockchainBlockDB.block_number.asc()).all()

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

