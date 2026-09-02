"""
NCRB SECURE DMS — Database Integration Module
Supports PostgreSQL / MySQL / SQLite database connections loaded from .env environment variables.
Defines SQLAlchemy ORM models for Cases, Documents, Versions, Lineage Edges, Access Requests, Audit Events, Integrity Events, Blockchain Blocks, and Police Assets.
Loads dataset metadata directly from CSV files into SQL database tables.
"""

import os
import csv
import json
import hashlib
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import create_engine, Column, String, Integer, Text, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Load .env environment variables
load_dotenv()

# Database Connection Credentials & URL Construction
DB_USER = os.getenv("DB_USER", "ncrb_admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "ncrb_dms_db")

# Fallback precedence: POSTGRES_URL -> DATABASE_URL -> constructed PostgreSQL URL -> SQLite default
DEFAULT_PG_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}" if DB_PASSWORD else "sqlite:///./ncrb_dms.db"
POSTGRES_URL = os.getenv("POSTGRES_URL", os.getenv("DATABASE_URL", DEFAULT_PG_URL))

if POSTGRES_URL.startswith("postgres://"):
    POSTGRES_URL = POSTGRES_URL.replace("postgres://", "postgresql://", 1)

connect_args = {"check_same_thread": False} if "sqlite" in POSTGRES_URL else {}
engine = create_engine(POSTGRES_URL, connect_args=connect_args, echo=False)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- SQLALCHEMY MODELS ---

class CaseDB(Base):
    __tablename__ = "cases"
    case_id = Column(String(50), primary_key=True)
    case_name = Column(String(255), nullable=False)
    case_type = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    created_at = Column(String(50), nullable=False)


class UserDB(Base):
    __tablename__ = "users"
    user_id = Column(String(50), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    name = Column(String(100), nullable=False)
    role = Column(String(50), nullable=False)
    department = Column(String(100), nullable=False)
    badge_number = Column(String(50), nullable=False)


class DocumentDB(Base):
    __tablename__ = "documents"
    document_id = Column(String(50), primary_key=True)
    case_id = Column(String(50), nullable=False, index=True)
    document_type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    classification = Column(String(50), nullable=False)
    content_text = Column(Text, nullable=False)
    current_hash = Column(String(128), nullable=False)
    integrity_status = Column(String(50), nullable=False, default="VERIFIED")
    created_at = Column(String(50), nullable=False)
    created_by = Column(String(100), nullable=False)
    version = Column(Integer, default=1)
    file_path = Column(String(255), nullable=True)
    hash_algorithm = Column(String(20), default="SHA-256")
    external_system_source = Column(String(100), nullable=True)
    digital_signature_json = Column(Text, nullable=True)


class ProvenanceEdgeDB(Base):
    __tablename__ = "provenance_edges"
    id = Column(String(50), primary_key=True)
    case_id = Column(String(50), nullable=False, index=True)
    source_doc_id = Column(String(50), nullable=False)
    target_doc_id = Column(String(50), nullable=False)
    relationship_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(String(50), nullable=False)


class VersionDB(Base):
    __tablename__ = "document_versions"
    version_id = Column(String(50), primary_key=True)
    document_id = Column(String(50), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    hash = Column(String(128), nullable=False)
    created_by = Column(String(100), nullable=False)
    created_at = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False)
    file_path = Column(String(255), nullable=True)


class AccessRequestDB(Base):
    __tablename__ = "access_requests"
    request_id = Column(String(50), primary_key=True)
    document_id = Column(String(50), nullable=False)
    requester_id = Column(String(50), nullable=False)
    requester_name = Column(String(100), nullable=False)
    requester_role = Column(String(50), nullable=False)
    requested_action = Column(String(50), nullable=False)
    purpose_reason = Column(Text, nullable=False)
    status = Column(String(50), nullable=False)
    approver_id = Column(String(50), nullable=True)
    session_token = Column(String(100), nullable=True)
    requested_at = Column(String(50), nullable=False)
    approved_at = Column(String(50), nullable=True)
    expires_at = Column(String(50), nullable=True)


class AuditLogDB(Base):
    __tablename__ = "audit_logs"
    event_id = Column(String(50), primary_key=True)
    timestamp = Column(String(50), nullable=False)
    event_type = Column(String(50), nullable=False)
    actor_id = Column(String(50), nullable=False)
    actor_name = Column(String(100), nullable=False)
    document_id = Column(String(50), nullable=True)
    case_id = Column(String(50), nullable=True)
    details = Column(Text, nullable=False)
    integrity_ref = Column(String(128), nullable=True)
    affected_nodes_json = Column(Text, nullable=True)


class IntegrityEventDB(Base):
    __tablename__ = "integrity_events"
    event_id = Column(String(50), primary_key=True)
    document_id = Column(String(50), nullable=False)
    expected_hash = Column(String(128), nullable=False)
    actual_hash = Column(String(128), nullable=False)
    result = Column(String(20), nullable=False)
    detected_at = Column(String(50), nullable=False)


class BlockchainBlockDB(Base):
    __tablename__ = "blockchain_blocks"
    block_number = Column(Integer, primary_key=True)
    tx_id = Column(String(50), nullable=False)
    timestamp = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False)
    document_id = Column(String(50), nullable=False)
    previous_hash = Column(String(128), nullable=False)
    block_hash = Column(String(128), nullable=False)
    merkle_root = Column(String(128), nullable=False)


class PoliceAssetDB(Base):
    __tablename__ = "police_assets"
    asset_id = Column(String(50), primary_key=True)
    case_id = Column(String(50), nullable=False, index=True)
    asset_name = Column(String(100), nullable=False)
    serial_number = Column(String(100), nullable=False)
    location = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    custodian_id = Column(String(50), nullable=False)


def init_db():
    Base.metadata.create_all(bind=engine)
    seed_db_from_csv()

def seed_db_from_csv():
    db = SessionLocal()
    try:
        # Check if database is already seeded
        if db.query(CaseDB).first():
            return

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        meta_dir = os.path.join(base_dir, "dataset", "metadata")
        if not os.path.exists(meta_dir):
            return

        # 1. Seed Cases
        cases_csv = os.path.join(meta_dir, "cases.csv")
        if os.path.exists(cases_csv):
            with open(cases_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(CaseDB(**row))

        # 2. Seed Users
        users_csv = os.path.join(meta_dir, "users.csv")
        if os.path.exists(users_csv):
            with open(users_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(UserDB(**row))

        # 3. Seed Documents
        docs_csv = os.path.join(meta_dir, "documents.csv")
        if os.path.exists(docs_csv):
            with open(docs_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    sig_json = json.dumps({
                        "algorithm": "SHA256withRSA",
                        "certificate_issuer": "National Informatics Centre (NIC) eSign Portal",
                        "status": "VALID",
                        "timestamp": row["created_at"]
                    })
                    db.add(DocumentDB(
                        document_id=row["document_id"],
                        case_id=row["case_id"],
                        document_type=row["document_type"],
                        title=row["title"],
                        description=row["content_text"][:150] + "...",
                        classification=row["classification"],
                        content_text=row["content_text"],
                        current_hash=row["hash"],
                        integrity_status=row["status"].upper(),
                        created_at=row["created_at"],
                        created_by=row["created_by"],
                        version=int(row["version"]),
                        file_path=row["file_path"],
                        hash_algorithm=row["hash_algorithm"],
                        external_system_source="CCTNS / ICJS Portal",
                        digital_signature_json=sig_json
                    ))

        db.commit()

        # Build document_id -> case_id map
        doc_case_map = {d.document_id: d.case_id for d in db.query(DocumentDB).all()}

        # 4. Seed Relationships
        rel_csv = os.path.join(meta_dir, "document_relationships.csv")
        if os.path.exists(rel_csv):
            with open(rel_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    c_id = doc_case_map.get(row["source"], "CASE-001")
                    db.add(ProvenanceEdgeDB(
                        id=row["relationship_id"],
                        case_id=c_id,
                        source_doc_id=row["source"],
                        target_doc_id=row["target"],
                        relationship_type=row["type"],
                        description=row["reason"],
                        created_at="2026-08-10 10:30:00"
                    ))

        # 5. Seed Versions
        ver_csv = os.path.join(meta_dir, "document_versions.csv")
        if os.path.exists(ver_csv):
            with open(ver_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(VersionDB(
                        version_id=row["version_id"],
                        document_id=row["document_id"],
                        version=int(row["version"]),
                        hash=row["hash"],
                        created_by=row["created_by"],
                        created_at=row["created_at"],
                        status=row["status"],
                        file_path=row["file_path"]
                    ))

        # 6. Seed Access Requests
        ar_csv = os.path.join(meta_dir, "access_requests.csv")
        if os.path.exists(ar_csv):
            with open(ar_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(AccessRequestDB(
                        request_id=row["request_id"],
                        document_id=row["document_id"],
                        requester_id=row["requested_by"],
                        requester_name="Officer " + row["requested_by"],
                        requester_role="Investigator",
                        requested_action="VIEW",
                        purpose_reason=row["reason"],
                        status=row["status"].upper(),
                        approver_id=row["approved_by"],
                        session_token=f"TOK-{row['request_id']}" if row["status"].upper() == "APPROVED" else None,
                        requested_at="2026-08-12 10:00:00"
                    ))

        # 7. Seed Audit Logs
        audit_csv = os.path.join(meta_dir, "audit_events.csv")
        if os.path.exists(audit_csv):
            with open(audit_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(AuditLogDB(
                        event_id=row["event_id"],
                        timestamp=row["timestamp"],
                        event_type=row["event_type"].upper(),
                        actor_id=row["user_id"],
                        actor_name="Officer " + row["user_id"],
                        document_id=row["document_id"],
                        case_id="CASE-001",
                        details=f"Performed {row['event_type']} on document {row['document_id']}"
                    ))

        # 8. Seed Integrity Events
        integ_csv = os.path.join(meta_dir, "integrity_events.csv")
        if os.path.exists(integ_csv):
            with open(integ_csv, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    db.add(IntegrityEventDB(
                        event_id=row["event_id"],
                        document_id=row["document_id"],
                        expected_hash=row["expected_hash"],
                        actual_hash=row["actual_hash"],
                        result=row["result"],
                        detected_at=row["detected_at"]
                    ))

        # 9. Seed Police Assets
        db.add(PoliceAssetDB(asset_id="AST-101", case_id="CASE-001", asset_name="RAID 5 Server Hard Array (Seized)", serial_number="WD-9921-X", location="MHA CFSL Evidence Vault 4", status="SEIZED_STORED", custodian_id="LAB-001"))
        db.add(PoliceAssetDB(asset_id="AST-102", case_id="CASE-001", asset_name="Suspect iPhone 15 Pro", serial_number="IMEI-3589-1092-2", location="Cyber Forensic Lab Bench 2", status="UNDER_ANALYSIS", custodian_id="LAB-001"))

        # 10. Seed Initial Blockchain Blocks
        db.add(BlockchainBlockDB(
            block_number=1,
            tx_id="TX-GENESIS-001",
            timestamp="2026-08-10 09:00:00",
            action="GENESIS_BLOCK",
            document_id="DOC-001",
            previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
            block_hash="b4a8e9f02c1182390192837465abc1234567890defabc1234567890def123456",
            merkle_root="a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
        ))

        db.commit()
        print("Database seeded successfully from CSV files!")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()
