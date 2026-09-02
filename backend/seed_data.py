"""
CUSTODY CHAIN / NCRB SECURE DMS - Seed Dataset (SIH26190)
Provides comprehensive synthetic dataset of NCRB FIRs, Police Asset Seizure logs,
CFSL Forensic Reports, Witness Depositions, Charge Sheets, Blockchain Blocks,
eSign Digital Signatures, and System Integration Metadata.
"""

from typing import Dict, List, Tuple
import hashlib
from datetime import datetime
from backend.models import (
    DocumentNode, ProvenanceEdge, DocumentType, RelationshipType,
    IntegrityStatus, Classification, User, UserRole, CaseSummary,
    DigitalSignature, BlockchainBlock, PoliceAsset
)

def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def generate_seed_data() -> Tuple[
    Dict[str, DocumentNode],
    List[ProvenanceEdge],
    Dict[str, User],
    Dict[str, CaseSummary],
    List[BlockchainBlock],
    List[PoliceAsset]
]:
    users: Dict[str, User] = {
        "INV-204": User(
            user_id="INV-204",
            name="Insp. Vikram Sharma",
            role=UserRole.INVESTIGATOR,
            department="NCRB Economic Offences & Cyber Division",
            badge_number="IND-NCRB-8821",
            assigned_cases=["CASE-2026-101", "CASE-2026-102", "CASE-2026-103"]
        ),
        "SUP-052": User(
            user_id="SUP-052",
            name="SP Dr. Ananya Sen",
            role=UserRole.SUPERVISOR,
            department="Crime Records Directorate, MHA",
            badge_number="IND-IPS-4402",
            assigned_cases=["CASE-2026-101", "CASE-2026-102", "CASE-2026-103"]
        ),
        "FOR-109": User(
            user_id="FOR-109",
            name="Dr. Rajesh Malviya",
            role=UserRole.FORENSIC_OFFICER,
            department="Central Forensic Science Laboratory (CFSL)",
            badge_number="CFSL-CY-091",
            assigned_cases=["CASE-2026-101", "CASE-2026-102"]
        ),
        "PRO-301": User(
            user_id="PRO-301",
            name="Adv. Meera Deshmukh",
            role=UserRole.PROSECUTOR,
            department="Directorate of Prosecution, High Court Bench",
            badge_number="BAR-MH-11029",
            assigned_cases=["CASE-2026-101", "CASE-2026-102"]
        ),
        "JUD-401": User(
            user_id="JUD-401",
            name="Hon. Magistrate K. S. Verma",
            role=UserRole.JUDICIAL_MAGISTRATE,
            department="Special Cyber & CID Court",
            badge_number="JUD-DEL-041",
            assigned_cases=["CASE-2026-101", "CASE-2026-102"]
        ),
        "AUD-001": User(
            user_id="AUD-001",
            name="Auditor K. R. Raman",
            role=UserRole.AUDITOR,
            department="National Crime Records Bureau (NCRB) Audit Cell",
            badge_number="JAA-NCRB-7710",
            assigned_cases=["CASE-2026-101", "CASE-2026-102"]
        )
    }

    cases: Dict[str, CaseSummary] = {
        "CASE-2026-101": CaseSummary(
            case_id="CASE-2026-101",
            case_number="FIR No. 0491/2026/EOW",
            title="Cyber Banking Infrastructure Breach & Data Theft",
            description="Unauthorized root intrusion into centralized banking transaction logs and illicit fund diversion.",
            investigator_id="INV-204",
            investigator_name="Insp. Vikram Sharma",
            status="ACTIVE_INVESTIGATION",
            created_at="2026-08-10 09:30:00",
            total_documents=7,
            provenance_links=6,
            verified_documents=7,
            review_required_documents=0,
            integrity_issues=0
        ),
        "CASE-2026-102": CaseSummary(
            case_id="CASE-2026-102",
            case_number="FIR No. 0118/2026/CID",
            title="High-Profile Homicide & Forensic Ballistics Provenance",
            description="Forensic examination of physical weapon evidence, autopsy pathological analysis, and witness testimony.",
            investigator_id="INV-204",
            investigator_name="Insp. Vikram Sharma",
            status="CHARGE_SHEET_FILED",
            created_at="2026-08-15 14:15:00",
            total_documents=6,
            provenance_links=6,
            verified_documents=6,
            review_required_documents=0,
            integrity_issues=0
        )
    }

    # Text contents
    txt_fir001 = "FIRST INFORMATION REPORT (FIR under CrPC 154 / BNSS 173): FIR No. 0491/2026/EOW filed at Cyber Crime Cell. Complainant: Bank Security Lead. Offence: IT Act Sec 66, 66D, IPC Sec 420. Unauthorized access to server cluster."
    txt_e001 = "SEIZURE MEMO & EVIDENCE LOG: Seized 4TB NVMe SSD containing raw kernel memory dump and server access logs. Sealed in Evidence Bag #EOW-401 with tamper-evident seal #99812."
    txt_ws004 = "WITNESS STATEMENT (CrPC 161): Statement of Chief Information Security Officer confirming unauthorized root privilege escalation executed from external IP 198.51.100.42 at 03:14:22 AM."
    txt_ws004_r = "WITNESS STATEMENT [REDACTED PUBLIC RECORD]: Statement of [CONFIDENTIAL CISO] confirming unauthorized root privilege escalation executed from external IP [REDACTED] at 03:14:22 AM."
    txt_fr009 = "CFSL FORENSIC EXPERT REPORT: Deep digital analysis confirming SQL Injection exploit vector targeting auth_handler.py. Cryptographic Hash of evidence verified intact."
    txt_ir014 = "CONSOLIDATED INVESTIGATION REPORT: Synthesizing FIR 0491, Seizure Memo E-001, CISO Statement WS-004, and CFSL Forensic Report FR-009 linking suspect laptop MAC address."
    txt_cs021 = "PROSECUTION CHARGE SHEET (Sec 173 CrPC / Sec 193 BNSS): Formal accusation filed against Suspect A under IPC 420/120B and IT Act 66D based on IR-014 and FR-009."

    txt_e101 = "PHYSICAL EVIDENCE RECOVERY MEMO: 9mm brass cartridge casing recovered from Crime Scene Alpha. Marked Item #E-101."
    txt_fr102 = "AUTOPSY & PATHOLOGY REPORT: Post-mortem evaluation by Senior Forensic Pathologist establishing cause of death as single projectile penetration."
    txt_fr103 = "BALLISTICS FORENSIC REPORT: Microscopic rifling striation matching casing E-101 to suspect firearm Serial #W-99182."
    txt_ws104 = "EYEWITNESS DEPOSITION: Sworn statement of eyewitness describing suspect vehicle departing scene at 22:45 hrs."
    txt_ir105 = "MASTER INVESTIGATION DIGEST: Synthesis of autopsy FR-102, ballistics FR-103, and witness deposition WS-104."
    txt_cs106 = "PROSECUTION CHARGE SHEET - IPC SEC 302: Indictment filed before Sessions Court."

    # Digital Signatures
    sig_fir001 = DigitalSignature(
        signature_id="SIG-001",
        signer_id="INV-204",
        signer_name="Insp. Vikram Sharma",
        signer_role="Investigating Officer",
        certificate_issuer="C-DAC eSign CA 2026 (Govt of India)",
        certificate_serial="IN-CDAC-88192-X509",
        signed_at="2026-08-10 10:00:00",
        signed_hash=compute_sha256(txt_fir001),
        is_valid=True
    )

    sig_fr009 = DigitalSignature(
        signature_id="SIG-009",
        signer_id="FOR-109",
        signer_name="Dr. Rajesh Malviya",
        signer_role="Senior Forensic Expert",
        certificate_issuer="CFSL PKI Certification Authority",
        certificate_serial="CFSL-DELHI-2026-9901",
        signed_at="2026-08-14 14:30:00",
        signed_hash=compute_sha256(txt_fr009),
        is_valid=True
    )

    sig_cs021 = DigitalSignature(
        signature_id="SIG-021",
        signer_id="PRO-301",
        signer_name="Adv. Meera Deshmukh",
        signer_role="Public Prosecutor",
        certificate_issuer="High Court e-Courts PKI Node",
        certificate_serial="HC-DEL-2026-7781",
        signed_at="2026-08-18 11:00:00",
        signed_hash=compute_sha256(txt_cs021),
        is_valid=True
    )

    documents: Dict[str, DocumentNode] = {
        # CASE-2026-101
        "FIR-001": DocumentNode(
            document_id="FIR-001",
            case_id="CASE-2026-101",
            document_type=DocumentType.FIR_POLICE_REPORT,
            title="First Information Report (FIR No. 0491/2026)",
            description="Initial police registration report filed under IT Act Section 66.",
            classification=Classification.INTERNAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-10 09:30:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/fir_001.pdf",
            current_hash=compute_sha256(txt_fir001),
            digital_signature=sig_fir001,
            blockchain_block_id=101,
            external_system_source="CCTNS",
            external_reference="CCTNS-FIR-2026-0491",
            content_text=txt_fir001,
            sensitive_flag=False
        ),
        "E-001": DocumentNode(
            document_id="E-001",
            case_id="CASE-2026-101",
            document_type=DocumentType.EVIDENCE_RECORD,
            title="Seizure Memo & SSD Drive Evidence Register",
            description="Official evidence seizure log for 4TB NVMe SSD server dump.",
            classification=Classification.HIGHLY_CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-11 10:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/e_001.raw",
            current_hash=compute_sha256(txt_e001),
            blockchain_block_id=102,
            external_system_source="eSakshya",
            external_reference="ESK-2026-8841-A",
            content_text=txt_e001,
            sensitive_flag=True
        ),
        "WS-004": DocumentNode(
            document_id="WS-004",
            case_id="CASE-2026-101",
            document_type=DocumentType.WITNESS_STATEMENT,
            title="Witness Deposition — CISO Office",
            description="Sworn statement of Chief Information Security Officer.",
            classification=Classification.CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-12 11:30:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/ws_004.pdf",
            current_hash=compute_sha256(txt_ws004),
            blockchain_block_id=103,
            content_text=txt_ws004,
            sensitive_flag=False
        ),
        "WS-004-R": DocumentNode(
            document_id="WS-004-R",
            case_id="CASE-2026-101",
            document_type=DocumentType.WITNESS_STATEMENT,
            title="Witness Deposition [PII Redacted Public Record]",
            description="Public redacted derivative of WS-004 with sensitive identities scrubbed.",
            classification=Classification.PUBLIC,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-12 15:45:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/ws_004_r.pdf",
            current_hash=compute_sha256(txt_ws004_r),
            blockchain_block_id=104,
            content_text=txt_ws004_r,
            sensitive_flag=False
        ),
        "FR-009": DocumentNode(
            document_id="FR-009",
            case_id="CASE-2026-101",
            document_type=DocumentType.FORENSIC_REPORT,
            title="CFSL Cyber Forensic Analysis Report",
            description="CFSL expert opinion detailing server intrusion logs and exploit payload.",
            classification=Classification.HIGHLY_CONFIDENTIAL,
            creator_id="FOR-109",
            creator_name="Dr. Rajesh Malviya",
            creation_timestamp="2026-08-14 14:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/fr_009.pdf",
            current_hash=compute_sha256(txt_fr009),
            digital_signature=sig_fr009,
            blockchain_block_id=105,
            external_system_source="CCTNS",
            external_reference="CCTNS-FR-99021",
            content_text=txt_fr009,
            sensitive_flag=True
        ),
        "IR-014": DocumentNode(
            document_id="IR-014",
            case_id="CASE-2026-101",
            document_type=DocumentType.INVESTIGATION_RECORD,
            title="Consolidated Master Investigation Synthesis Report",
            description="Synthesis connecting FIR, digital evidence, witness deposition, and forensic analysis.",
            classification=Classification.CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-16 16:30:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/ir_014.pdf",
            current_hash=compute_sha256(txt_ir014),
            blockchain_block_id=106,
            content_text=txt_ir014,
            sensitive_flag=False
        ),
        "CS-021": DocumentNode(
            document_id="CS-021",
            case_id="CASE-2026-101",
            document_type=DocumentType.CHARGE_SHEET,
            title="Police Charge Sheet (Sec 173 CrPC / Sec 193 BNSS)",
            description="Formal prosecution indictment filed before Cyber Magistrate.",
            classification=Classification.CONFIDENTIAL,
            creator_id="PRO-301",
            creator_name="Adv. Meera Deshmukh",
            creation_timestamp="2026-08-18 10:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case101/cs_021.pdf",
            current_hash=compute_sha256(txt_cs021),
            digital_signature=sig_cs021,
            blockchain_block_id=107,
            external_system_source="ICJS",
            external_reference="ICJS-CS-2026-0122",
            content_text=txt_cs021,
            sensitive_flag=False
        ),

        # CASE-2026-102
        "E-101": DocumentNode(
            document_id="E-101",
            case_id="CASE-2026-102",
            document_type=DocumentType.EVIDENCE_RECORD,
            title="Crime Scene Evidence & Seizure Register",
            description="Seizure memo for 9mm cartridge casing E-101.",
            classification=Classification.HIGHLY_CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-15 15:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/e_101.raw",
            current_hash=compute_sha256(txt_e101),
            blockchain_block_id=201,
            external_system_source="eSakshya",
            external_reference="ESK-2026-9901-B",
            content_text=txt_e101,
            sensitive_flag=True
        ),
        "FR-102": DocumentNode(
            document_id="FR-102",
            case_id="CASE-2026-102",
            document_type=DocumentType.FORENSIC_REPORT,
            title="Medical Examiner Autopsy Evaluation",
            description="Post-mortem pathology findings by Senior Medical Officer.",
            classification=Classification.HIGHLY_CONFIDENTIAL,
            creator_id="FOR-109",
            creator_name="Dr. Rajesh Malviya",
            creation_timestamp="2026-08-16 09:30:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/fr_102.pdf",
            current_hash=compute_sha256(txt_fr102),
            blockchain_block_id=202,
            content_text=txt_fr102,
            sensitive_flag=True
        ),
        "FR-103": DocumentNode(
            document_id="FR-103",
            case_id="CASE-2026-102",
            document_type=DocumentType.FORENSIC_REPORT,
            title="Ballistics & Firearm Comparison Report",
            description="Ballistics striation analysis matching recovered casing E-101.",
            classification=Classification.CONFIDENTIAL,
            creator_id="FOR-109",
            creator_name="Dr. Rajesh Malviya",
            creation_timestamp="2026-08-17 14:20:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/fr_103.pdf",
            current_hash=compute_sha256(txt_fr103),
            blockchain_block_id=203,
            content_text=txt_fr103,
            sensitive_flag=False
        ),
        "WS-104": DocumentNode(
            document_id="WS-104",
            case_id="CASE-2026-102",
            document_type=DocumentType.WITNESS_STATEMENT,
            title="Eyewitness Deposition Transcript",
            description="Sworn statement recorded under CrPC Section 161.",
            classification=Classification.CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-18 11:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/ws_104.pdf",
            current_hash=compute_sha256(txt_ws104),
            blockchain_block_id=204,
            content_text=txt_ws104,
            sensitive_flag=False
        ),
        "IR-105": DocumentNode(
            document_id="IR-105",
            case_id="CASE-2026-102",
            document_type=DocumentType.INVESTIGATION_RECORD,
            title="Master Case Investigation Digest",
            description="Synthesis of ballistics FR-103, autopsy FR-102, and witness deposition WS-104.",
            classification=Classification.CONFIDENTIAL,
            creator_id="INV-204",
            creator_name="Insp. Vikram Sharma",
            creation_timestamp="2026-08-20 16:00:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/ir_105.pdf",
            current_hash=compute_sha256(txt_ir105),
            blockchain_block_id=205,
            content_text=txt_ir105,
            sensitive_flag=False
        ),
        "CS-106": DocumentNode(
            document_id="CS-106",
            case_id="CASE-2026-102",
            document_type=DocumentType.CHARGE_SHEET,
            title="Prosecution Charge Sheet — IPC 302",
            description="Formal prosecution charge sheet filed before Sessions Court.",
            classification=Classification.CONFIDENTIAL,
            creator_id="PRO-301",
            creator_name="Adv. Meera Deshmukh",
            creation_timestamp="2026-08-22 10:30:00",
            current_version=1,
            integrity_status=IntegrityStatus.VERIFIED,
            storage_reference="vault://ncrb/case102/cs_106.pdf",
            current_hash=compute_sha256(txt_cs106),
            blockchain_block_id=206,
            external_system_source="eCourts",
            external_reference="ECOURT-SESS-2026-1102",
            content_text=txt_cs106,
            sensitive_flag=False
        )
    }

    edges: List[ProvenanceEdge] = [
        # CASE-2026-101
        ProvenanceEdge(
            edge_id="EDGE-001",
            source_document_id="FIR-001",
            target_document_id="E-001",
            relationship_type=RelationshipType.REFERENCED_FROM,
            transformation_reason="Seizure memo E-001 executed pursuant to FIR 0491 registration",
            created_by="INV-204",
            created_at="2026-08-11 10:00:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-002",
            source_document_id="E-001",
            target_document_id="FR-009",
            relationship_type=RelationshipType.DERIVED_FROM,
            transformation_reason="CFSL disk image parsing and SQL injection payload extraction",
            created_by="FOR-109",
            created_at="2026-08-14 14:00:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-003",
            source_document_id="WS-004",
            target_document_id="WS-004-R",
            relationship_type=RelationshipType.REDACTED_FROM,
            transformation_reason="Scrubbed sensitive PII credentials for public judicial repository",
            created_by="INV-204",
            created_at="2026-08-12 15:45:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-004",
            source_document_id="FR-009",
            target_document_id="IR-014",
            relationship_type=RelationshipType.MERGED_FROM,
            transformation_reason="Merged CFSL technical exploit report into master investigation digest",
            created_by="INV-204",
            created_at="2026-08-16 16:30:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-005",
            source_document_id="WS-004",
            target_document_id="IR-014",
            relationship_type=RelationshipType.MERGED_FROM,
            transformation_reason="Merged CISO witness deposition into master investigation digest",
            created_by="INV-204",
            created_at="2026-08-16 16:30:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-006",
            source_document_id="IR-014",
            target_document_id="CS-021",
            relationship_type=RelationshipType.DERIVED_FROM,
            transformation_reason="Formulated police charge sheet from master investigation report IR-014",
            created_by="PRO-301",
            created_at="2026-08-18 10:00:00"
        ),

        # CASE-2026-102
        ProvenanceEdge(
            edge_id="EDGE-101",
            source_document_id="E-101",
            target_document_id="FR-102",
            relationship_type=RelationshipType.DERIVED_FROM,
            transformation_reason="Pathology autopsy examination based on crime scene recovery E-101",
            created_by="FOR-109",
            created_at="2026-08-16 09:30:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-102",
            source_document_id="E-101",
            target_document_id="FR-103",
            relationship_type=RelationshipType.DERIVED_FROM,
            transformation_reason="Ballistics striation comparison matching casing E-101 to suspect firearm",
            created_by="FOR-109",
            created_at="2026-08-17 14:20:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-103",
            source_document_id="FR-102",
            target_document_id="IR-105",
            relationship_type=RelationshipType.MERGED_FROM,
            transformation_reason="Incorporated autopsy pathology report into master digest",
            created_by="INV-204",
            created_at="2026-08-20 16:00:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-104",
            source_document_id="FR-103",
            target_document_id="IR-105",
            relationship_type=RelationshipType.MERGED_FROM,
            transformation_reason="Incorporated ballistics comparison findings into master digest",
            created_by="INV-204",
            created_at="2026-08-20 16:00:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-105",
            source_document_id="WS-104",
            target_document_id="IR-105",
            relationship_type=RelationshipType.MERGED_FROM,
            transformation_reason="Incorporated eyewitness testimony into master digest",
            created_by="INV-204",
            created_at="2026-08-20 16:00:00"
        ),
        ProvenanceEdge(
            edge_id="EDGE-106",
            source_document_id="IR-105",
            target_document_id="CS-106",
            relationship_type=RelationshipType.DERIVED_FROM,
            transformation_reason="Formulated prosecution charge sheet CS-106 from digest IR-105",
            created_by="PRO-301",
            created_at="2026-08-22 10:30:00"
        )
    ]

    blockchain_blocks: List[BlockchainBlock] = [
        BlockchainBlock(
            block_number=101,
            block_hash="0x3a9f812b9c0182e440182f7182903123847aef01923184910239102",
            previous_hash="0x000000000000000000000000000000000000000000000000000000",
            timestamp="2026-08-10 09:30:05",
            document_id="FIR-001",
            action="CREATED_AND_ESIGNED",
            merkle_root="0x9182aef10293102",
            tx_id="TX-NCRB-9901-01"
        ),
        BlockchainBlock(
            block_number=102,
            block_hash="0x7f8a91c0128e4418290123847aef019231849102391028391823901",
            previous_hash="0x3a9f812b9c0182e440182f7182903123847aef01923184910239102",
            timestamp="2026-08-11 10:00:02",
            document_id="E-001",
            action="SEIZURE_HASH_REGISTERED",
            merkle_root="0x8821bc102930491",
            tx_id="TX-NCRB-9901-02"
        ),
        BlockchainBlock(
            block_number=105,
            block_hash="0x99120bc771a2839102384910239102839182390190123847aef019",
            previous_hash="0x7f8a91c0128e4418290123847aef019231849102391028391823901",
            timestamp="2026-08-14 14:00:10",
            document_id="FR-009",
            action="CFSL_FORENSIC_HASH_COMMITTED",
            merkle_root="0x770192831092830",
            tx_id="TX-NCRB-9901-05"
        )
    ]

    police_assets: List[PoliceAsset] = [
        PoliceAsset(
            asset_id="AST-EOW-401",
            asset_name="Seized 4TB NVMe SSD Server Disk Image",
            category="DIGITAL_DRIVE",
            serial_number="NVME-SAMSUNG-990182",
            case_id="CASE-2026-101",
            custodian_id="FOR-109",
            location="CFSL Cyber Forensic Vault #4B",
            status="FORENSIC_LAB",
            linked_document_ids=["E-001", "FR-009"]
        ),
        PoliceAsset(
            asset_id="AST-CID-991",
            asset_name="Recovered 9mm Cartridge Casing",
            category="EVIDENCE",
            serial_number="EVI-CASING-2026-01",
            case_id="CASE-2026-102",
            custodian_id="INV-204",
            location="District Evidence Locker #12",
            status="VAULT_SEALED",
            linked_document_ids=["E-101", "FR-102", "FR-103"]
        )
    ]

    return documents, edges, users, cases, blockchain_blocks, police_assets
