"""
NCRB SECURE DMS — SIH26190 Complete Dataset & PDF Generator
Generates:
1. Physical document files (.pdf, .jpg) in dataset/documents/
2. Metadata CSV files in dataset/metadata/ (cases, documents, relationships, versions, users, access_requests, audit_events, integrity_events)
"""

import os
import csv
import hashlib
import json
from datetime import datetime, timedelta
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

# Directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DOCS_DIR = os.path.join(DATASET_DIR, "documents")
META_DIR = os.path.join(DATASET_DIR, "metadata")

os.makedirs(DOCS_DIR, exist_ok=True)
os.makedirs(META_DIR, exist_ok=True)

def generate_pdf(file_path, title, doc_id, case_id, doc_type, classification, content_body):
    doc = SimpleDocTemplate(file_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    
    header_style = ParagraphStyle(
        'GovHeader',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1e3a8a'),
        alignment=1
    )
    
    sub_header_style = ParagraphStyle(
        'GovSubHeader',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        alignment=1
    )
    
    doc_title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        alignment=0,
        spaceBefore=10,
        spaceAfter=10
    )
    
    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=15,
        textColor=colors.HexColor('#1e293b')
    )

    elements = []
    
    # Official Header
    elements.append(Paragraph("MINISTRY OF HOME AFFAIRS • NATIONAL CRIME RECORDS BUREAU", header_style))
    elements.append(Paragraph("NCRB Secure Digital Document Management System (SIH26190)", sub_header_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#1e3a8a'), spaceAfter=15))
    
    # Meta Data Table
    meta_data = [
        [Paragraph(f"<b>DOCUMENT ID:</b> {doc_id}", body_style), Paragraph(f"<b>CASE ID:</b> {case_id}", body_style)],
        [Paragraph(f"<b>TYPE:</b> {doc_type}", body_style), Paragraph(f"<b>CLASSIFICATION:</b> {classification}", body_style)],
        [Paragraph(f"<b>RECORD DATE:</b> 2026-08-10 10:30 IST", body_style), Paragraph("<b>PKI eSIGN:</b> VERIFIED (SHA-256)", body_style)]
    ]
    t = Table(meta_data, colWidths=[270, 270])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f1f5f9')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))
    
    # Title
    elements.append(Paragraph(title.upper(), doc_title_style))
    
    # Content Body
    for para in content_body.split('\n\n'):
        if para.strip():
            elements.append(Paragraph(para.replace('\n', '<br/>'), body_style))
            elements.append(Spacer(1, 10))
            
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cbd5e1'), spaceAfter=10))
    
    # Signature Footer Block
    footer_text = f"<b>DIGITAL PKI SIGNATURE:</b><br/>Issuer: National Informatics Centre (NIC) eSign Portal<br/>SHA-256 Checksum Verified & Committed to Blockchain Ledger Block."
    elements.append(Paragraph(footer_text, sub_header_style))
    
    doc.build(elements)

def compute_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def create_dataset():
    print("Generating NCRB Dataset & PDF Files...")
    
    # --- 1. CASES ---
    cases = [
        {"case_id": "CASE-001", "case_name": "State v. Arun Kumar", "case_type": "Criminal Investigation", "status": "Under Investigation", "created_at": "2026-08-10 09:00:00"},
        {"case_id": "CASE-002", "case_name": "Union of India v. Cyber Crime Syndicate", "case_type": "Cyber Fraud & Money Laundering", "status": "Under Trial", "created_at": "2026-08-12 11:30:00"},
        {"case_id": "CASE-003", "case_name": "State v. Rajesh Gupta & Ors.", "case_type": "Financial Fraud & Forgery", "status": "Charge Sheet Filed", "created_at": "2026-08-15 14:20:00"}
    ]
    
    with open(os.path.join(META_DIR, "cases.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["case_id", "case_name", "case_type", "status", "created_at"])
        writer.writeheader()
        writer.writerows(cases)

    # --- 2. USERS ---
    users = [
        {"user_id": "OFF-001", "username": "vikram", "hashed_password": "password123", "name": "Insp. Vikram Sharma", "role": "Investigator", "department": "Cyber Crime Branch", "badge_number": "IND-NCRB-8821"},
        {"user_id": "OFF-002", "username": "priya", "hashed_password": "password123", "name": "Sub-Insp. Priya Singh", "role": "Investigator", "department": "Cyber Crime Branch", "badge_number": "IND-NCRB-8822"},
        {"user_id": "SUP-001", "username": "drsen", "hashed_password": "password123", "name": "SP Dr. Ananya Sen", "role": "Supervisor", "department": "Superintendent of Police", "badge_number": "IND-NCRB-9001"},
        {"user_id": "LAB-001", "username": "malviya", "hashed_password": "password123", "name": "Dr. Malviya", "role": "Forensic Analyst", "department": "CFSL Cyber Division", "badge_number": "IND-CFSL-7712"},
        {"user_id": "PRO-001", "username": "deshmukh", "hashed_password": "password123", "name": "Adv. Deshmukh", "role": "Prosecutor", "department": "Directorate of Prosecution", "badge_number": "IND-DOP-4410"},
        {"user_id": "CRT-001", "username": "magistrate", "hashed_password": "password123", "name": "Hon. Magistrate Verma", "role": "Court Officer", "department": "District & Sessions Court", "badge_number": "IND-JUD-1001"},
        {"user_id": "AUD-001", "username": "raman", "hashed_password": "password123", "name": "Auditor Raman", "role": "Auditor", "department": "NCRB Audit Directorate", "badge_number": "IND-NCRB-007"}
    ]
    
    with open(os.path.join(META_DIR, "users.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["user_id", "username", "hashed_password", "name", "role", "department", "badge_number"])
        writer.writeheader()
        writer.writerows(users)

    # --- 3. DOCUMENTS (CASE-001 Detailed Chain + CASE-002 & CASE-003) ---
    doc_definitions = [
        # CASE-001 Main Chain
        ("DOC-001", "CASE-001", "FIR", "First Information Report (FIR-2026-8801)", "OFF-001", "2026-08-10 10:30", 1, "Verified", "Confidential", "DOC-001_FIR.pdf", "Complainant alleges unauthorized wire transfer of Rs 45,00,000 from corporate escrow account via spoofed banking IP addresses."),
        ("DOC-002", "CASE-001", "Witness Statement", "Witness Statement of Bank Nodal Officer", "OFF-001", "2026-08-10 14:15", 1, "Verified", "Confidential", "DOC-002_Witness_Statement.pdf", "Witness Suresh Patel confirms login attempt from IP 192.168.1.45 using compromise admin credentials."),
        ("DOC-003", "CASE-001", "Evidence Record", "Seizure Memo of Server Hard Drive", "OFF-001", "2026-08-11 09:45", 1, "Verified", "Highly Confidential", "DOC-003_Evidence_Record.pdf", "Physical seizure of RAID 5 storage array from server room at Sector 62 Noida. Hardware serial: WD-9921-X."),
        ("DOC-004", "CASE-001", "Evidence Photo", "Crime Scene Physical Media Photograph", "OFF-002", "2026-08-11 11:20", 1, "Verified", "Restricted", "DOC-004_Evidence_Photo.pdf", "High-resolution photographic capture of seized server rack, unbroken anti-tamper security seals, and port connections."),
        ("DOC-005", "CASE-001", "Forensic Report", "CFSL Cyber Forensic Analysis Report", "LAB-001", "2026-08-12 16:00", 1, "Verified", "Highly Confidential", "DOC-005_Forensic_Report.pdf", "Disk image analysis revealed malware payload 'Ratchet-V2' injected at 03:14 AM. MAC address traced to suspect Arun Kumar."),
        ("DOC-006", "CASE-001", "Investigation Report", "Interim Investigation Findings Report", "OFF-001", "2026-08-13 11:00", 2, "Verified", "Confidential", "DOC-006_Investigation_Report.pdf", "Correlating forensic report DOC-005 and witness statement DOC-002 confirms primary suspect involvement of Arun Kumar."),
        ("DOC-007", "CASE-001", "Supplementary Report", "Supplementary Financial Trail Report", "OFF-002", "2026-08-14 10:30", 1, "Verified", "Confidential", "DOC-007_Supplementary_Report.pdf", "Bank transaction logs reveal immediate layering into cryptocurrency wallets across 3 offshore exchanges."),
        ("DOC-008", "CASE-001", "Charge Sheet", "Final Charge Sheet under IPC 420 & IT Act 66D", "OFF-001", "2026-08-15 15:30", 1, "Verified", "Confidential", "DOC-008_Charge_Sheet.pdf", "Comprehensive formal charge sheet establishing accused Arun Kumar's guilt under IT Act Section 66D and IPC Section 420."),
        ("DOC-009", "CASE-001", "Court Submission", "District Court Evidentiary Filing", "PRO-001", "2026-08-16 11:00", 1, "Verified", "Confidential", "DOC-009_Court_Submission.pdf", "Official filing to Judicial Magistrate requesting remand and asset freezing orders based on charge sheet DOC-008."),
        ("DOC-010", "CASE-001", "Translated Charge Sheet", "Charge Sheet Hindi Regional Translation", "OFF-002", "2026-08-16 14:00", 1, "Verified", "Public Record", "DOC-010_Translated_Charge_Sheet.pdf", "Official certified Hindi translation of Charge Sheet DOC-008 for court record and accused copy service."),
        ("DOC-011", "CASE-001", "Redacted Witness Statement", "Redacted Witness Statement for Public Record", "OFF-001", "2026-08-17 09:30", 1, "Verified", "Public Record", "DOC-011_Redacted_Witness_Statement.pdf", "Redacted derivative of DOC-002 scrubbing PII numbers, home address, and phone details pursuant to Section 44."),
        ("DOC-012", "CASE-001", "Revised Investigation Report", "Revised Final Investigation Report", "OFF-001", "2026-08-18 12:00", 1, "Verified", "Confidential", "DOC-012_Revised_Investigation_Report.pdf", "Updated investigation report incorporating supplementary offshore banking responses and CFSL updates."),
        
        # CASE-002 Documents
        ("DOC-020", "CASE-002", "FIR", "FIR for Cyber Ransomware Attack", "OFF-002", "2026-08-12 12:00", 1, "Verified", "Confidential", "DOC-020_FIR.pdf", "Ransomware encryption incident reported by National Health Portal server admin."),
        ("DOC-021", "CASE-002", "Forensic Report", "Ransomware Binary Decompilation Report", "LAB-001", "2026-08-13 15:00", 1, "Verified", "Highly Confidential", "DOC-021_Forensic_Report.pdf", "Malware reverse engineering confirms LockBit 3.0 variant with hardcoded C2 server IP."),
        ("DOC-022", "CASE-002", "Charge Sheet", "Cyber Terrorism Charge Sheet IT Act 66F", "OFF-002", "2026-08-15 17:00", 1, "Verified", "Confidential", "DOC-022_Charge_Sheet.pdf", "Charges filed under IT Act Section 66F (Cyber Terrorism) against international syndicate nodes."),

        # CASE-003 Documents
        ("DOC-030", "CASE-003", "FIR", "FIR for Bank Document Forgery", "OFF-001", "2026-08-15 10:00", 1, "Verified", "Confidential", "DOC-030_FIR.pdf", "Forged bank guarantee certificates submitted for government tender allocation."),
        ("DOC-031", "CASE-003", "Evidence Record", "Forged Bank Guarantee Hardcopy", "OFF-001", "2026-08-16 11:30", 1, "Verified", "Confidential", "DOC-031_Evidence_Record.pdf", "Seized physical bank guarantee paper bearing fake stamp and signature of Manager."),
        ("DOC-032", "CASE-003", "Forensic Report", "Handwriting & Ink Chemistry Analysis Report", "LAB-001", "2026-08-17 16:30", 1, "Verified", "Highly Confidential", "DOC-032_Forensic_Report.pdf", "CFSL document examiner confirms ink signature mismatch and fake rubber stamp impression.")
    ]

    documents_meta = []
    versions_meta = []
    
    for doc_id, case_id, doc_type, title, created_by, created_at, ver, status, classification, file_name, content in doc_definitions:
        pdf_path = os.path.join(DOCS_DIR, file_name)
        generate_pdf(pdf_path, title, doc_id, case_id, doc_type, classification, content)
        file_hash = compute_sha256(pdf_path)
        
        documents_meta.append({
            "document_id": doc_id,
            "case_id": case_id,
            "document_type": doc_type,
            "title": title,
            "created_by": created_by,
            "created_at": created_at,
            "version": ver,
            "status": status,
            "classification": classification,
            "file_path": f"/documents/{file_name}",
            "hash_algorithm": "SHA-256",
            "hash": file_hash,
            "content_text": content
        })

        # Add initial version entry
        versions_meta.append({
            "version_id": f"V-{doc_id}-v1",
            "document_id": doc_id,
            "version": 1,
            "hash": file_hash,
            "created_by": created_by,
            "created_at": created_at,
            "status": "Current" if ver == 1 else "Superseded",
            "file_path": f"/documents/{file_name}"
        })
        
        if ver == 2:
            # Add v1 superseded record for version 2 docs
            old_hash = hashlib.sha256((content + "_v1_draft").encode()).hexdigest()
            versions_meta.append({
                "version_id": f"V-{doc_id}-v2",
                "document_id": doc_id,
                "version": 2,
                "hash": file_hash,
                "created_by": created_by,
                "created_at": created_at,
                "status": "Current",
                "file_path": f"/documents/{file_name}"
            })

    with open(os.path.join(META_DIR, "documents.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["document_id", "case_id", "document_type", "title", "created_by", "created_at", "version", "status", "classification", "file_path", "hash_algorithm", "hash", "content_text"])
        writer.writeheader()
        writer.writerows(documents_meta)

    with open(os.path.join(META_DIR, "document_versions.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["version_id", "document_id", "version", "hash", "created_by", "created_at", "status", "file_path"])
        writer.writeheader()
        writer.writerows(versions_meta)

    # --- 4. RELATIONSHIPS (MAIN INNOVATION) ---
    relationships = [
        {"relationship_id": "R001", "source": "DOC-001", "target": "DOC-002", "type": "derived_from", "reason": "Witness information extracted from initial FIR complaint"},
        {"relationship_id": "R002", "source": "DOC-001", "target": "DOC-003", "type": "derived_from", "reason": "Evidence hard drives seized pursuant to FIR allegations"},
        {"relationship_id": "R003", "source": "DOC-003", "target": "DOC-004", "type": "referenced_from", "reason": "Crime scene photography documenting physical seizure"},
        {"relationship_id": "R004", "source": "DOC-003", "target": "DOC-005", "type": "derived_from", "reason": "Forensic extraction performed on seized server hard drive"},
        {"relationship_id": "R005", "source": "DOC-002", "target": "DOC-006", "type": "referenced_from", "reason": "Investigation findings citing witness statement corroboration"},
        {"relationship_id": "R006", "source": "DOC-005", "target": "DOC-006", "type": "derived_from", "reason": "Forensic findings establishing suspect malware MAC address"},
        {"relationship_id": "R007", "source": "DOC-006", "target": "DOC-007", "type": "merged_from", "reason": "Supplementary financial layering trail merged into investigation"},
        {"relationship_id": "R008", "source": "DOC-006", "target": "DOC-008", "type": "derived_from", "reason": "Final charge sheet preparation based on investigation findings"},
        {"relationship_id": "R009", "source": "DOC-008", "target": "DOC-009", "type": "derived_from", "reason": "Court submission filing incorporating final charge sheet"},
        {"relationship_id": "R010", "source": "DOC-008", "target": "DOC-010", "type": "translated_from", "reason": "Certified Hindi translation of primary charge sheet for court service"},
        {"relationship_id": "R011", "source": "DOC-002", "target": "DOC-011", "type": "redacted_from", "reason": "PII redaction scrubbing phone numbers and address for public record"},
        {"relationship_id": "R012", "source": "DOC-006", "target": "DOC-012", "type": "revised_from", "reason": "Investigation report revised with offshore banking updates"},
        
        # CASE-002 & CASE-003 Links
        {"relationship_id": "R020", "source": "DOC-020", "target": "DOC-021", "type": "derived_from", "reason": "Malware decompilation from encrypted server backup"},
        {"relationship_id": "R021", "source": "DOC-021", "target": "DOC-022", "type": "derived_from", "reason": "Cyber terrorism charge sheet prepared from C2 server trace"},
        {"relationship_id": "R030", "source": "DOC-030", "target": "DOC-031", "type": "derived_from", "reason": "Forged bank guarantee seized during FIR investigation"},
        {"relationship_id": "R031", "source": "DOC-031", "target": "DOC-032", "type": "derived_from", "reason": "Ink chemistry & handwriting analysis of forged signature"}
    ]

    with open(os.path.join(META_DIR, "document_relationships.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["relationship_id", "source", "target", "type", "reason"])
        writer.writeheader()
        writer.writerows(relationships)

    # --- 5. ACCESS REQUESTS ---
    access_requests = [
        {"request_id": "AR-001", "document_id": "DOC-005", "requested_by": "OFF-002", "reason": "Review forensic evidence payload trace", "status": "Approved", "approved_by": "SUP-001"},
        {"request_id": "AR-002", "document_id": "DOC-008", "requested_by": "PRO-001", "reason": "Prepare prosecution arguments for bail hearing", "status": "Approved", "approved_by": "SUP-001"},
        {"request_id": "AR-003", "document_id": "DOC-003", "requested_by": "OFF-002", "reason": "Inspect physical hardware serial logs", "status": "Pending", "approved_by": ""}
    ]

    with open(os.path.join(META_DIR, "access_requests.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["request_id", "document_id", "requested_by", "reason", "status", "approved_by"])
        writer.writeheader()
        writer.writerows(access_requests)

    # --- 6. AUDIT EVENTS ---
    audit_events = [
        {"event_id": "E001", "document_id": "DOC-001", "user_id": "OFF-001", "event_type": "created", "timestamp": "2026-08-10 10:30:00"},
        {"event_id": "E002", "document_id": "DOC-005", "user_id": "LAB-001", "event_type": "created", "timestamp": "2026-08-12 16:00:00"},
        {"event_id": "E003", "document_id": "DOC-005", "user_id": "OFF-002", "event_type": "access_requested", "timestamp": "2026-08-12 16:30:00"},
        {"event_id": "E004", "document_id": "DOC-005", "user_id": "SUP-001", "event_type": "access_approved", "timestamp": "2026-08-12 16:45:00"},
        {"event_id": "E005", "document_id": "DOC-008", "user_id": "OFF-001", "event_type": "created", "timestamp": "2026-08-15 15:30:00"}
    ]

    with open(os.path.join(META_DIR, "audit_events.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["event_id", "document_id", "user_id", "event_type", "timestamp"])
        writer.writeheader()
        writer.writerows(audit_events)

    # --- 7. INTEGRITY EVENTS ---
    integrity_events = [
        {"event_id": "INT-001", "document_id": "DOC-001", "expected_hash": documents_meta[0]["hash"], "actual_hash": documents_meta[0]["hash"], "result": "PASS", "detected_at": "2026-08-15 10:00:00"},
        {"event_id": "INT-002", "document_id": "DOC-005", "expected_hash": documents_meta[4]["hash"], "actual_hash": documents_meta[4]["hash"], "result": "PASS", "detected_at": "2026-08-15 11:00:00"}
    ]

    with open(os.path.join(META_DIR, "integrity_events.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["event_id", "document_id", "expected_hash", "actual_hash", "result", "detected_at"])
        writer.writeheader()
        writer.writerows(integrity_events)

    print("Dataset generation COMPLETE! Created files in dataset/documents/ and dataset/metadata/")

if __name__ == "__main__":
    create_dataset()
