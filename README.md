# TraceX: Secure Document Provenance & Dependency Tracking 🛡️

**TraceX** (also known as NCRB Secure DMS) is an enterprise-grade digital document management and provenance tracking system designed for law enforcement, courts, and investigative departments. It ensures end-to-end transparency, data integrity, and accountability in the digital evidence lifecycle.

---

## 🎯 Impact and Benefits

![Impact and Benefits](./assets/image_1.png)

TraceX creates transparency, accountability, and trust in every stage of the investigation journey. 
* **End-to-End Transparency:** Every document's journey is visible from origin to final submission.
* **Data Integrity & Authenticity:** Integrity verified using SHA-256 hashing, digital signatures, and tamper-evident audit trails.
* **Dependency Impact Awareness:** Instantly identify all downstream documents affected if a source document has an integrity issue.
* **Accountability & Auditability:** Complete audit trail of every action, approval, and access.

---

## 🚀 Key Features

* **Hierarchical Provenance Graph:** Visualizes document lineage from origin (e.g., FIR) to downstream transformations (Forensic Reports, Charge Sheets). Includes dynamic switching between Tree and Force-directed layouts.
* **Tamper-Evident Integrity:** Detects unauthorized modifications. If a document's hash is corrupted, TraceX proactively calculates the blast radius and flags downstream dependents for review.
* **Role-Based Access Control (RBAC) & Approvals:** Granular access based on roles (Investigator, Supervisor, Auditor). Restricted documents require formal access request workflows.
* **Cryptographic Signatures:** Integrates eSign PKI for legally binding digital signatures.

---

## 💻 Technologies Used

![Technologies Used](./assets/image_3.png)

* **Frontend:** Vanilla JS, D3.js (for Graph Engine), HTML5, CSS3 (Glassmorphism UI)
* **Backend:** FastAPI (Python)
* **Database:** PostgreSQL (with SQLite fallback for development)
* **ORM:** SQLAlchemy
* **Security:** JWT Authentication, SHA-256 Hashing, Role-Based Workflows

---

## ⚙️ Architecture

### DBMS Architecture
![DBMS Architecture](./assets/image.png)

---

## 📊 Feasibility and Viability

![Feasibility and Viability](./assets/image_4.png)

TraceX is built to be technically feasible, operationally effective, and scalable from a hackathon prototype to an enterprise-level government deployment. It uses adapter-based integration strategies to interface with existing systems like CCTNS, eSakshya, ICJS, and eCourts.

---

## 📚 Research & References

![Research & References](./assets/image_2.png)

Designed in compliance with the **Bharatiya Sakshya Adhiniyam, 2023** and **CCA Digital Signature** guidelines, TraceX bridges the gap in provenance tracking within existing government systems.

---

## 🛠️ Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/your-org/TraceX.git
cd TraceX
```

### 2. Set up the Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Copy the example environment file and update the credentials:
```bash
cp .env.example .env
```
Ensure your database credentials and `SECRET_KEY` are properly configured in `.env`.

### 4. Initialize the Database & Seed Data
```bash
python -c "from backend.database import init_db; init_db()"
```

### 5. Run the Server
```bash
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

### 6. Access the Application
Open your browser and navigate to: [http://localhost:8000](http://localhost:8000)

**Default Credentials for Testing:**
* **Admin/Supervisor:** `username: admin`, `password: admin123`
* **Investigator:** `username: investigator1`, `password: inv123`

---
*Built for SIH 2026 - Problem Statement SIH26190*
