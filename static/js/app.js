/**
 * NCRB SECURE DMS — SPA Master Application Controller (SIH26190)
 * Enforces strict User-Specific Role-Based Access Control (RBAC):
 * 1. Each Access Grant token is STRICTLY BOUND to a specific Officer ID (e.g. Insp. Vikram vs Dr. Malviya).
 * 2. Approving access for Inspector Vikram DOES NOT give access to Forensic Officer Dr. Malviya.
 * 3. Upon logout, all active temporary access tokens for that officer are REVOKED.
 * 4. Only Superintendent of Police (Supervisor Dr. Sen) can approve access requests in the Supervisor Queue.
 */

window.CustodyApp = {
  currentCaseId: 'CASE-001',
  currentUser: null,
  currentDocNode: null,
  allCaseDocs: [],
  accessRequests: [],

  init() {
    this.bindEvents();
    this.checkSession();
  },

  bindEvents() {
    // Login Submit
    document.getElementById('btn-submit-login').onclick = () => {
      this.loginUser();
    };

    // Logout
    document.getElementById('btn-logout').onclick = () => {
      this.logoutUser();
    };

    // Navigation Tabs
    document.querySelectorAll('.nav-tab-btn').forEach(btn => {
      btn.onclick = (e) => {
        const viewId = btn.getAttribute('data-view');
        
        // Strict RBAC Tab Guard: Only Supervisor can access Queue tab!
        if (viewId === 'view-queue' && (!this.currentUser || this.currentUser.role !== 'Supervisor')) {
          alert('ACCESS DENIED: The Supervisor Queue is strictly restricted to Superintendent of Police (Supervisor) personnel.');
          return;
        }

        document.querySelectorAll('.nav-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.view-panel').forEach(v => v.style.display = 'none');
        
        btn.classList.add('active');
        document.getElementById(viewId).style.display = 'block';

        if (viewId === 'view-graph') {
          this.renderGraphView();
        } else if (viewId === 'view-blockchain') {
          this.loadBlockchainLedger();
        } else if (viewId === 'view-assets') {
          this.loadPoliceAssets();
        } else if (viewId === 'view-queue') {
          this.loadAccessQueue(true);
        } else if (viewId === 'view-audit') {
          this.loadAuditLedger();
        }
      };
    });

    // Case Switcher
    document.getElementById('case-select').onchange = (e) => {
      this.currentCaseId = e.target.value;
      this.reloadCurrentCase();
    };

    // Full-Text Search
    document.getElementById('repo-search-input').oninput = (e) => {
      const q = e.target.value.trim();
      if (q.length > 0) {
        fetch(`/api/documents/search?q=${encodeURIComponent(q)}`)
          .then(r => r.json())
          .then(res => this.renderDocCards(res.documents));
      } else {
        this.renderDocCards(this.allCaseDocs);
      }
    };

    // Type Filter
    document.getElementById('filter-type-select').onchange = (e) => {
      const val = e.target.value;
      if (val) {
        const filtered = this.allCaseDocs.filter(d => d.document_type === val);
        this.renderDocCards(filtered);
      } else {
        this.renderDocCards(this.allCaseDocs);
      }
    };

    // Upload Modal Trigger
    document.getElementById('btn-open-upload').onclick = () => {
      document.getElementById('upload-modal').classList.add('active');
    };

    // Upload Submission
    document.getElementById('btn-submit-upload').onclick = () => {
      this.submitDocumentUpload();
    };

    // Graph Layout Toggle Buttons
    const btnTree = document.getElementById('btn-layout-tree');
    const btnForce = document.getElementById('btn-layout-force');
    if (btnTree && btnForce) {
      btnTree.onclick = () => {
        btnTree.className = 'btn-primary';
        btnForce.className = 'btn-secondary';
        window.CustodyGraph.setLayoutMode('tree');
      };
      btnForce.onclick = () => {
        btnForce.className = 'btn-primary';
        btnTree.className = 'btn-secondary';
        window.CustodyGraph.setLayoutMode('force');
      };
    }

    // Drawer Buttons
    document.getElementById('close-drawer-btn').onclick = () => {
      document.getElementById('drawer-panel').classList.remove('open');
    };

    document.getElementById('btn-demo-tamper').onclick = () => {
      if (!this.currentDocNode) { alert('Select a document node first.'); return; }
      this.triggerTamperDemo(this.currentDocNode.document_id);
    };

    document.getElementById('btn-reset-tamper').onclick = () => {
      if (!this.currentDocNode) return;
      this.resetTamper(this.currentDocNode.document_id);
    };

    document.getElementById('btn-verify-hash').onclick = () => {
      if (!this.currentDocNode) return;
      this.verifyIntegrity(this.currentDocNode.document_id);
    };

    document.getElementById('btn-explain-why').onclick = () => {
      if (!this.currentDocNode) return;
      window.CustodyAudit.showExplainImpactModal(this.currentDocNode.document_id);
    };

    document.getElementById('btn-open-viewer').onclick = () => {
      if (!this.currentDocNode) return;
      this.attemptOpenDocument(this.currentDocNode.document_id);
    };

    document.getElementById('btn-request-access').onclick = () => {
      if (!this.currentDocNode) return;
      this.showPermissionModal(this.currentDocNode);
    };

    document.getElementById('btn-submit-perm-request').onclick = () => {
      const docId = this.currentDocNode ? this.currentDocNode.document_id : document.getElementById('perm-doc-id').innerText;
      if (!docId) return;
      const reason = document.getElementById('perm-reason-input').value;
      this.submitAccessRequest(docId, reason);
    };

    document.getElementById('btn-pii-redact').onclick = () => {
      if (!this.currentDocNode) return;
      window.CustodyAudit.showRedactModal(this.currentDocNode);
    };

    document.getElementById('btn-sim-impact').onclick = () => {
      if (!this.currentDocNode) return;
      window.CustodyAudit.showSimulationModal(this.currentDocNode.document_id);
    };

    // Modal Background Click Closes Modal
    document.querySelectorAll('.modal-overlay').forEach(modal => {
      modal.onclick = (e) => {
        if (e.target === modal) {
          modal.classList.remove('active');
        }
      };
    });
  },

  quickFillLogin(username, password) {
    document.getElementById('login-username').value = username;
    document.getElementById('login-password').value = password;
    this.loginUser();
  },

  loginUser() {
    const u = document.getElementById('login-username').value.trim();
    const p = document.getElementById('login-password').value.trim();

    if (!u || !p) {
      alert('Username and password are required.');
      return;
    }

    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    })
    .then(r => {
      if (!r.ok) throw new Error('Invalid credentials');
      return r.json();
    })
    .then(res => {
      this.currentUser = res.user;
      localStorage.setItem('ncrb_user', JSON.stringify(res.user));
      document.getElementById('login-screen-overlay').style.display = 'none';
      this.updateUserProfileUI();
      this.loadCases();
    })
    .catch(err => {
      alert('Authentication Failed: Invalid username or password. Try demo accounts!');
    });
  },

  checkSession() {
    const stored = localStorage.getItem('ncrb_user');
    if (stored) {
      this.currentUser = JSON.parse(stored);
      document.getElementById('login-screen-overlay').style.display = 'none';
      this.updateUserProfileUI();
      this.loadCases();
    } else {
      document.getElementById('login-screen-overlay').style.display = 'flex';
    }
  },

  logoutUser() {
    if (this.currentUser) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: this.currentUser.user_id })
      });
    }

    this.currentUser = null;
    localStorage.removeItem('ncrb_user');
    document.getElementById('login-screen-overlay').style.display = 'flex';
  },

  updateUserProfileUI() {
    if (!this.currentUser) return;

    document.getElementById('u-display-name').innerText = this.currentUser.name;
    document.getElementById('u-display-role').innerText = `${this.currentUser.role.toUpperCase()} • ${this.currentUser.badge_number}`;

    const queueTabBtn = document.getElementById('tab-btn-queue');
    // STRICT RBAC: Only Supervisors get the Queue Tab!
    if (this.currentUser.role === 'Supervisor') {
      queueTabBtn.style.display = 'inline-flex';
    } else {
      queueTabBtn.style.display = 'none';
    }
  },

  loadCases() {
    fetch('/api/cases')
      .then(r => r.json())
      .then(cases => {
        const select = document.getElementById('case-select');
        select.innerHTML = cases.map(c => `
          <option value="${c.case_id}">${c.case_id} — ${c.title}</option>
        `).join('');
        select.value = this.currentCaseId;
        this.reloadCurrentCase();
      });
  },

  reloadCurrentCase() {
    fetch(`/api/cases/${this.currentCaseId}/graph`)
      .then(r => r.json())
      .then(data => {
        this.allCaseDocs = data.nodes;
        this.renderMetrics(data.case);
        this.graphData = data;
        this.loadAccessQueue(false);
        
        const graphView = document.getElementById('view-graph');
        if (graphView && graphView.style.display !== 'none') {
          this.renderGraphView();
        }
      });
  },

  renderMetrics(c) {
    document.getElementById('m-total-docs').innerText = c.total_documents;
    document.getElementById('m-links').innerText = c.provenance_links;
    document.getElementById('m-verified').innerText = c.verified_documents;
    document.getElementById('m-warning').innerText = c.review_required_documents;
    document.getElementById('m-critical').innerText = c.integrity_issues;

    const banner = document.getElementById('top-status-banner');
    if (c.integrity_issues > 0) {
      banner.className = 'badge-pill critical';
      banner.innerText = `⚠ INTEGRITY ISSUE DETECTED (${c.integrity_issues} Compromised Source, ${c.review_required_documents} Review Required)`;
    } else if (c.review_required_documents > 0) {
      banner.className = 'badge-pill warning';
      banner.innerText = `⚠ REVIEW REQUIRED (${c.review_required_documents} Affected Downstream)`;
    } else {
      banner.className = 'badge-pill verified';
      banner.innerText = '✓ ALL DOCUMENTS VERIFIED & SECURE';
    }
  },

  renderDocCards(docs) {
    const container = document.getElementById('doc-grid-container');
    if (!docs || docs.length === 0) {
      container.innerHTML = '<div style="color:#64748b; font-size:14px;">No documents match the search criteria.</div>';
      return;
    }

    const currentUserId = this.currentUser ? this.currentUser.user_id : null;

    container.innerHTML = docs.map(d => {
      const isRestricted = d.classification !== 'Public Record';

      // STRICT USER-SPECIFIC CHECK: Match document_id AND requester_id!
      const appReq = this.accessRequests.find(r => r.document_id === d.document_id && r.requester_id === currentUserId && r.status === 'APPROVED');
      const pendReq = this.accessRequests.find(r => r.document_id === d.document_id && r.requester_id === currentUserId && r.status === 'PENDING');

      let badgeHtml = '';
      if (appReq) {
        badgeHtml = `<span class="badge-pill verified" style="font-size:10px;">✓ SP APPROVED FOR YOU</span>`;
      } else if (pendReq) {
        badgeHtml = `<span class="badge-pill warning" style="font-size:10px;">⏳ PENDING SP APPROVAL</span>`;
      } else if (isRestricted) {
        badgeHtml = `<span class="badge-pill critical" style="font-size:10px;">🔒 SP ACCESS REQUIRED</span>`;
      }

      return `
        <div class="doc-card state-${d.integrity_status}" onclick="window.CustodyApp.onNodeSelected('${d.document_id}')">
          <div class="doc-card-header">
            <div>
              <span class="doc-id-tag">${d.document_id}</span>
              <div class="doc-card-title">${d.title}</div>
            </div>
            <span class="badge-pill ${d.integrity_status.toLowerCase()}">${d.integrity_status}</span>
          </div>

          <div style="font-size: 12px; color: #94a3b8; line-height: 1.4;">${d.description}</div>

          <div class="doc-card-meta">
            <span class="meta-chip">📁 ${d.document_type}</span>
            <span class="meta-chip">🔒 ${d.classification}</span>
            ${d.digital_signature ? '<span class="esign-badge">✓ eSigned PKI</span>' : ''}
            ${d.external_system_source ? `<span class="meta-chip" style="color:#06b6d4;">🔗 ${d.external_system_source}</span>` : ''}
          </div>

          <div style="display:flex; justify-content:space-between; align-items:center; margin-top:12px; border-top:1px solid rgba(255,255,255,0.06); padding-top:10px;" onclick="event.stopPropagation();">
            ${badgeHtml}
            <button class="btn-primary" style="padding:6px 12px; font-size:12px;" onclick="window.CustodyApp.attemptOpenDocument('${d.document_id}')">
              <span>👁️</span> Open Viewer
            </button>
          </div>
        </div>
      `;
    }).join('');
  },

  /**
   * STRICT ACCESS CHECK BEFORE OPENING DOCUMENT:
   * 1. If user role is Supervisor (SP Dr. Sen) or Judicial Magistrate -> Allow direct viewing.
   * 2. If Document classification is Public Record -> Allow direct viewing.
   * 3. If Officer -> Check if an APPROVED access request exists FOR THIS SPECIFIC OFFICER ID!
   * 4. IF NOT APPROVED -> BLOCK & Show Permission Modal!
   */
  attemptOpenDocument(docId) {
    const doc = this.allCaseDocs.find(d => d.document_id === docId);
    if (!doc) return;
    this.currentDocNode = doc;

    const role = this.currentUser ? this.currentUser.role : 'Investigator';
    const currentUserId = this.currentUser ? this.currentUser.user_id : null;
    const isSupervisorOrJudge = (role === 'Supervisor' || role === 'Judicial Magistrate');
    const isPublic = (doc.classification === 'Public Record');

    if (isSupervisorOrJudge || isPublic) {
      window.SecureViewer.open(doc, null, { name: this.currentUser ? this.currentUser.name : 'Officer', badge_number: this.currentUser ? this.currentUser.badge_number : 'IND-NCRB' });
      return;
    }

    // STRICT CHECK: Approved token must match document_id AND requester_id!
    const approvedReq = this.accessRequests.find(r => 
      r.document_id === docId && 
      r.requester_id === currentUserId && 
      r.status === 'APPROVED'
    );

    if (approvedReq) {
      window.SecureViewer.open(doc, approvedReq, { name: this.currentUser ? this.currentUser.name : 'Officer', badge_number: this.currentUser ? this.currentUser.badge_number : 'IND-NCRB' });
    } else {
      // BLOCK OPENING & SHOW PERMISSION MODAL
      this.showPermissionModal(doc);
    }
  },

  showPermissionModal(doc) {
    if (!doc) return;
    this.currentDocNode = doc;

    document.getElementById('perm-doc-id').innerText = doc.document_id;
    document.getElementById('perm-doc-title').innerText = doc.title;
    document.getElementById('perm-doc-class').innerText = doc.classification;

    const currentUserId = this.currentUser ? this.currentUser.user_id : null;
    const pending = this.accessRequests.find(r => r.document_id === doc.document_id && r.requester_id === currentUserId && r.status === 'PENDING');
    const statusBox = document.getElementById('perm-status-box');

    if (pending) {
      statusBox.innerHTML = `Status: <strong style="color:#f59e0b;">PENDING SUPERVISOR APPROVAL (Request #${pending.request_id})</strong><br><span style="font-size:11px; color:#94a3b8;">Logout and log in as SP Dr. Sen (Supervisor) to review & approve in Supervisor Queue.</span>`;
    } else {
      statusBox.innerHTML = `Status: <strong style="color:#ef4444;">NO SUPERVISOR CLEARANCE FOR ${this.currentUser ? this.currentUser.name.toUpperCase() : 'OFFICER'}</strong><br><span style="font-size:11px; color:#94a3b8;">Click below to submit an official access request to SP Dr. Sen.</span>`;
    }

    document.getElementById('permission-modal').classList.add('active');
  },

  submitAccessRequest(docId, reason) {
    if (!this.currentUser) return;

    fetch('/api/access-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        document_id: docId,
        user_id: this.currentUser.user_id,
        requested_action: 'VIEW',
        purpose_reason: reason || 'Official Case Investigation Review'
      })
    })
    .then(r => r.json())
    .then(req => {
      document.getElementById('permission-modal').classList.remove('active');
      alert(`ACCESS REQUEST SUBMITTED!\nRequest ID: ${req.request_id}\nDocument: ${docId}\nOfficer: ${this.currentUser.name} (${this.currentUser.user_id})\nStatus: PENDING SUPERVISOR APPROVAL.\n\nThe document CANNOT be opened until SP Dr. Sen approves it for your officer ID. Logout and log in as SP Dr. Sen to approve!`);
      this.reloadCurrentCase();
    });
  },

  loadAccessQueue(renderView = true) {
    fetch('/api/access-requests')
      .then(r => r.json())
      .then(requests => {
        this.accessRequests = requests;
        const pendingCount = requests.filter(r => r.status === 'PENDING').length;
        const badge = document.getElementById('pending-count-badge');
        if (pendingCount > 0) {
          badge.innerText = pendingCount;
          badge.style.display = 'inline-block';
        } else {
          badge.style.display = 'none';
        }

        this.renderDocCards(this.allCaseDocs);

        if (renderView && this.currentUser && this.currentUser.role === 'Supervisor') {
          const container = document.getElementById('access-queue-container');
          if (!requests || requests.length === 0) {
            container.innerHTML = '<div style="color:#64748b; font-size:14px;">No pending supervisor access requests.</div>';
            return;
          }

          container.innerHTML = requests.map(req => `
            <div style="background: rgba(30,41,59,0.6); border:1px solid rgba(255,255,255,0.08); border-radius:10px; padding:16px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center;">
              <div>
                <div style="font-weight:800; color:#38bdf8; font-size:14px;">${req.request_id} &bull; Document ${req.document_id}</div>
                <div style="font-size:13px; color:#e2e8f0; margin-top:2px;">Requester: <strong>${req.requester_name}</strong> (${req.requester_role} &bull; ID: ${req.requester_id})</div>
                <div style="font-size:12px; color:#94a3b8; margin-top:2px;">Purpose: ${req.purpose_reason} | Action: ${req.requested_action}</div>
                <div style="font-size:11px; margin-top:4px;">Status: <strong style="color:${req.status === 'APPROVED' ? '#10b981' : '#f59e0b'}">${req.status}</strong> ${req.session_token ? '| Token: ' + req.session_token : ''}</div>
              </div>
              <div>
                ${req.status === 'PENDING' ? `
                  <button class="btn-primary" onclick="window.CustodyApp.approveAccessRequest('${req.request_id}')">
                    <span>✓</span> Approve & Grant Access Token for ${req.requester_name.split(' ')[0]}
                  </button>
                ` : `<span class="badge-pill verified">APPROVED BY SUPERVISOR</span>`}
              </div>
            </div>
          `).join('');
        }
      });
  },

  approveAccessRequest(reqId) {
    if (!this.currentUser || this.currentUser.role !== 'Supervisor') {
      alert('FORBIDDEN: Only Superintendent of Police (Supervisor) can approve access requests!');
      return;
    }

    fetch(`/api/access-requests/${reqId}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ approver_id: this.currentUser.user_id, approver_role: this.currentUser.role })
    })
    .then(r => {
      if (!r.ok) throw new Error('Forbidden');
      return r.json();
    })
    .then(req => {
      alert(`SUPERVISOR APPROVED!\nRequest: ${req.request_id}\nRequester: ${req.requester_name} (${req.requester_id})\nSession Token: ${req.session_token}\nValid Until: ${req.expires_at}\n\nDocument ${req.document_id} is now unlocked ONLY FOR ${req.requester_name}!`);
      this.loadAccessQueue(true);
      this.reloadCurrentCase();
    })
    .catch(err => {
      alert('FORBIDDEN: Only Superintendent of Police (Supervisor) can approve requests!');
    });
  },

  renderGraphView() {
    if (!this.graphData) return;
    window.CustodyGraph.init('graph-viewport-container', (node) => this.onNodeSelected(node.document_id));
    window.CustodyGraph.render(this.graphData.nodes, this.graphData.links || this.graphData.edges || []);
  },

  onNodeSelected(docId) {
    let node = typeof docId === 'string' ? this.allCaseDocs.find(d => d.document_id === docId) : docId;
    if (!node) return;

    this.currentDocNode = node;
    const drawer = document.getElementById('drawer-panel');

    document.getElementById('d-id').innerText = node.document_id;
    document.getElementById('d-title').innerText = node.title;
    document.getElementById('d-hash').innerText = node.current_hash || 'N/A';

    const pdfBtn = document.getElementById('btn-download-pdf');
    if (pdfBtn) {
      pdfBtn.href = node.file_path || `/documents/${node.document_id}.pdf`;
    }

    const statusEl = document.getElementById('d-status-badge');
    statusEl.className = `badge-pill ${node.integrity_status.toLowerCase()}`;
    statusEl.innerText = node.integrity_status;

    const explainBtn = document.getElementById('btn-explain-why');
    explainBtn.style.display = (node.integrity_status === 'REVIEW_REQUIRED') ? 'inline-flex' : 'none';

    fetch(`/api/documents/${node.document_id}`)
      .then(r => r.json())
      .then(detail => {
        const auditList = document.getElementById('d-audit-logs-list');
        if (detail.audit_logs && detail.audit_logs.length > 0) {
          auditList.innerHTML = detail.audit_logs.map(a => `
            <div style="padding: 8px 10px; background: rgba(30,41,59,0.5); border-radius: 6px; margin-bottom: 6px; font-size: 11px;">
              <div style="display:flex; justify-content:space-between; font-weight:700; color:#f3f4f6;">
                <span>${a.event_type}</span>
                <span style="color:#64748b;">${a.timestamp}</span>
              </div>
              <div style="color:#94a3b8; margin-top:2px;">${a.details}</div>
            </div>
          `).join('');
        } else {
          auditList.innerHTML = '<div style="font-size:12px; color:#64748b;">No audit records.</div>';
        }
      });

    drawer.classList.add('open');
  },

  submitDocumentUpload() {
    const title = document.getElementById('up-title').value.trim();
    const docType = document.getElementById('up-type').value;
    const classification = document.getElementById('up-class').value;
    const desc = document.getElementById('up-desc').value.trim();
    const content = document.getElementById('up-content').value.trim();
    const fileInput = document.getElementById('up-file');

    if (!title && (!fileInput.files || fileInput.files.length === 0)) {
      alert('Please enter a Document Title or select a physical PDF file to upload.');
      return;
    }

    const formData = new FormData();
    formData.append('case_id', this.currentCaseId);
    formData.append('document_type', docType);
    formData.append('title', title || (fileInput.files[0] ? fileInput.files[0].name : 'Uploaded Physical Document'));
    formData.append('description', desc || title);
    formData.append('classification', classification);
    formData.append('content_text', content);
    formData.append('user_id', this.currentUser ? this.currentUser.user_id : 'OFF-001');

    if (fileInput.files && fileInput.files.length > 0) {
      formData.append('file', fileInput.files[0]);
    }

    fetch('/api/documents/upload', {
      method: 'POST',
      body: formData
    })
    .then(r => r.json())
    .then(res => {
      document.getElementById('upload-modal').classList.remove('active');
      alert(`SUCCESS: Physical File ${res.document_id} uploaded!\nFile Path: ${res.file_path}\nSHA-256 Hash: ${res.hash}\neSigned PKI & Blockchain Block #${res.blockchain_block} Committed.`);
      this.reloadCurrentCase();
    })
    .catch(err => {
      alert('Upload failed. Please check file format.');
    });
  },

  loadBlockchainLedger() {
    fetch('/api/blockchain')
      .then(r => r.json())
      .then(blocks => {
        const container = document.getElementById('blockchain-ledger-container');
        container.innerHTML = blocks.map(b => `
          <div class="block-card">
            <div class="block-header">
              <span class="block-num">BLOCK #${b.block_number} &bull; ${b.tx_id}</span>
              <span style="font-size:11px; color:#94a3b8;">${b.timestamp}</span>
            </div>
            <div style="font-size:13px; font-weight:700; color:#10b981;">ACTION: ${b.action}</div>
            <div style="font-size:12px; color:#e2e8f0;">Target Document: <strong>${b.document_id}</strong></div>
            <div class="block-hash">Block Hash: ${b.block_hash}</div>
            <div class="block-hash" style="color:#64748b;">Previous Hash: ${b.previous_hash}</div>
          </div>
        `).join('');
      });
  },

  loadPoliceAssets() {
    fetch('/api/assets')
      .then(r => r.json())
      .then(assets => {
        const container = document.getElementById('police-assets-container');
        container.innerHTML = assets.map(a => `
          <div class="doc-card">
            <div>
              <span class="doc-id-tag">${a.asset_id}</span>
              <div class="doc-card-title">${a.asset_name}</div>
              <div style="font-size:12px; color:#94a3b8; margin-top:4px;">Serial: ${a.serial_number}</div>
            </div>
            <div style="font-size:12px; color:#e2e8f0; margin-top:8px;">
              <div>Location: <strong>${a.location}</strong></div>
              <div>Case ID: <strong>${a.case_id}</strong></div>
              <div style="margin-top:4px;">Status: <span class="badge-pill verified" style="display:inline-flex;">${a.status}</span></div>
            </div>
          </div>
        `).join('');
      });
  },

  loadAuditLedger() {
    fetch('/api/audit')
      .then(r => r.json())
      .then(logs => {
        const container = document.getElementById('audit-trail-container');
        container.innerHTML = logs.map(a => `
          <div style="background: rgba(30,41,59,0.5); border-radius:8px; padding:12px; margin-bottom:10px; border:1px solid rgba(255,255,255,0.08);">
            <div style="display:flex; justify-content:space-between; font-weight:700; color:#3b82f6; font-size:13px;">
              <span>${a.event_id} &bull; ${a.event_type}</span>
              <span style="color:#64748b; font-size:11px;">${a.timestamp}</span>
            </div>
            <div style="color:#e2e8f0; font-size:12px; margin-top:4px;">${a.details}</div>
            <div style="font-size:11px; color:#64748b; margin-top:4px;">Actor: ${a.actor_name} (${a.actor_id}) ${a.document_id ? '| Doc: ' + a.document_id : ''}</div>
          </div>
        `).join('');
      });
  },

  triggerTamperDemo(docId) {
    fetch(`/api/documents/${docId}/trigger-tamper`, { method: 'POST' })
      .then(r => r.json())
      .then(res => {
        alert(`PRIMARY DEMO TRIGGER EXECUTED: Integrity failure simulated for ${docId}! Cryptographic hash mismatch detected. Downstream nodes updated to REVIEW_REQUIRED.`);
        this.reloadCurrentCase();
      });
  },

  resetTamper(docId) {
    fetch(`/api/documents/${docId}/reset-tamper`, { method: 'POST' })
      .then(r => r.json())
      .then(res => {
        alert(`Document ${docId} restored to pristine state. Integrity status verified.`);
        this.reloadCurrentCase();
      });
  },

  verifyIntegrity(docId) {
    fetch(`/api/documents/${docId}/verify-integrity`, { method: 'POST' })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'VERIFIED') {
          alert(`VERIFIED: Content SHA-256 hash matches recorded reference:\n${res.calculated_hash}`);
        } else {
          alert(`INTEGRITY MISMATCH DETECTED for ${docId}!\nCalculated: ${res.calculated_hash}\nRecorded: ${res.recorded_hash}`);
        }
        this.reloadCurrentCase();
      });
  }
};

document.addEventListener('DOMContentLoaded', () => {
  window.CustodyApp.init();
});
