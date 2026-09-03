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
  vocabulary: null,
  authToken: null,

  init() {
    this.authToken = localStorage.getItem('ncrb_token');
    this.bindEvents();
    this.loadVocabulary();
    this.checkSession();
  },

  /**
   * Every call to the API goes through here so the session token is always attached.
   * The server identifies the caller from that token — the client never asserts its own
   * user id or role, which is what stopped one officer's clearance showing up as another's.
   */
  api(path, options = {}) {
    const headers = Object.assign({}, options.headers || {});
    if (this.authToken) {
      headers['Authorization'] = `Bearer ${this.authToken}`;
    }

    return fetch(path, Object.assign({}, options, { headers })).then(response => {
      if (response.status === 401) {
        this.handleSessionExpiry();
        throw new Error('Your session has expired. Please sign in again.');
      }
      return response;
    });
  },

  /** Read a JSON body, turning any error status into a rejection carrying the server's message. */
  apiJson(path, options = {}) {
    return this.api(path, options).then(async (response) => {
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.detail || `Request failed (HTTP ${response.status}).`);
      }
      return payload;
    });
  },

  handleSessionExpiry() {
    this.authToken = null;
    this.currentUser = null;
    this.accessRequests = [];
    localStorage.removeItem('ncrb_token');
    localStorage.removeItem('ncrb_user');
    document.getElementById('login-screen-overlay').style.display = 'flex';
  },

  /**
   * Pull the controlled vocabulary from the backend and build the upload dropdowns from it,
   * so the form can never offer a document type or relationship the server would reject.
   */
  loadVocabulary() {
    return this.api('/api/vocabulary')
      .then(r => r.json())
      .then(vocab => {
        this.vocabulary = vocab;

        const fill = (elementId, values) => {
          const select = document.getElementById(elementId);
          if (!select) return;
          select.innerHTML = values
            .map(value => `<option value="${value}">${value}</option>`)
            .join('');
        };

        fill('up-type', vocab.document_types);
        fill('up-class', vocab.classifications);
        fill('up-relationship', vocab.relationship_types);

        // Confidential is the safe default for a new evidentiary record
        const classSelect = document.getElementById('up-class');
        if (classSelect && vocab.classifications.includes('Confidential')) {
          classSelect.value = 'Confidential';
        }

        const fileInput = document.getElementById('up-file');
        if (fileInput && vocab.allowed_file_extensions) {
          fileInput.setAttribute('accept', vocab.allowed_file_extensions.join(','));
        }

        // The repository filter compares against the normalised type the graph API returns,
        // so it has to offer the same canonical list.
        const repoFilter = document.getElementById('filter-type-select');
        if (repoFilter) {
          repoFilter.innerHTML = '<option value="">All Document Types</option>' +
            vocab.document_types
              .map(value => `<option value="${value}">${value}</option>`)
              .join('');
        }
      })
      .catch(() => {
        console.warn('Could not load the controlled vocabulary; upload form may be incomplete.');
      });
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
        this.api(`/api/documents/search?q=${encodeURIComponent(q)}`)
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
      this.openUploadModal();
    };

    // Upload Submission
    document.getElementById('btn-submit-upload').onclick = () => {
      this.submitDocumentUpload();
    };

    // Keep the lineage preview in step with the chosen parents / relationship
    const parentSelect = document.getElementById('up-parents');
    const relationshipSelect = document.getElementById('up-relationship');
    if (parentSelect) parentSelect.onchange = () => this.updateLineagePreview();
    if (relationshipSelect) relationshipSelect.onchange = () => this.updateLineagePreview();

    // Graph View Controls
    const graphControls = {
      'btn-add-node': () => this.openUploadModal({ fromGraph: true }),
      'btn-zoom-in': () => window.CustodyGraph.zoomBy(1.3),
      'btn-zoom-out': () => window.CustodyGraph.zoomBy(1 / 1.3),
      'btn-zoom-fit': () => window.CustodyGraph.fitToView(),
      'btn-clear-focus': () => window.CustodyGraph.render(
        window.CustodyGraph.nodesData,
        window.CustodyGraph.edgesData
      )
    };
    Object.entries(graphControls).forEach(([id, handler]) => {
      const el = document.getElementById(id);
      if (el) el.onclick = handler;
    });

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
      this.authToken = res.auth_token;
      this.currentUser = res.user;
      localStorage.setItem('ncrb_token', res.auth_token);
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
    if (!stored || !this.authToken) {
      this.handleSessionExpiry();
      return;
    }

    this.currentUser = JSON.parse(stored);
    document.getElementById('login-screen-overlay').style.display = 'none';
    this.updateUserProfileUI();
    this.loadCases();
  },

  logoutUser() {
    const finish = () => {
      this.authToken = null;
      this.currentUser = null;
      this.accessRequests = [];
      localStorage.removeItem('ncrb_token');
      localStorage.removeItem('ncrb_user');
      document.getElementById('login-screen-overlay').style.display = 'flex';
    };

    if (!this.authToken) {
      finish();
      return;
    }

    // The server ends the session behind the token and revokes that officer's clearances
    this.api('/api/auth/logout', { method: 'POST' })
      .catch(() => {})
      .finally(finish);
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
    this.api('/api/cases')
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
    return this.api(`/api/cases/${this.currentCaseId}/graph`)
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
      container.innerHTML = '<div style="color:var(--text-muted); font-size:14px;">No documents match the search criteria.</div>';
      return;
    }

    const currentUserId = this.currentUser ? this.currentUser.user_id : null;
    const role = this.currentUser ? this.currentUser.role : null;

    const vocab = this.vocabulary || {};
    const privilegedRoles = vocab.privileged_read_roles || [];
    const publicClass = vocab.public_classification || 'Public Record';
    const hasRolePrivilege = privilegedRoles.indexOf(role) !== -1;

    container.innerHTML = docs.map(d => {
      const isRestricted = d.classification !== publicClass;

      // this.accessRequests only ever holds the caller's own requests unless they are the
      // SP, because the server scopes the list. The requester_id match is a second guard
      // so a supervisor reviewing the queue never sees someone else's grant as their own.
      const appReq = this.accessRequests.find(r => r.document_id === d.document_id && r.requester_id === currentUserId && r.status === 'APPROVED');
      const pendReq = this.accessRequests.find(r => r.document_id === d.document_id && r.requester_id === currentUserId && r.status === 'PENDING');

      let badgeHtml = '';
      if (!isRestricted) {
        badgeHtml = `<span class="badge-pill info" style="font-size:10px;">PUBLIC RECORD</span>`;
      } else if (hasRolePrivilege) {
        badgeHtml = `<span class="badge-pill verified" style="font-size:10px;">✓ ${role.toUpperCase()} ACCESS</span>`;
      } else if (appReq) {
        badgeHtml = `<span class="badge-pill verified" style="font-size:10px;">✓ SP APPROVED FOR YOU</span>`;
      } else if (pendReq) {
        badgeHtml = `<span class="badge-pill warning" style="font-size:10px;">⏳ PENDING SP APPROVAL</span>`;
      } else {
        badgeHtml = `<span class="badge-pill critical" style="font-size:10px;">🔒 SP ACCESS REQUIRED</span>`;
      }

      const title = this.displayDocumentTitle(d);
      const description = this.displayDocumentDescription(d);
      const classChip = isRestricted ? 'meta-chip' : 'meta-chip public';

      return `
        <div class="doc-card state-${d.integrity_status}" onclick="window.CustodyApp.onNodeSelected('${d.document_id}')">
          <div class="doc-card-header">
            <div>
              <span class="doc-id-tag">${d.document_id}</span>
              <div class="doc-card-title">${title}</div>
            </div>
            <span class="badge-pill ${d.integrity_status.toLowerCase()}">${d.integrity_status}</span>
          </div>

          ${description ? `<div class="doc-card-desc">${description}</div>` : ''}

          <div class="doc-card-meta">
            <span class="meta-chip">📁 ${d.document_type}</span>
            <span class="${classChip}">🔒 ${d.classification}</span>
            ${d.digital_signature ? '<span class="esign-badge">✓ eSigned PKI</span>' : ''}
            ${d.external_system_source ? `<span class="meta-chip source">🔗 ${d.external_system_source}</span>` : ''}
          </div>

          <div class="doc-card-footer" onclick="event.stopPropagation();">
            ${badgeHtml}
            <button class="btn-primary" onclick="window.CustodyApp.attemptOpenDocument('${d.document_id}')">
              <span>👁️</span> Open Secure Preview
            </button>
          </div>
        </div>
      `;
    }).join('');
  },

  displayDocumentTitle(doc) {
    return String(doc.title || '')
      .replace(/^Court Copy \(PII Redacted\)\s+[—–-]\s+/, 'Court Copy — ');
  },

  displayDocumentDescription(doc) {
    return String(doc.description || '').replace(/[.…]{2,}\s*$/, '.').trim();
  },

  /**
   * The server decides whether this document may be opened. Asking it rather than
   * reasoning about roles and grants here means the preview and the
   * repository badges all follow one rule, evaluated against the signed-in officer.
   */
  attemptOpenDocument(docId) {
    const doc = this.allCaseDocs.find(d => d.document_id === docId);
    if (!doc) return;
    this.currentDocNode = doc;

    this.apiJson(`/api/documents/${docId}/access-check`)
      .then(verdict => {
        if (!verdict.allowed) {
          this.showPermissionModal(doc, verdict);
          return;
        }

        const grant = verdict.request_id
          ? { request_id: verdict.request_id, expires_at: verdict.expires_at }
          : null;

        window.SecureViewer.open(doc, grant, {
          name: this.currentUser ? this.currentUser.name : 'Officer',
          badge_number: this.currentUser ? this.currentUser.badge_number : 'IND-NCRB'
        });
      })
      .catch(err => alert(err.message));
  },

  /** `verdict` is the server's access-check result, used to explain exactly why access failed. */
  showPermissionModal(doc, verdict = null) {
    if (!doc) return;
    this.currentDocNode = doc;

    document.getElementById('perm-doc-id').innerText = doc.document_id;
    document.getElementById('perm-doc-title').innerText = doc.title;
    document.getElementById('perm-doc-class').innerText = doc.classification;

    const statusBox = document.getElementById('perm-status-box');
    const officer = this.currentUser ? this.currentUser.name : 'this officer';
    const reason = verdict ? verdict.reason : 'NO_CLEARANCE';

    const headline = {
      PENDING_APPROVAL: ['var(--status-warning)', 'PENDING SUPERVISOR APPROVAL'],
      GRANT_EXPIRED: ['var(--status-warning)', 'CLEARANCE EXPIRED'],
      NO_CLEARANCE: ['var(--status-critical)', `NO SUPERVISOR CLEARANCE FOR ${officer.toUpperCase()}`]
    }[reason] || ['var(--status-critical)', `ACCESS DENIED FOR ${officer.toUpperCase()}`];

    const detail = verdict && verdict.message
      ? verdict.message
      : 'Submit an official access request to the Superintendent of Police.';

    statusBox.innerHTML = `
      Status: <strong style="color:${headline[0]};">${headline[1]}</strong>
      <br><span style="font-size:11px; color:var(--text-secondary);">${detail}</span>
    `;

    // Nothing to request while one is already in flight
    const submitBtn = document.getElementById('btn-submit-perm-request');
    if (submitBtn) submitBtn.style.display = reason === 'PENDING_APPROVAL' ? 'none' : '';

    document.getElementById('permission-modal').classList.add('active');
  },

  submitAccessRequest(docId, reason) {
    if (!this.currentUser) return;

    // The requester is taken from the session token server-side, not sent from here
    this.apiJson('/api/access-requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        document_id: docId,
        requested_action: 'VIEW',
        purpose_reason: reason || 'Official case investigation review'
      })
    })
      .then(req => {
        document.getElementById('permission-modal').classList.remove('active');
        alert(
          `ACCESS REQUEST SUBMITTED\n\n` +
          `Request ID: ${req.request_id}\nDocument: ${docId}\n` +
          `Officer: ${req.requester_name} (${req.requester_id})\n` +
          `Status: PENDING SUPERVISOR APPROVAL\n\n` +
          `The document stays locked until SP Dr. Sen approves it for your officer ID. ` +
          `This clearance will apply to you alone.`
        );
        this.reloadCurrentCase();
      })
      .catch(err => alert(`REQUEST NOT SUBMITTED\n\n${err.message}`));
  },

  loadAccessQueue(renderView = true) {
    this.api('/api/access-requests')
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
            container.innerHTML = '<div style="color:var(--text-muted); font-size:14px;">No pending supervisor access requests.</div>';
            return;
          }

          container.innerHTML = requests.map(req => `
            <div style="background: var(--bg-card); border:1px solid var(--border-light); border-left:3px solid var(--saffron); border-radius:var(--radius); padding:16px; margin-bottom:12px; display:flex; justify-content:space-between; align-items:center; box-shadow: var(--shadow-sm);">
              <div>
                <div style="font-weight:800; color:var(--accent-blue); font-size:14px;">${req.request_id} &bull; Document ${req.document_id}</div>
                <div style="font-size:13px; color:var(--text-primary); margin-top:2px;">Requester: <strong>${req.requester_name}</strong> (${req.requester_role} &bull; ID: ${req.requester_id})</div>
                <div style="font-size:12px; color:var(--text-secondary); margin-top:2px;">Purpose: ${req.purpose_reason} | Action: ${req.requested_action}</div>
                <div style="font-size:11px; margin-top:4px;">Status: <strong style="color:${req.status === 'APPROVED' ? 'var(--status-verified)' : 'var(--status-warning)'}">${req.status}</strong> ${req.session_token ? '| Token: ' + req.session_token : ''}</div>
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
    // The approver is the signed-in user; the server rejects anyone who is not the SP
    this.apiJson(`/api/access-requests/${reqId}/approve`, { method: 'POST' })
      .then(req => {
        alert(
          `SUPERVISOR APPROVED\n\n` +
          `Request: ${req.request_id}\n` +
          `Requester: ${req.requester_name} (${req.requester_id})\n` +
          `Session Token: ${req.session_token}\n` +
          `Valid Until: ${req.expires_at}\n\n` +
          `Document ${req.document_id} is now unlocked for ${req.requester_name} only.`
        );
        this.loadAccessQueue(true);
        this.reloadCurrentCase();
      })
      .catch(err => alert(`APPROVAL FAILED\n\n${err.message}`));
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

    const statusEl = document.getElementById('d-status-badge');
    statusEl.className = `badge-pill ${node.integrity_status.toLowerCase()}`;
    statusEl.innerText = node.integrity_status;

    const explainBtn = document.getElementById('btn-explain-why');
    explainBtn.style.display = (node.integrity_status === 'REVIEW_REQUIRED') ? 'inline-flex' : 'none';

    this.api(`/api/documents/${node.document_id}`)
      .then(r => r.json())
      .then(detail => {
        const auditList = document.getElementById('d-audit-logs-list');
        if (detail.audit_logs && detail.audit_logs.length > 0) {
          auditList.innerHTML = detail.audit_logs.map(a => `
            <div style="padding: 8px 10px; background: var(--bg-subtle); border: 1px solid var(--border-light); border-radius: var(--radius); margin-bottom: 6px; font-size: 11px;">
              <div style="display:flex; justify-content:space-between; font-weight:700; color:var(--text-primary);">
                <span>${a.event_type}</span>
                <span style="color:var(--text-muted);">${a.timestamp}</span>
              </div>
              <div style="color:var(--text-secondary); margin-top:2px;">${a.details}</div>
            </div>
          `).join('');
        } else {
          auditList.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">No audit records.</div>';
        }
      });

    drawer.classList.add('open');
  },

  /**
   * Open the digitisation form. The parent picker is rebuilt from the current case each
   * time, and when a node is already selected in the graph it is pre-selected as the
   * parent, so "add document" from the graph lands the new node in the right place.
   */
  openUploadModal({ fromGraph = false } = {}) {
    this.populateParentPicker(fromGraph && this.currentDocNode ? this.currentDocNode.document_id : null);
    document.getElementById('upload-modal').classList.add('active');
  },

  populateParentPicker(preselectId = null) {
    const select = document.getElementById('up-parents');
    if (!select) return;

    this.api(`/api/cases/${this.currentCaseId}/documents`)
      .then(r => r.json())
      .then(docs => {
        select.innerHTML = docs.map(d => `
          <option value="${d.document_id}">${d.document_id} — ${d.title}</option>
        `).join('');

        if (preselectId) {
          const option = [...select.options].find(o => o.value === preselectId);
          if (option) option.selected = true;
        }
        this.updateLineagePreview();
      })
      .catch(() => {
        select.innerHTML = '';
        this.updateLineagePreview();
      });
  },

  selectedParentIds() {
    const select = document.getElementById('up-parents');
    if (!select) return [];
    return [...select.selectedOptions].map(o => o.value);
  },

  updateLineagePreview() {
    const preview = document.getElementById('up-lineage-preview');
    if (!preview) return;

    const parents = this.selectedParentIds();
    const relationship = document.getElementById('up-relationship');
    const relationshipValue = relationship ? relationship.value : 'derived_from';

    if (parents.length === 0) {
      preview.innerHTML = 'Will be added as a <strong>new root node</strong> with no parent.';
      return;
    }

    preview.innerHTML = `
      New node will be linked as <strong>${relationshipValue}</strong>
      ${parents.length === 1 ? 'of' : `of all ${parents.length} of`}
      <strong>${parents.join(', ')}</strong>.
    `;
  },

  submitDocumentUpload() {
    const title = document.getElementById('up-title').value.trim();
    const docType = document.getElementById('up-type').value;
    const classification = document.getElementById('up-class').value;
    const desc = document.getElementById('up-desc').value.trim();
    const content = document.getElementById('up-content').value.trim();
    const relationship = document.getElementById('up-relationship').value;
    const fileInput = document.getElementById('up-file');
    const parentIds = this.selectedParentIds();

    if (!title && (!fileInput.files || fileInput.files.length === 0)) {
      alert('Please enter a Document Title or select a physical file to upload.');
      return;
    }

    const submitBtn = document.getElementById('btn-submit-upload');
    const originalLabel = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>⏳</span> Hashing, eSigning & committing to ledger...';

    const formData = new FormData();
    formData.append('case_id', this.currentCaseId);
    formData.append('document_type', docType);
    formData.append('title', title);
    formData.append('description', desc || title);
    formData.append('classification', classification);
    formData.append('content_text', content);
    formData.append('relationship_type', relationship);
    formData.append('parent_doc_ids', JSON.stringify(parentIds));

    if (fileInput.files && fileInput.files.length > 0) {
      formData.append('file', fileInput.files[0]);
    }

    this.api('/api/documents/upload', { method: 'POST', body: formData })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          // Surface the server's validation message rather than a generic failure
          throw new Error(payload.detail || `Upload rejected (HTTP ${response.status}).`);
        }
        return payload;
      })
      .then(res => {
        document.getElementById('upload-modal').classList.remove('active');
        this.resetUploadForm();

        const lineage = res.parent_document_ids && res.parent_document_ids.length
          ? `Linked as ${res.relationship_type} of ${res.parent_document_ids.join(', ')}.`
          : 'Added as a new root node.';

        alert(
          `DOCUMENT ${res.document_id} COMMITTED\n\n` +
          `${res.document_type} — ${res.title}\n` +
          `Classification: ${res.classification}\n` +
          `SHA-256: ${res.hash}\n` +
          `eSigned & sealed in blockchain block #${res.blockchain_block}.\n\n${lineage}`
        );

        // Centre and flash the new node once the graph redraws. If the graph tab is
        // already open, reloadCurrentCase() redraws it; otherwise switching tabs does.
        window.CustodyGraph.markAsJustAdded(res.document_id);
        this.reloadCurrentCase().then(() => {
          const graphView = document.getElementById('view-graph');
          if (graphView && graphView.style.display === 'none') {
            this.switchToGraphView();
          }
        });
      })
      .catch(err => {
        alert(`UPLOAD FAILED\n\n${err.message}`);
      })
      .finally(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalLabel;
      });
  },

  resetUploadForm() {
    ['up-title', 'up-desc', 'up-content'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    const fileInput = document.getElementById('up-file');
    if (fileInput) fileInput.value = '';
  },

  /** Move to the provenance graph tab, so a newly added node is immediately visible. */
  switchToGraphView() {
    const tab = document.querySelector('.nav-tab-btn[data-view="view-graph"]');
    if (tab) tab.click();
  },

  loadBlockchainLedger() {
    this.api('/api/blockchain')
      .then(r => r.json())
      .then(blocks => {
        const container = document.getElementById('blockchain-ledger-container');
        container.innerHTML = blocks.map(b => `
          <div class="block-card">
            <div class="block-header">
              <span class="block-num">BLOCK #${b.block_number} &bull; ${b.tx_id}</span>
              <span style="font-size:11px; color:var(--text-secondary);">${b.timestamp}</span>
            </div>
            <div style="font-size:13px; font-weight:700; color:var(--status-verified);">ACTION: ${b.action}</div>
            <div style="font-size:12px; color:var(--text-primary);">Target Document: <strong>${b.document_id}</strong></div>
            <div class="block-hash">Block Hash: ${b.block_hash}</div>
            <div class="block-hash" style="color:var(--text-muted);">Previous Hash: ${b.previous_hash}</div>
          </div>
        `).join('');
      });
  },

  loadPoliceAssets() {
    this.api('/api/assets')
      .then(r => r.json())
      .then(assets => {
        const container = document.getElementById('police-assets-container');
        container.innerHTML = assets.map(a => `
          <div class="doc-card">
            <div>
              <span class="doc-id-tag">${a.asset_id}</span>
              <div class="doc-card-title">${a.asset_name}</div>
              <div style="font-size:12px; color:var(--text-secondary); margin-top:4px;">Serial: ${a.serial_number}</div>
            </div>
            <div style="font-size:12px; color:var(--text-primary); margin-top:8px;">
              <div>Location: <strong>${a.location}</strong></div>
              <div>Case ID: <strong>${a.case_id}</strong></div>
              <div style="margin-top:4px;">Status: <span class="badge-pill verified" style="display:inline-flex;">${a.status}</span></div>
            </div>
          </div>
        `).join('');
      });
  },

  loadAuditLedger() {
    this.api('/api/audit')
      .then(r => r.json())
      .then(logs => {
        const container = document.getElementById('audit-trail-container');
        container.innerHTML = logs.map(a => `
          <div style="background: var(--bg-card); border-radius:var(--radius); padding:12px; margin-bottom:10px; border:1px solid var(--border-light); border-left:3px solid var(--navy-light); box-shadow: var(--shadow-sm);">
            <div style="display:flex; justify-content:space-between; font-weight:700; color:var(--navy); font-size:13px;">
              <span>${a.event_id} &bull; ${a.event_type}</span>
              <span style="color:var(--text-muted); font-size:11px;">${a.timestamp}</span>
            </div>
            <div style="color:var(--text-primary); font-size:12px; margin-top:4px;">${a.details}</div>
            <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">Actor: ${a.actor_name} (${a.actor_id}) ${a.document_id ? '| Doc: ' + a.document_id : ''}</div>
          </div>
        `).join('');
      });
  },

  triggerTamperDemo(docId) {
    this.api(`/api/documents/${docId}/trigger-tamper`, { method: 'POST' })
      .then(r => r.json())
      .then(res => {
        alert(`PRIMARY DEMO TRIGGER EXECUTED: Integrity failure simulated for ${docId}! Cryptographic hash mismatch detected. Downstream nodes updated to REVIEW_REQUIRED.`);
        this.reloadCurrentCase();
      });
  },

  resetTamper(docId) {
    this.api(`/api/documents/${docId}/reset-tamper`, { method: 'POST' })
      .then(r => r.json())
      .then(res => {
        alert(`Document ${docId} restored to pristine state. Integrity status verified.`);
        this.reloadCurrentCase();
      });
  },

  /**
   * Fetch the original file for the secure viewer to render.
   *
   * Resolves to an object URL the viewer can point an iframe at, or to null when the
   * server holds no original file — in which case the viewer falls back to the extracted
   * text. The bytes are fetched with the session token rather than navigated to, so the
   * file is never handed to the browser as a download.
   */
  fetchDocumentForPreview(docId) {
    return this.api(`/api/documents/${docId}/preview`).then(async (response) => {
      if (response.status === 404) return null;
      if (!response.ok) {
        const payload = await response.json().catch(() => ({}));
        throw new Error(payload.detail || `Preview failed (HTTP ${response.status}).`);
      }

      const blob = await response.blob();
      return { url: URL.createObjectURL(blob), mediaType: blob.type };
    });
  },

  verifyIntegrity(docId) {
    this.api(`/api/documents/${docId}/verify-integrity`, { method: 'POST' })
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
