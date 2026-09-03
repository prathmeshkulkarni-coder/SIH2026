/**
 * CUSTODY CHAIN - Controlled Secure Document Viewer
 * Implements view-only security controls, dynamic session watermarking,
 * copy/print restrictions, and active countdown timer.
 */

window.SecureViewer = {
  modalEl: null,
  timerInterval: null,
  objectUrl: null,

  open(documentNode, sessionInfo = null, currentUser = null) {
    let modal = document.getElementById('secure-viewer-modal');
    if (!modal) return;

    const docId = documentNode.document_id;
    const title = documentNode.title;
    const content = documentNode.content_text || 'No extracted text is available for this document.';
    
    const officerName = currentUser ? currentUser.name : 'Insp. Vikram Sharma (INV-204)';
    const officerBadge = currentUser ? currentUser.badge_number : 'IND-EOW-8821';
    const caseId = documentNode.case_id;
    const sessionToken = sessionInfo ? sessionInfo.session_token : 'SESS-TEMP-88192';
    const accessTime = new Date().toLocaleTimeString();

    // Populate modal markup
    document.getElementById('viewer-doc-title').innerText = `${docId} — ${title}`;
    document.getElementById('viewer-doc-classification').innerText = documentNode.classification;
    document.getElementById('viewer-content-body').innerText = content;

    // The original PDF is shown here — never as a download. The server re-checks
    // supervisor clearance before streaming any bytes.
    this.loadOriginalFile(docId);

    // Build dynamic watermark text
    const watermarkHtml = `
      CONFIDENTIAL &bull; RESTRICTED VIEW<br>
      OFFICER: ${officerName} (${officerBadge})<br>
      CASE: ${caseId} &bull; SESSION: ${sessionToken}<br>
      ACCESSED: ${accessTime} &bull; PURPOSE: JUDICIAL INVESTIGATION REVIEW
    `;
    document.getElementById('viewer-watermark-overlay').innerHTML = watermarkHtml;

    // Start 30-minute countdown timer
    this.startCountdown(30 * 60);

    modal.classList.add('active');

    // Add copy/context menu prevention handlers
    const contentArea = document.getElementById('viewer-content-area');
    contentArea.oncopy = (e) => {
      e.preventDefault();
      alert('SECURITY POLICY RESTRICTION: Copying sensitive document content is prohibited and audited.');
      return false;
    };
    contentArea.oncontextmenu = (e) => {
      e.preventDefault();
      return false;
    };
  },

  close() {
    const modal = document.getElementById('secure-viewer-modal');
    if (modal) modal.classList.remove('active');
    if (this.timerInterval) clearInterval(this.timerInterval);
    this.releaseObjectUrl();

    const frame = document.getElementById('viewer-file-frame');
    const container = document.getElementById('viewer-content-area');
    const textBody = document.getElementById('viewer-content-body');
    if (frame) {
      frame.src = '';
      frame.style.display = 'none';
    }
    if (container) container.classList.remove('showing-file');
    if (textBody) textBody.style.display = '';
  },

  releaseObjectUrl() {
    if (this.objectUrl) {
      URL.revokeObjectURL(this.objectUrl);
      this.objectUrl = null;
    }
  },

  /**
   * Render the original file inside the viewer iframe. If the server has no stored
   * file, the extracted text already in the modal stays visible.
   */
  loadOriginalFile(docId) {
    const frame = document.getElementById('viewer-file-frame');
    const textBody = document.getElementById('viewer-content-body');
    const sourceLabel = document.getElementById('viewer-source-label');
    const container = document.getElementById('viewer-content-area');

    this.releaseObjectUrl();
    if (frame) {
      frame.src = '';
      frame.style.display = 'none';
    }
    if (container) container.classList.remove('showing-file');
    if (textBody) textBody.style.display = '';
    if (sourceLabel) sourceLabel.innerText = 'Loading original document…';

    if (!window.CustodyApp || typeof window.CustodyApp.fetchDocumentForPreview !== 'function') {
      if (sourceLabel) sourceLabel.innerText = 'Showing extracted text. Original file is not available.';
      return;
    }

    window.CustodyApp.fetchDocumentForPreview(docId)
      .then(file => {
        if (!file) {
          if (sourceLabel) {
            sourceLabel.innerText = 'Original file is not stored on the server. Showing extracted text.';
          }
          return;
        }

        this.objectUrl = file.url;
        if (frame) {
          frame.src = file.url;
          frame.style.display = 'block';
        }
        if (textBody) textBody.style.display = 'none';
        if (container) container.classList.add('showing-file');
        if (sourceLabel) {
          sourceLabel.innerText = 'Original document opened in a view-only session. Download is disabled.';
        }
      })
      .catch(err => {
        if (sourceLabel) {
          sourceLabel.innerText = err.message || 'Could not load the original file. Showing extracted text.';
        }
      });
  },

  startCountdown(secondsLeft) {
    if (this.timerInterval) clearInterval(this.timerInterval);
    const timerEl = document.getElementById('viewer-timer');
    
    const updateTimer = () => {
      if (secondsLeft <= 0) {
        clearInterval(this.timerInterval);
        if (timerEl) timerEl.innerText = '00:00 (SESSION EXPIRED)';
        alert('ACCESS SESSION EXPIRED: Your time-limited sensitive document session has elapsed.');
        this.close();
        return;
      }
      const mins = Math.floor(secondsLeft / 60);
      const secs = secondsLeft % 60;
      const fmt = `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
      if (timerEl) timerEl.innerText = fmt;
      secondsLeft--;
    };

    updateTimer();
    this.timerInterval = setInterval(updateTimer, 1000);
  }
};
