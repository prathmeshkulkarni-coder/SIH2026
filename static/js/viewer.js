/**
 * CUSTODY CHAIN - Controlled Secure Document Viewer
 * Implements view-only security controls, dynamic session watermarking,
 * copy/print restrictions, and active countdown timer.
 */

window.SecureViewer = {
  modalEl: null,
  timerInterval: null,

  open(documentNode, sessionInfo = null, currentUser = null) {
    let modal = document.getElementById('secure-viewer-modal');
    if (!modal) return;

    const docId = documentNode.document_id;
    const title = documentNode.title;
    const content = documentNode.content_text || 'No preview available.';
    
    const officerName = currentUser ? currentUser.name : 'Insp. Vikram Sharma (INV-204)';
    const officerBadge = currentUser ? currentUser.badge_number : 'IND-EOW-8821';
    const caseId = documentNode.case_id;
    const sessionToken = sessionInfo ? sessionInfo.session_token : 'SESS-TEMP-88192';
    const accessTime = new Date().toLocaleTimeString();

    // Populate modal markup
    document.getElementById('viewer-doc-title').innerText = `${docId} — ${title}`;
    document.getElementById('viewer-doc-classification').innerText = documentNode.classification;
    document.getElementById('viewer-content-body').innerText = content;

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
