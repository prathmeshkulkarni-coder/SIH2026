/**
 * TraceX — Controlled Secure Document Viewer
 *
 * The session watermark is burned into the preview bytes by the server.
 * This UI does not paint a DOM overlay (Inspect cannot delete the mark).
 * Copy / context-menu are still blocked as belt-and-suspenders controls.
 */

window.SecureViewer = {
  modalEl: null,
  timerInterval: null,
  objectUrl: null,

  open(documentNode, sessionInfo = null, currentUser = null) {
    const modal = document.getElementById('secure-viewer-modal');
    if (!modal) return;

    const docId = documentNode.document_id;
    const title = documentNode.title;
    const content = documentNode.content_text || 'No extracted text is available for this document.';

    document.getElementById('viewer-doc-title').innerText = `${docId} — ${title}`;
    document.getElementById('viewer-doc-classification').innerText = documentNode.classification;
    document.getElementById('viewer-content-body').innerText = content;

    this.loadOriginalFile(docId);
    this.startCountdown(30 * 60);
    modal.classList.add('active');

    const contentArea = document.getElementById('viewer-content-area');
    contentArea.oncopy = (e) => {
      e.preventDefault();
      alert('SECURITY POLICY: Copying TraceX secure-preview content is prohibited and audited.');
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
   * Render the server-stamped preview. PDF toolbar is suppressed so the native
   * Download/Print chrome is hidden; any saved copy is still the watermarked bytes.
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
    if (sourceLabel) {
      sourceLabel.innerText = 'Loading TraceX session-watermarked preview…';
    }

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
          // toolbar=0 / navpanes=0 hide Chrome's PDF chrome (download / print)
          const isPdf = (file.mediaType || '').includes('pdf');
          frame.src = isPdf ? `${file.url}#toolbar=0&navpanes=0&scrollbar=1` : file.url;
          frame.style.display = 'block';
        }
        if (textBody) textBody.style.display = 'none';
        if (container) container.classList.add('showing-file');
        if (sourceLabel) {
          sourceLabel.innerText = (
            'Server-side session watermark active — officer, case, and time are burned into ' +
            'these bytes (hash-chain audited). DevTools cannot remove the mark.'
          );
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
        alert('ACCESS SESSION EXPIRED: Your time-limited TraceX secure-preview session has elapsed.');
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
