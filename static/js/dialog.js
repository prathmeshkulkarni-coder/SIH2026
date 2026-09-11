/**
 * TraceX in-app dialogs — replaces browser alert().
 * Uses #app-dialog-modal from index.html.
 */
window.TraceXDialog = {
  _resolve: null,

  alert({ title = 'TraceX', message = '', tone = 'info' } = {}) {
    return new Promise((resolve) => {
      const overlay = document.getElementById('app-dialog-modal');
      const titleEl = document.getElementById('app-dialog-title');
      const bodyEl = document.getElementById('app-dialog-message');
      const headerEl = document.getElementById('app-dialog-header');
      const confirmBtn = document.getElementById('app-dialog-confirm');
      const cancelBtn = document.getElementById('app-dialog-cancel');
      if (!overlay || !titleEl || !bodyEl) {
        resolve();
        return;
      }

      this._resolve = resolve;
      titleEl.textContent = title;
      bodyEl.textContent = message;
      headerEl.className = 'modal-header' + (tone === 'error' || tone === 'critical' ? ' critical' : '');
      cancelBtn.style.display = 'none';
      confirmBtn.textContent = 'OK';
      confirmBtn.onclick = () => this._close();
      overlay.classList.add('active');
    });
  },

  _close() {
    const overlay = document.getElementById('app-dialog-modal');
    if (overlay) overlay.classList.remove('active');
    const done = this._resolve;
    this._resolve = null;
    if (done) done();
  }
};

/** Convenience alias used across the SPA */
window.uiAlert = function uiAlert(message, title = 'TraceX', tone = 'info') {
  if (window.TraceXDialog) {
    return window.TraceXDialog.alert({ title, message, tone });
  }
  return Promise.resolve();
};
