/**
 * CUSTODY CHAIN - Audit Trail, Impact Explainer & PII Redaction Engine
 */

window.CustodyAudit = {
  
  showExplainImpactModal(targetDocId, sourceId = null) {
    if (!window.CustodyApp) return;
    const path = `/api/documents/${targetDocId}/explain-impact${sourceId ? '?source_id=' + encodeURIComponent(sourceId) : ''}`;
    window.CustodyApp.apiJson(path)
      .then(data => {
        const modal = document.getElementById('explain-modal');
        if (!modal) return;

        document.getElementById('explain-doc-id').innerText = targetDocId;
        const bodyEl = document.getElementById('explain-modal-body');

        if (!data.path_found) {
          bodyEl.innerHTML = `
            <div class="impact-banner verified">
              <div class="impact-title">✓ NO UNRESOLVED UPSTREAM COMPROMISE</div>
              <div class="impact-text">This document currently has no active upstream integrity mismatch.</div>
            </div>
          `;
        } else {
          let stepsHtml = data.steps.map((step, idx) => `
            <div style="background: var(--bg-card); border: 1px solid var(--border-light); border-left: 3px solid var(--navy-light); border-radius: var(--radius); padding: 12px; margin-top: 8px;">
              <div style="font-size: 11px; color: var(--text-secondary); font-weight: 700; text-transform: uppercase;">Step ${idx + 1}: [${step.relationship_type}]</div>
              <div style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-top: 4px;">
                <span style="color: var(--status-critical);">${step.from_doc_id}</span> (${step.from_title})
                <br>&darr;
                <br><span style="color: var(--status-warning);">${step.to_doc_id}</span> (${step.to_title})
              </div>
              <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px; font-style: italic;">Reason: ${step.reason}</div>
            </div>
          `).join('');

          bodyEl.innerHTML = `
            <div class="impact-banner">
              <div class="impact-title">⚠ DEPENDENCY IMPACT EXPLANATION</div>
              <div class="impact-text">${data.human_explanation}</div>
            </div>
            <div style="margin-top: 12px;">
              <div style="font-size: 12px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase;">Directional Provenance Path (${data.steps.length} hops)</div>
              ${stepsHtml}
            </div>
          `;
        }

        modal.classList.add('active');
      })
      .catch(err => alert(err.message));
  },

  scrubPersonalDetails(text) {
    return (text || '')
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED EMAIL]')
      .replace(/\b(?:\+91[-\s]?)?[6-9]\d{9}\b/g, '[REDACTED PHONE]')
      .replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[REDACTED AADHAAR]')
      .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED IP ADDRESS]')
      .replace(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g, '[REDACTED MAC]')
      .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, '[REDACTED PAN]')
      .replace(/\b(Witness|Suspect|Accused|Complainant)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+/g, '$1 [REDACTED NAME]');
  },

  showRedactModal(docNode) {
    const modal = document.getElementById('redact-modal');
    if (!modal || !window.CustodyApp) return;

    const originalBox = document.getElementById('redact-original');
    const courtBox = document.getElementById('redact-content-input');
    document.getElementById('redact-doc-id').innerText = docNode.document_id;

    const fillBoxes = (originalText) => {
      originalBox.value = originalText;
      courtBox.value = this.scrubPersonalDetails(originalText);
    };

    fillBoxes('Loading the original text…');

    window.CustodyApp.apiJson(`/api/documents/${docNode.document_id}/access-check`)
      .then(verdict => {
        if (!verdict.allowed) {
          window.CustodyApp.showPermissionModal(docNode, verdict);
          return;
        }

        return window.CustodyApp.apiJson(`/api/documents/${docNode.document_id}`).then(detail => {
          const originalText = (detail.document && detail.document.content_text) || '';
          fillBoxes(originalText);
          modal.classList.add('active');
        });
      })
      .catch(err => alert(err.message));

    document.getElementById('btn-auto-scrub').onclick = () => {
      courtBox.value = this.scrubPersonalDetails(originalBox.value);
    };

    document.getElementById('btn-submit-redaction').onclick = () => {
      const submitBtn = document.getElementById('btn-submit-redaction');
      const originalLabel = submitBtn.innerHTML;
      submitBtn.disabled = true;
      submitBtn.innerText = 'Creating court copy…';

      window.CustodyApp.apiJson(`/api/documents/${docNode.document_id}/redact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redacted_content: courtBox.value })
      })
        .then(res => {
          modal.classList.remove('active');
          const newId = res.new_document.document_id;
          alert(
            `COURT COPY READY\n\n` +
            `Public copy: ${newId}\n` +
            `Source (unchanged): ${res.source_document_id}\n\n` +
            `A judge can open ${newId} without clearance. ` +
            `The graph now shows a redacted_from link from the original to this copy.`
          );
          window.CustodyGraph.markAsJustAdded(newId);
          window.CustodyApp.reloadCurrentCase().then(() => {
            window.CustodyApp.switchToGraphView();
          });
        })
        .catch(err => alert(`COURT COPY NOT CREATED\n\n${err.message}`))
        .finally(() => {
          submitBtn.disabled = false;
          submitBtn.innerHTML = originalLabel;
        });
    };
  },

  showSimulationModal(docId) {
    if (!window.CustodyApp) return;

    window.CustodyApp.apiJson('/api/simulation/impact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_id: docId, action: 'INTEGRITY_FAILURE' })
    })
      .then(res => {
        const modal = document.getElementById('sim-modal');
        if (!modal) return;

        document.getElementById('sim-doc-id').innerText = docId;
        const bodyEl = document.getElementById('sim-modal-body');
        const summary = res.affected_summary || {};
        const nodes = res.simulated_nodes || {};
        const total = summary.total_affected || 0;

        const nodesListHtml = Object.keys(nodes).length === 0
          ? '<div style="font-size:13px; color:var(--text-muted);">No later documents depend on this one.</div>'
          : Object.entries(nodes).map(([id, info]) => `
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 8px 12px; background: var(--bg-subtle); border: 1px solid var(--border-light); border-radius: var(--radius); margin-bottom: 6px; font-size: 12px;">
                <span>
                  <strong>${id}</strong> — ${info.title || ''}
                  <div style="font-size:11px; color:var(--text-muted);">${info.role}</div>
                </span>
                <span class="badge-pill ${info.simulated_status === 'INTEGRITY_ISSUE' ? 'critical' : 'warning'}">${info.simulated_status}</span>
              </div>
            `).join('');

        bodyEl.innerHTML = `
          <div class="impact-banner simulation">
            <div class="impact-title">WHAT IF THIS DOCUMENT WERE COMPROMISED?</div>
            <div class="impact-text">
              This is only a preview. Real files and integrity flags are unchanged.<br><br>
              If <strong>${docId}</strong> (${res.source_title || 'this document'}) were tampered with or withdrawn,
              <strong>${total} later document(s)</strong> would need review
              (${summary.direct_count || 0} direct, ${summary.indirect_count || 0} further down the chain).
            </div>
          </div>
          <div style="margin-top: 12px;">
            <div style="font-size: 11px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 6px;">Would be flagged</div>
            ${nodesListHtml}
          </div>
        `;

        modal.classList.add('active');

        if (window.CustodyGraph && typeof window.CustodyGraph.highlightLineage === 'function') {
          window.CustodyGraph.highlightLineage(docId);
        }
      })
      .catch(err => alert(`SIMULATION FAILED\n\n${err.message}`));
  },

  showReportModal(docId) {
    fetch(`/api/reports/provenance/${docId}`)
      .then(r => r.json())
      .then(data => {
        const modal = document.getElementById('report-modal');
        if (!modal) return;

        document.getElementById('report-modal-body').innerText = JSON.stringify(data, null, 2);
        modal.classList.add('active');
      });
  }
};
