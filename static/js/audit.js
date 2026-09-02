/**
 * CUSTODY CHAIN - Audit Trail, Impact Explainer & PII Redaction Engine
 */

window.CustodyAudit = {
  
  showExplainImpactModal(targetDocId, sourceId = null) {
    fetch(`/api/documents/${targetDocId}/explain-impact${sourceId ? '?source_id=' + sourceId : ''}`)
      .then(r => r.json())
      .then(data => {
        const modal = document.getElementById('explain-modal');
        if (!modal) return;

        document.getElementById('explain-doc-id').innerText = targetDocId;
        const bodyEl = document.getElementById('explain-modal-body');

        if (!data.path_found) {
          bodyEl.innerHTML = `
            <div class="impact-banner" style="background: rgba(16,185,129,0.1); border-color: rgba(16,185,129,0.4);">
              <div class="impact-title" style="color: #10b981;">✓ NO UNRESOLVED UPSTREAM COMPROMISE</div>
              <div class="impact-text">This document currently has no active upstream integrity mismatch.</div>
            </div>
          `;
        } else {
          let stepsHtml = data.steps.map((step, idx) => `
            <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 12px; margin-top: 8px;">
              <div style="font-size: 11px; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Step ${idx + 1}: [${step.relationship_type}]</div>
              <div style="font-size: 13px; font-weight: 600; color: #f3f4f6; margin-top: 4px;">
                <span style="color: #ef4444;">${step.from_doc_id}</span> (${step.from_title})
                <br>&darr;
                <br><span style="color: #f59e0b;">${step.to_doc_id}</span> (${step.to_title})
              </div>
              <div style="font-size: 11px; color: #64748b; margin-top: 4px; font-style: italic;">Reason: ${step.reason}</div>
            </div>
          `).join('');

          bodyEl.innerHTML = `
            <div class="impact-banner">
              <div class="impact-title">⚠ DEPENDENCY IMPACT EXPLANATION</div>
              <div class="impact-text">${data.human_explanation}</div>
            </div>
            <div style="margin-top: 12px;">
              <div style="font-size: 12px; font-weight: 700; color: #94a3b8; text-transform: uppercase;">Directional Provenance Path (${data.steps.length} hops)</div>
              ${stepsHtml}
            </div>
          `;
        }

        modal.classList.add('active');
      });
  },

  showRedactModal(docNode) {
    const modal = document.getElementById('redact-modal');
    if (!modal) return;

    document.getElementById('redact-doc-id').innerText = docNode.document_id;
    const textarea = document.getElementById('redact-content-input');
    
    // Auto-detect and suggest PII redactions
    let text = docNode.content_text;
    textarea.value = text;

    document.getElementById('btn-auto-scrub').onclick = () => {
      let scrubbed = text
        .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED EMAIL]')
        .replace(/\b\d{10}\b/g, '[REDACTED PHONE]')
        .replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[REDACTED AADHAAR]')
        .replace(/Chief Information Security Officer/gi, '[REDACTED TITLE]')
        .replace(/IT Security Lead/gi, '[REDACTED TITLE]');
      textarea.value = scrubbed;
    };

    document.getElementById('btn-submit-redaction').onclick = () => {
      const redactedText = textarea.value;
      fetch(`/api/documents/${docNode.document_id}/redact`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redacted_content: redactedText, user_id: 'INV-204' })
      })
      .then(r => r.json())
      .then(res => {
        modal.classList.remove('active');
        alert(`PII Redacted derivative created successfully: ${res.new_document.document_id}! Linked via [redacted_from] to original ${docNode.document_id}.`);
        window.CustodyApp.reloadCurrentCase();
      });
    };

    modal.classList.add('active');
  },

  showSimulationModal(docId) {
    fetch(`/api/simulation/impact`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ document_id: docId, action: 'INTEGRITY_FAILURE' })
    })
    .then(r => r.json())
    .then(res => {
      const modal = document.getElementById('sim-modal');
      if (!modal) return;

      document.getElementById('sim-doc-id').innerText = docId;
      const bodyEl = document.getElementById('sim-modal-body');

      let nodesListHtml = Object.entries(res.simulated_nodes).map(([id, info]) => `
        <div style="display: flex; justify-content: space-between; padding: 8px 12px; background: rgba(30,41,59,0.5); border-radius: 6px; margin-bottom: 6px; font-size: 12px;">
          <span><strong>${id}</strong> (${info.role})</span>
          <span class="badge-pill ${info.simulated_status === 'INTEGRITY_ISSUE' ? 'critical' : 'warning'}">${info.simulated_status}</span>
        </div>
      `).join('');

      bodyEl.innerHTML = `
        <div class="impact-banner" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.4);">
          <div class="impact-title" style="color: #6366f1;">🔬 COUNTERFACTUAL IMPACT SIMULATION (NON-DESTRUCTIVE)</div>
          <div class="impact-text">
            Simulating withdrawal or integrity compromise of <strong>${docId}</strong>.<br>
            Total Downstream Blast Radius: <strong>${res.affected_summary.total_affected} documents</strong> (${res.affected_summary.direct_count} direct, ${res.affected_summary.indirect_count} indirect).
          </div>
        </div>
        <div style="margin-top: 12px;">
          <div style="font-size: 11px; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px;">Simulated Downstream States</div>
          ${nodesListHtml}
        </div>
      `;

      modal.classList.add('active');
    });
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
