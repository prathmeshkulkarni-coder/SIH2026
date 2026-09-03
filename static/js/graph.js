/**
 * CUSTODY CHAIN — Hierarchical Provenance Graph Engine (SIH26190)
 * Lays the case out as a left-to-right DAG, depth assigned by BFS from the root documents.
 * Nodes are colour-coded by document type, with a legend, hover detail, lineage focus,
 * and zoom controls.
 */

window.CustodyGraph = {
  svg: null,
  svgRoot: null,
  zoomBehavior: null,
  container: null,
  nodesData: [],
  edgesData: [],
  selectedNodeId: null,
  onNodeSelectCallback: null,
  mutedTypes: new Set(),
  justAddedId: null,

  // Horizontal distance between tree levels. Cards are 190px wide, so this leaves a
  // 140px corridor between columns for the edge labels to sit in.
  LEVEL_X_DISTANCE: 330,

  /**
   * Document-type palette. Each canonical DocumentType from the backend vocabulary gets a
   * distinct hue so an officer can read the shape of a case at a glance: police-origin
   * records in navy, testimony in teal, forensics in cyan, prosecution in saffron,
   * and anything judicial in purple.
   */
  TYPE_COLORS: {
    'FIR / Police Report': '#0b3d76',
    'Witness Statement': '#0f766e',
    'Forensic & Pathology Report': '#0e7490',
    'Investigation Record': '#475b71',
    'Charge Sheet': '#c2620f',
    'Court Filing / Order': '#6d28d9',
    'Evidence & Seizure Memo': '#8a5a00',
    'Legal Notice / Judgment': '#a21caf'
  },
  FALLBACK_TYPE_COLOR: '#475b71',

  getTypeColor(type) {
    if (this.TYPE_COLORS[type]) return this.TYPE_COLORS[type];

    // Tolerate legacy spellings still sitting in older rows
    const lowered = (type || '').toLowerCase();
    const match = Object.keys(this.TYPE_COLORS).find(key => {
      const first = key.toLowerCase().split(/[\s/&]+/)[0];
      return first && lowered.includes(first);
    });
    return match ? this.TYPE_COLORS[match] : this.FALLBACK_TYPE_COLOR;
  },

  getStatusColor(status) {
    if (status === 'VERIFIED') return '#0f7b3f';
    if (status === 'REVIEW_REQUIRED') return '#8a5a00';
    return '#b42318';
  },

  init(containerId, onNodeSelect) {
    this.container = document.getElementById(containerId);
    this.onNodeSelectCallback = onNodeSelect;
    this.container.innerHTML = '';

    const svg = d3.select(this.container)
      .append('svg')
      .attr('class', 'provenance-svg')
      .attr('width', '100%')
      .attr('height', '100%');

    const defs = svg.append('defs');

    // Standard arrow
    defs.append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 32)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#93a6ba');

    // Affected arrow
    defs.append('marker')
      .attr('id', 'arrow-affected')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 32)
      .attr('refY', 0)
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#b42318');

    const g = svg.append('g').attr('class', 'main-graph-g');

    const zoom = d3.zoom()
      .scaleExtent([0.2, 2.5])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Clicking empty canvas clears the lineage focus
    svg.on('click', (event) => {
      if (event.target === svg.node()) this.clearFocus();
    });

    this.svgRoot = svg;
    this.zoomBehavior = zoom;
    this.svg = g;
  },

  render(nodes, edges) {
    if (!this.svg) return;

    this.nodesData = JSON.parse(JSON.stringify(nodes || []));
    this.edgesData = JSON.parse(JSON.stringify(edges || []));
    this.svg.selectAll('*').remove();

    this.renderTreeLayout();
    this.renderLegend();
    this.applyTypeFilter();

    if (this.justAddedId) {
      const arrivedId = this.justAddedId;
      this.justAddedId = null;
      this.focusNode(arrivedId, { flash: true });
    }
  },

  /**
   * DYNAMIC HIERARCHICAL TREE LAYOUT ENGINE
   * Flexibly calculates levels via BFS from existing root nodes.
   * Only renders existing document nodes without creating empty stage placeholders.
   */
  renderTreeLayout() {
    const height = this.container.clientHeight || 600;

    // Calculate in-degree for each node
    const inDegree = {};
    const adj = {};
    this.nodesData.forEach(n => {
      inDegree[n.document_id] = 0;
      adj[n.document_id] = [];
    });

    this.edgesData.forEach(e => {
      const src = e.source_document_id || e.source;
      const tgt = e.target_document_id || e.target;
      if (inDegree[tgt] !== undefined) inDegree[tgt]++;
      if (adj[src]) adj[src].push(tgt);
    });

    // BFS to assign tree depth/level
    const depthMap = {};
    const queue = [];

    // Roots are nodes with inDegree 0 (e.g. FIR DOC-001 or initial evidence)
    this.nodesData.forEach(n => {
      if (inDegree[n.document_id] === 0) {
        depthMap[n.document_id] = 0;
        queue.push(n.document_id);
      }
    });

    // Fallback if no 0 in-degree root exists
    if (queue.length === 0 && this.nodesData.length > 0) {
      const firstId = this.nodesData[0].document_id;
      depthMap[firstId] = 0;
      queue.push(firstId);
    }

    while (queue.length > 0) {
      const curr = queue.shift();
      const currDepth = depthMap[curr];
      (adj[curr] || []).forEach(childId => {
        if (depthMap[childId] === undefined || depthMap[childId] < currDepth + 1) {
          depthMap[childId] = currDepth + 1;
          queue.push(childId);
        }
      });
    }

    // Group nodes by tree depth level
    const levelGroups = {};
    this.nodesData.forEach(n => {
      const d = depthMap[n.document_id] || 0;
      n.depth = d;
      if (!levelGroups[d]) levelGroups[d] = [];
      levelGroups[d].push(n);
    });

    const levels = Object.keys(levelGroups).map(Number).sort((a, b) => a - b);
    const levelXDistance = this.LEVEL_X_DISTANCE;
    const startX = 120;
    const rowYDistance = 125;

    levels.forEach(level => {
      const group = levelGroups[level];
      const levelX = startX + level * levelXDistance;
      const totalGroupHeight = group.length * rowYDistance;
      const startY = Math.max(80, (height - totalGroupHeight) / 2 + 50);

      group.forEach((node, index) => {
        node.x = levelX;
        node.y = startY + index * rowYDistance;
      });
    });

    this.drawGraphElements();
  },

  /**
   * Pull apart labels that landed on top of each other.
   *
   * Every edge into a given document flattens towards that document's row near the end of
   * its curve, so a node with several parents would stack all of its labels in one spot.
   * A corridor between two columns holds no cards, so labels sharing one can be spaced out
   * vertically and then re-centred on where they started.
   */
  spreadLabelsInCorridor(anchors, minGap = 28) {
    const corridors = new Map();
    anchors.forEach((anchor, index) => {
      if (!anchor) return;
      if (!corridors.has(anchor.corridor)) corridors.set(anchor.corridor, []);
      corridors.get(anchor.corridor).push(index);
    });

    corridors.forEach(indices => {
      if (indices.length < 2) return;
      indices.sort((a, b) => anchors[a].y - anchors[b].y);

      const averageY = (list) => list.reduce((sum, i) => sum + anchors[i].y, 0) / list.length;
      const originalCentre = averageY(indices);

      for (let k = 1; k < indices.length; k++) {
        const previousY = anchors[indices[k - 1]].y;
        if (anchors[indices[k]].y - previousY < minGap) {
          anchors[indices[k]].y = previousY + minGap;
        }
      }

      const drift = originalCentre - averageY(indices);
      indices.forEach(i => { anchors[i].y += drift; });
    });
  },

  /**
   * Walk a path to the point where it crosses `targetX`.
   * These curves rise monotonically in x, so a bisection on arc length converges quickly
   * and gives the exact y on the curve rather than an approximation from the endpoints.
   */
  pointOnPathAtX(pathNode, targetX) {
    const total = pathNode.getTotalLength();
    let low = 0;
    let high = total;

    for (let i = 0; i < 24; i++) {
      const mid = (low + high) / 2;
      if (pathNode.getPointAtLength(mid).x < targetX) {
        low = mid;
      } else {
        high = mid;
      }
    }
    return pathNode.getPointAtLength((low + high) / 2);
  },

  edgeEndpoints(d) {
    const src = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
    const tgt = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
    return { src, tgt };
  },

  drawGraphElements() {
    // 1. Render Links (Edges with Date & Relationship Type)
    const linkG = this.svg.append('g').attr('class', 'links-g');
    const links = linkG.selectAll('g')
      .data(this.edgesData)
      .enter()
      .append('g')
      .attr('class', 'link-group');

    const isAffectedEdge = (d) => {
      const { src, tgt } = this.edgeEndpoints(d);
      const srcNode = this.nodesData.find(n => n.document_id === src);
      const tgtNode = this.nodesData.find(n => n.document_id === tgt);
      return (srcNode && srcNode.integrity_status === 'INTEGRITY_ISSUE') ||
             (tgtNode && tgtNode.integrity_status === 'REVIEW_REQUIRED');
    };

    const linkPaths = links.append('path')
      .attr('class', d => `graph-edge ${isAffectedEdge(d) ? 'affected-edge' : ''}`)
      .attr('marker-end', d => isAffectedEdge(d) ? 'url(#arrow-affected)' : 'url(#arrow)');

    // EDGE LABELS WITH DATE AND RELATIONSHIP TYPE
    // Stacked on two lines over an opaque pill: one line was far wider than the gap
    // between cards, so the relationship and the date both ran under the nodes.
    const linkLabels = links.append('g')
      .attr('class', 'edge-label-group');

    linkLabels.append('rect')
      .attr('class', 'edge-label-bg')
      .attr('rx', 3);

    linkLabels.append('text')
      .attr('class', 'edge-label edge-label-rel')
      .attr('text-anchor', 'middle')
      .attr('y', -2)
      .text(d => d.relationship_type || 'derived_from');

    linkLabels.append('text')
      .attr('class', 'edge-label edge-label-date')
      .attr('text-anchor', 'middle')
      .attr('y', 9)
      .text(d => (d.created_at || '2026-08-10').split(' ')[0]);

    // Size each pill to the widest of its two lines, now that they are laid out
    linkLabels.each(function () {
      const group = d3.select(this);
      const widest = Math.max(
        ...group.selectAll('text').nodes().map(node => node.getComputedTextLength())
      );
      const width = widest + 12;
      group.select('rect')
        .attr('x', -width / 2)
        .attr('y', -13)
        .attr('width', width)
        .attr('height', 25);
    });

    // 2. Render Nodes
    const nodeG = this.svg.append('g').attr('class', 'nodes-g');
    const nodeGroups = nodeG.selectAll('g')
      .data(this.nodesData)
      .enter()
      .append('g')
      .attr('class', d => `graph-node state-${d.integrity_status}`)
      .on('click', (event, d) => {
        event.stopPropagation();
        this.selectedNodeId = d.document_id;
        if (this.onNodeSelectCallback) {
          this.onNodeSelectCallback(d);
        }
        this.highlightLineage(d.document_id);
      })
      .on('mouseenter', (event, d) => this.showTooltip(event, d))
      .on('mousemove', (event, d) => this.showTooltip(event, d))
      .on('mouseleave', () => this.hideTooltip());

    // Node Card Outer Container
    nodeGroups.append('rect')
      .attr('class', 'node-card-rect')
      .attr('width', 190)
      .attr('height', 90)
      .attr('x', -95)
      .attr('y', -45)
      .attr('rx', 4)
      .attr('ry', 4);

    // Document-type colour band down the left edge
    nodeGroups.append('rect')
      .attr('class', 'node-type-band')
      .attr('x', -94)
      .attr('y', -43)
      .attr('width', 5)
      .attr('height', 86)
      .attr('rx', 2)
      .attr('fill', d => this.getTypeColor(d.document_type));

    // Node Icon Badge
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', -26)
      .attr('font-size', '15px')
      .text(d => this.getNodeIcon(d.document_type));

    // Node ID
    nodeGroups.append('text')
      .attr('x', -58)
      .attr('y', -26)
      .attr('fill', '#0b3d76')
      .attr('font-size', '12.5px')
      .attr('font-weight', '800')
      .text(d => d.document_id);

    // Document type label, in the type colour
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', -12)
      .attr('font-size', '8px')
      .attr('font-weight', '800')
      .attr('letter-spacing', '0.4')
      .attr('fill', d => this.getTypeColor(d.document_type))
      .text(d => (d.document_type || 'DOCUMENT').toUpperCase().substring(0, 30));

    // Node Title (Truncated)
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', 2)
      .attr('fill', '#14283c')
      .attr('font-size', '10px')
      .text(d => d.title.length > 28 ? d.title.substring(0, 26) + '...' : d.title);

    // Node Status Pill Text
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', 15)
      .attr('font-size', '8.5px')
      .attr('font-weight', '700')
      .attr('fill', d => this.getStatusColor(d.integrity_status))
      .text(d => `STATUS: ${d.integrity_status}`);

    // Single action on the card: open the controlled secure viewer. There is no download
    // button — the original file is only ever shown inside that viewer, and only to an
    // officer the supervisor has cleared for this document.
    const btnGroup = nodeGroups.append('g')
      .attr('transform', 'translate(-80, 22)');

    const viewBtn = btnGroup.append('g')
      .attr('style', 'cursor: pointer; pointer-events: all;')
      .on('click', (event, d) => {
        event.stopPropagation();
        this.selectedNodeId = d.document_id;
        if (this.onNodeSelectCallback) this.onNodeSelectCallback(d);
        window.CustodyApp.attemptOpenDocument(d.document_id);
      });

    viewBtn.append('rect')
      .attr('width', 156)
      .attr('height', 16)
      .attr('rx', 3)
      .attr('fill', '#0b3d76');

    viewBtn.append('text')
      .attr('x', 78)
      .attr('y', 11)
      .attr('text-anchor', 'middle')
      .attr('fill', '#ffffff')
      .attr('font-size', '9px')
      .attr('font-weight', '700')
      .text('👁️ Open Secure Preview');

    this.nodeSelection = nodeGroups;
    this.linkPathSelection = linkPaths;

    const positionOf = (id) => this.nodesData.find(n => n.document_id === id);

    const drawEdges = () => {
      linkPaths.attr('d', d => {
        const { src, tgt } = this.edgeEndpoints(d);
        const s = positionOf(src);
        const t = positionOf(tgt);
        if (!s || !t) return '';
        const sx = s.x + 95, sy = s.y;
        const tx = t.x - 95, ty = t.y;
        const dx = tx - sx;
        return `M ${sx} ${sy} C ${sx + dx / 2} ${sy}, ${sx + dx / 2} ${ty}, ${tx} ${ty}`;
      });

      // Sit each label in the empty corridor immediately before its target column. For a
      // single-level edge that is the midpoint anyway; for an edge that skips levels it
      // keeps the label clear of the cards it flies over.
      const pathNodes = linkPaths.nodes();
      const anchors = this.edgesData.map((d, i) => {
        const { src, tgt } = this.edgeEndpoints(d);
        const s = positionOf(src);
        const t = positionOf(tgt);
        if (!s || !t) return null;

        const pathStartX = s.x + 95;
        const pathEndX = t.x - 95;
        let labelX = t.x - this.LEVEL_X_DISTANCE / 2;
        if (labelX < pathStartX || labelX > pathEndX) {
          labelX = (pathStartX + pathEndX) / 2;
        }

        const point = this.pointOnPathAtX(pathNodes[i], labelX);
        return { x: point.x, y: point.y, corridor: t.x };
      });

      this.spreadLabelsInCorridor(anchors);

      linkLabels.attr('transform', (d, i) => (
        anchors[i] ? `translate(${anchors[i].x},${anchors[i].y})` : 'translate(0,0)'
      ));

      nodeGroups.attr('transform', d => `translate(${d.x},${d.y})`);
    };

    drawEdges();

    // Nodes stay draggable so an officer can untangle a dense case by hand
    nodeGroups.call(
      d3.drag()
        .on('start', () => this.hideTooltip())
        .on('drag', (event, d) => {
          d.x = event.x;
          d.y = event.y;
          drawEdges();
        })
    );
  },

  getNodeIcon(type) {
    const t = (type || '').toLowerCase();
    if (t.includes('fir') || t.includes('police')) return '⚖️';
    if (t.includes('witness')) return '🗣️';
    if (t.includes('forensic')) return '🔬';
    if (t.includes('investigation')) return '📋';
    if (t.includes('charge')) return '📑';
    if (t.includes('court')) return '🏛️';
    if (t.includes('evidence')) return '📦';
    if (t.includes('notice') || t.includes('judgment')) return '📜';
    return '📄';
  },

  // --- LEGEND -------------------------------------------------------------

  renderLegend() {
    const el = document.getElementById('graph-legend');
    if (!el) return;

    const counts = new Map();
    this.nodesData.forEach(n => {
      const type = n.document_type || 'Document';
      counts.set(type, (counts.get(type) || 0) + 1);
    });

    if (counts.size === 0) {
      el.innerHTML = '';
      return;
    }

    const rows = [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([type, count]) => `
        <div class="legend-item ${this.mutedTypes.has(type) ? 'muted' : ''}" data-type="${type}"
             title="Click to show or hide this document type">
          <span class="legend-swatch" style="background:${this.getTypeColor(type)}"></span>
          <span>${type}</span>
          <span class="legend-count">${count}</span>
        </div>
      `).join('');

    el.innerHTML = `<div class="graph-legend-title">Document Type</div>${rows}`;

    el.querySelectorAll('.legend-item').forEach(item => {
      item.onclick = () => this.toggleTypeFilter(item.dataset.type);
    });
  },

  toggleTypeFilter(type) {
    if (this.mutedTypes.has(type)) {
      this.mutedTypes.delete(type);
    } else {
      this.mutedTypes.add(type);
    }
    this.renderLegend();
    this.applyTypeFilter();
  },

  /** Dim nodes (and their edges) whose type has been switched off in the legend. */
  applyTypeFilter() {
    if (!this.svg) return;

    const isMuted = (docId) => {
      const node = this.nodesData.find(n => n.document_id === docId);
      return node ? this.mutedTypes.has(node.document_type || 'Document') : false;
    };

    this.svg.selectAll('.graph-node')
      .style('opacity', d => this.mutedTypes.has(d.document_type || 'Document') ? 0.12 : 1);

    // Fade on the whole edge group so the path and its label dim together
    this.svg.selectAll('.link-group')
      .style('opacity', d => {
        const { src, tgt } = this.edgeEndpoints(d);
        return (isMuted(src) || isMuted(tgt)) ? 0.08 : 1;
      });
  },

  // --- TOOLTIP ------------------------------------------------------------

  showTooltip(event, d) {
    const tip = document.getElementById('graph-tooltip');
    if (!tip) return;

    const viewport = tip.parentElement.getBoundingClientRect();
    const hash = d.current_hash ? `${d.current_hash.substring(0, 24)}…` : 'n/a';

    tip.innerHTML = `
      <div class="tt-title">${d.document_id} — ${d.title}</div>
      <div class="tt-row">Type: <strong>${d.document_type || 'Document'}</strong></div>
      <div class="tt-row">Classification: <strong>${d.classification || 'n/a'}</strong></div>
      <div class="tt-row">Integrity: <strong>${d.integrity_status}</strong> &bull; v${d.version || 1}</div>
      ${d.created_at ? `<div class="tt-row">Created: <strong>${d.created_at}</strong></div>` : ''}
      ${d.created_by ? `<div class="tt-row">By: <strong>${d.created_by}</strong></div>` : ''}
      <div class="tt-row" style="font-family:var(--font-mono); font-size:10px; margin-top:4px;">${hash}</div>
    `;

    tip.classList.add('visible');

    // Keep the tooltip inside the viewport box
    const width = tip.offsetWidth;
    const heightPx = tip.offsetHeight;
    let left = event.clientX - viewport.left + 16;
    let top = event.clientY - viewport.top + 16;
    if (left + width > viewport.width) left = Math.max(8, left - width - 32);
    if (top + heightPx > viewport.height) top = Math.max(8, top - heightPx - 32);

    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  },

  hideTooltip() {
    const tip = document.getElementById('graph-tooltip');
    if (tip) tip.classList.remove('visible');
  },

  // --- VIEW CONTROLS ------------------------------------------------------

  zoomBy(factor) {
    if (!this.svgRoot || !this.zoomBehavior) return;
    this.svgRoot.transition().duration(250).call(this.zoomBehavior.scaleBy, factor);
  },

  resetZoom() {
    if (!this.svgRoot || !this.zoomBehavior) return;
    this.svgRoot.transition().duration(300).call(this.zoomBehavior.transform, d3.zoomIdentity);
  },

  /** Scale and centre the transform so every node is visible. */
  fitToView(padding = 60) {
    if (!this.svgRoot || !this.zoomBehavior || this.nodesData.length === 0) return;

    const width = this.container.clientWidth || 900;
    const height = this.container.clientHeight || 600;
    const halfCard = { x: 95, y: 45 };

    const minX = Math.min(...this.nodesData.map(n => n.x - halfCard.x));
    const maxX = Math.max(...this.nodesData.map(n => n.x + halfCard.x));
    const minY = Math.min(...this.nodesData.map(n => n.y - halfCard.y));
    const maxY = Math.max(...this.nodesData.map(n => n.y + halfCard.y));

    const graphWidth = Math.max(1, maxX - minX);
    const graphHeight = Math.max(1, maxY - minY);

    const scale = Math.min(
      2.5,
      Math.max(0.2, Math.min(
        (width - padding * 2) / graphWidth,
        (height - padding * 2) / graphHeight
      ))
    );

    const translateX = (width - (minX + maxX) * scale) / 2;
    const translateY = (height - (minY + maxY) * scale) / 2;

    this.svgRoot.transition().duration(450).call(
      this.zoomBehavior.transform,
      d3.zoomIdentity.translate(translateX, translateY).scale(scale)
    );
  },

  /** Centre the view on one node and focus its lineage. */
  focusNode(docId, { flash = false } = {}) {
    const node = this.nodesData.find(n => n.document_id === docId);
    if (!node || !this.svgRoot || !this.zoomBehavior) return;

    const width = this.container.clientWidth || 900;
    const height = this.container.clientHeight || 600;
    const scale = 1;

    this.svgRoot.transition().duration(500).call(
      this.zoomBehavior.transform,
      d3.zoomIdentity
        .translate(width / 2 - node.x * scale, height / 2 - node.y * scale)
        .scale(scale)
    );

    this.highlightLineage(docId);

    if (flash) {
      const selection = this.svg.selectAll('.graph-node').filter(d => d.document_id === docId);
      selection.classed('just-added', true);
      setTimeout(() => selection.classed('just-added', false), 3500);
    }
  },

  /** Mark a node to be centred and flashed on the next render. */
  markAsJustAdded(docId) {
    this.justAddedId = docId;
  },

  clearFocus() {
    if (!this.svg) return;
    this.selectedNodeId = null;
    this.svg.selectAll('.graph-edge').classed('highlighted', false);
    this.hideTooltip();
    this.applyTypeFilter();
  },

  highlightLineage(selectedDocId) {
    if (!this.svg) return;
    this.svg.selectAll('.graph-node').style('opacity', 0.3);
    this.svg.selectAll('.link-group').style('opacity', 0.15);
    this.svg.selectAll('.graph-edge').classed('highlighted', false);

    // Walk the DAG both ways so the whole chain of custody lights up, not just neighbours
    const upstream = {};
    const downstream = {};
    this.edgesData.forEach(e => {
      const { src, tgt } = this.edgeEndpoints(e);
      (downstream[src] = downstream[src] || []).push(tgt);
      (upstream[tgt] = upstream[tgt] || []).push(src);
    });

    const lineage = new Set([selectedDocId]);
    const walk = (startId, adjacency) => {
      const stack = [startId];
      while (stack.length) {
        const current = stack.pop();
        (adjacency[current] || []).forEach(next => {
          if (!lineage.has(next)) {
            lineage.add(next);
            stack.push(next);
          }
        });
      }
    };
    walk(selectedDocId, upstream);
    walk(selectedDocId, downstream);

    this.svg.selectAll('.graph-node')
      .filter(d => lineage.has(d.document_id))
      .style('opacity', 1);

    const inLineage = (d) => {
      const { src, tgt } = this.edgeEndpoints(d);
      return lineage.has(src) && lineage.has(tgt);
    };

    this.svg.selectAll('.link-group').filter(inLineage).style('opacity', 1);
    this.svg.selectAll('.graph-edge').filter(inLineage).classed('highlighted', true);
  }
};
