/**
 * CUSTODY CHAIN — Hierarchical Tree & Provenance Graph Engine (SIH26190)
 * Renders directed graph nodes and lineage edges in both Hierarchical Tree and Physics Network modes.
 * Displays edge dates, relationship types, and interactive node action buttons.
 */

window.CustodyGraph = {
  svg: null,
  container: null,
  simulation: null,
  nodesData: [],
  edgesData: [],
  selectedNodeId: null,
  onNodeSelectCallback: null,
  layoutMode: 'tree', // 'tree' or 'force'

  init(containerId, onNodeSelect) {
    this.container = document.getElementById(containerId);
    this.onNodeSelectCallback = onNodeSelect;
    this.container.innerHTML = '';

    const svg = d3.select(this.container)
      .append('svg')
      .attr('class', 'provenance-svg')
      .attr('width', '100%')
      .attr('height', '100%');

    // Add marker arrow definitions
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
      .attr('fill', '#64748b');

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
      .attr('fill', '#ef4444');

    const g = svg.append('g').attr('class', 'main-graph-g');

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.2, 2.5])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);
    this.svg = g;
  },

  setLayoutMode(mode) {
    this.layoutMode = mode;
    if (this.nodesData && this.nodesData.length > 0) {
      this.render(this.nodesData, this.edgesData);
    }
  },

  render(nodes, edges) {
    if (!this.svg) return;
    if (this.simulation) this.simulation.stop();

    this.nodesData = JSON.parse(JSON.stringify(nodes || []));
    this.edgesData = JSON.parse(JSON.stringify(edges || []));
    this.svg.selectAll('*').remove();

    if (this.layoutMode === 'tree') {
      this.renderTreeLayout();
    } else {
      this.renderForceLayout();
    }
  },

  /**
   * DYNAMIC HIERARCHICAL TREE LAYOUT ENGINE
   * Flexibly calculates levels via BFS from existing root nodes.
   * Only renders existing document nodes without creating empty stage placeholders.
   */
  renderTreeLayout() {
    const width = this.container.clientWidth || 900;
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

    // Calculate dynamic spacing & positions
    const levels = Object.keys(levelGroups).map(Number).sort((a, b) => a - b);
    const levelXDistance = 260;
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

    this.drawGraphElements(true);
  },

  /**
   * DYNAMIC FORCE NETWORK LAYOUT ENGINE
   */
  renderForceLayout() {
    const width = this.container.clientWidth || 900;
    const height = this.container.clientHeight || 600;

    this.nodesData.forEach((n, i) => {
      n.x = (i % 4) * 240 + 120;
      n.y = Math.floor(i / 4) * 130 + 90;
    });

    this.simulation = d3.forceSimulation(this.nodesData)
      .force('link', d3.forceLink(this.edgesData).id(d => d.document_id).distance(200))
      .force('charge', d3.forceManyBody().strength(-500))
      .force('collide', d3.forceCollide().radius(90))
      .force('y', d3.forceY(height / 2).strength(0.1));

    this.drawGraphElements(false);
  },

  drawGraphElements(isTree = true) {
    // 1. Render Links (Edges with Date & Relationship Type)
    const linkG = this.svg.append('g').attr('class', 'links-g');
    const links = linkG.selectAll('g')
      .data(this.edgesData)
      .enter()
      .append('g');

    const linkPaths = links.append('path')
      .attr('class', d => {
        const srcId = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
        const tgtId = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
        const srcNode = this.nodesData.find(n => n.document_id === srcId);
        const tgtNode = this.nodesData.find(n => n.document_id === tgtId);
        const isAffected = (srcNode && srcNode.integrity_status === 'INTEGRITY_ISSUE') || 
                           (tgtNode && tgtNode.integrity_status === 'REVIEW_REQUIRED');
        return `graph-edge ${isAffected ? 'affected-edge' : ''}`;
      })
      .attr('marker-end', d => {
        const srcId = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
        const tgtId = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
        const srcNode = this.nodesData.find(n => n.document_id === srcId);
        const tgtNode = this.nodesData.find(n => n.document_id === tgtId);
        const isAffected = (srcNode && srcNode.integrity_status === 'INTEGRITY_ISSUE') || 
                           (tgtNode && tgtNode.integrity_status === 'REVIEW_REQUIRED');
        return isAffected ? 'url(#arrow-affected)' : 'url(#arrow)';
      });

    // EDGE LABELS WITH DATE AND RELATIONSHIP TYPE
    const linkLabels = links.append('text')
      .attr('class', 'edge-label')
      .attr('dy', -6)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', '10px')
      .attr('font-weight', '600')
      .text(d => {
        const rel = d.relationship_type || 'derived_from';
        const rawDate = d.created_at || '2026-08-10';
        const dateStr = rawDate.split(' ')[0];
        return `${rel} • ${dateStr}`;
      });

    // 2. Render Nodes
    const nodeG = this.svg.append('g').attr('class', 'nodes-g');
    const nodeGroups = nodeG.selectAll('g')
      .data(this.nodesData)
      .enter()
      .append('g')
      .attr('class', d => `graph-node state-${d.integrity_status}`)
      .on('click', (event, d) => {
        this.selectedNodeId = d.document_id;
        if (this.onNodeSelectCallback) {
          this.onNodeSelectCallback(d);
        }
        this.highlightLineage(d.document_id);
      });

    // Node Card Outer Container
    nodeGroups.append('rect')
      .attr('class', 'node-card-rect')
      .attr('width', 190)
      .attr('height', 90)
      .attr('x', -95)
      .attr('y', -45)
      .attr('rx', 12)
      .attr('ry', 12);

    // Node Icon Badge
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', -20)
      .attr('font-size', '18px')
      .text(d => this.getNodeIcon(d.document_type));

    // Node ID
    nodeGroups.append('text')
      .attr('x', -54)
      .attr('y', -20)
      .attr('fill', '#f3f4f6')
      .attr('font-size', '13px')
      .attr('font-weight', '800')
      .text(d => d.document_id);

    // Node Title (Truncated)
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', 2)
      .attr('fill', '#cbd5e1')
      .attr('font-size', '10px')
      .text(d => d.title.length > 27 ? d.title.substring(0, 25) + '...' : d.title);

    // Node Status Pill Text
    nodeGroups.append('text')
      .attr('x', -80)
      .attr('y', 18)
      .attr('font-size', '9px')
      .attr('font-weight', '700')
      .attr('fill', d => {
        if (d.integrity_status === 'VERIFIED') return '#10b981';
        if (d.integrity_status === 'REVIEW_REQUIRED') return '#f59e0b';
        return '#ef4444';
      })
      .text(d => `STATUS: ${d.integrity_status}`);

    // Quick Action Buttons directly inside Node Card
    const btnGroup = nodeGroups.append('g')
      .attr('transform', 'translate(-80, 24)');

    // Action 1: Open Viewer / Request Access Button
    const viewBtn = btnGroup.append('g')
      .attr('style', 'cursor: pointer; pointer-events: all;')
      .on('click', (event, d) => {
        event.stopPropagation();
        this.selectedNodeId = d.document_id;
        if (this.onNodeSelectCallback) this.onNodeSelectCallback(d);
        window.CustodyApp.attemptOpenDocument(d.document_id);
      });

    viewBtn.append('rect')
      .attr('width', 76)
      .attr('height', 16)
      .attr('rx', 4)
      .attr('fill', '#0284c7');

    viewBtn.append('text')
      .attr('x', 38)
      .attr('y', 11)
      .attr('text-anchor', 'middle')
      .attr('fill', '#ffffff')
      .attr('font-size', '9px')
      .attr('font-weight', '700')
      .text('👁️ Open Doc');

    // Action 2: Download PDF File Button
    const pdfBtn = btnGroup.append('g')
      .attr('transform', 'translate(82, 0)')
      .attr('style', 'cursor: pointer; pointer-events: all;')
      .on('click', (event, d) => {
        event.stopPropagation();
        const filePath = d.file_path || `/documents/${d.document_id}.pdf`;
        window.open(filePath, '_blank');
      });

    pdfBtn.append('rect')
      .attr('width', 74)
      .attr('height', 16)
      .attr('rx', 4)
      .attr('fill', '#334155');

    pdfBtn.append('text')
      .attr('x', 37)
      .attr('y', 11)
      .attr('text-anchor', 'middle')
      .attr('fill', '#38bdf8')
      .attr('font-size', '9px')
      .attr('font-weight', '700')
      .text('📄 Download');

    // Draw Function for Tree vs Force
    if (isTree) {
      // Tree Bezier Curves
      linkPaths.attr('d', d => {
        const srcId = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
        const tgtId = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
        const s = this.nodesData.find(n => n.document_id === srcId);
        const t = this.nodesData.find(n => n.document_id === tgtId);
        if (!s || !t) return '';
        const sx = s.x + 95, sy = s.y;
        const tx = t.x - 95, ty = t.y;
        const dx = tx - sx;
        return `M ${sx} ${sy} C ${sx + dx / 2} ${sy}, ${sx + dx / 2} ${ty}, ${tx} ${ty}`;
      });

      linkLabels
        .attr('x', d => {
          const srcId = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
          const tgtId = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
          const s = this.nodesData.find(n => n.document_id === srcId);
          const t = this.nodesData.find(n => n.document_id === tgtId);
          return (s && t) ? (s.x + t.x) / 2 : 0;
        })
        .attr('y', d => {
          const srcId = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
          const tgtId = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
          const s = this.nodesData.find(n => n.document_id === srcId);
          const t = this.nodesData.find(n => n.document_id === tgtId);
          return (s && t) ? (s.y + t.y) / 2 : 0;
        });

      nodeGroups.attr('transform', d => `translate(${d.x},${d.y})`);

    } else {
      // Force Simulation Ticks
      const drag = d3.drag()
        .on('start', (event, d) => {
          if (!event.active) this.simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x; d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) this.simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        });

      nodeGroups.call(drag);

      this.simulation.on('tick', () => {
        linkPaths.attr('d', d => {
          const sx = d.source.x, sy = d.source.y;
          const tx = d.target.x, ty = d.target.y;
          return `M${sx},${sy} L${tx},${ty}`;
        });

        linkLabels
          .attr('x', d => (d.source.x + d.target.x) / 2)
          .attr('y', d => (d.source.y + d.target.y) / 2);

        nodeGroups.attr('transform', d => `translate(${d.x},${d.y})`);
      });
    }
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
    return '📄';
  },

  highlightLineage(selectedDocId) {
    if (!this.svg) return;
    this.svg.selectAll('.graph-node').style('opacity', 0.35);
    this.svg.selectAll('.graph-edge').style('opacity', 0.2);

    const connectedDocIds = new Set([selectedDocId]);
    this.edgesData.forEach(e => {
      const src = e.source_document_id || (typeof e.source === 'object' ? e.source.document_id : e.source);
      const tgt = e.target_document_id || (typeof e.target === 'object' ? e.target.document_id : e.target);
      if (src === selectedDocId || tgt === selectedDocId) {
        connectedDocIds.add(src);
        connectedDocIds.add(tgt);
      }
    });

    this.svg.selectAll('.graph-node')
      .filter(d => connectedDocIds.has(d.document_id))
      .style('opacity', 1);

    this.svg.selectAll('.graph-edge')
      .filter(d => {
        const src = d.source_document_id || (typeof d.source === 'object' ? d.source.document_id : d.source);
        const tgt = d.target_document_id || (typeof d.target === 'object' ? d.target.document_id : d.target);
        return src === selectedDocId || tgt === selectedDocId;
      })
      .style('opacity', 1)
      .classed('highlighted', true);
  }
};
