"""
CUSTODY CHAIN - Provenance Graph & Dependency Impact Engine
Provides graph traversal, downstream impact analysis, explainability paths,
upstream lineage tracing, and counterfactual simulation.
"""

from typing import Dict, List, Set, Tuple, Optional, Any
from collections import deque
from backend.models import DocumentNode, ProvenanceEdge, IntegrityStatus, RelationshipType

class ProvenanceGraphEngine:
    def __init__(self, documents: Dict[str, DocumentNode], edges: List[ProvenanceEdge]):
        self.documents: Dict[str, DocumentNode] = documents
        self.edges: List[ProvenanceEdge] = edges
        
        # Build adjacency lists
        # downstream_adj: source_id -> list of (target_id, edge)
        self.downstream_adj: Dict[str, List[Tuple[str, ProvenanceEdge]]] = {}
        # upstream_adj: target_id -> list of (source_id, edge)
        self.upstream_adj: Dict[str, List[Tuple[str, ProvenanceEdge]]] = {}
        
        self._build_graph()

    def _build_graph(self):
        self.downstream_adj = {doc_id: [] for doc_id in self.documents}
        self.upstream_adj = {doc_id: [] for doc_id in self.documents}
        
        for edge in self.edges:
            src = edge.source_document_id
            tgt = edge.target_document_id
            if src in self.downstream_adj:
                self.downstream_adj[src].append((tgt, edge))
            if tgt in self.upstream_adj:
                self.upstream_adj[tgt].append((src, edge))

    def get_graph_data(self, case_id: str = "CASE-001") -> Dict[str, Any]:
        nodes = []
        for doc_id, doc in self.documents.items():
            dt = doc.document_type.value if hasattr(doc.document_type, 'value') else str(doc.document_type)
            cl = doc.classification.value if hasattr(doc.classification, 'value') else str(doc.classification)
            st = doc.integrity_status.value if hasattr(doc.integrity_status, 'value') else str(doc.integrity_status)
            
            nodes.append({
                "id": doc_id,
                "document_id": doc_id,
                "title": doc.title,
                "description": doc.description,
                "document_type": dt,
                "classification": cl,
                "integrity_status": st,
                "current_hash": doc.current_hash,
                "file_path": doc.storage_reference,
                "version": doc.current_version,
                "created_at": doc.creation_timestamp,
                "created_by": doc.creator_name,
                "external_system_source": doc.external_system_source,
                "digital_signature": bool(doc.digital_signature)
            })

        links = []
        for edge in self.edges:
            rt = edge.relationship_type.value if hasattr(edge.relationship_type, 'value') else str(edge.relationship_type)
            links.append({
                "id": edge.edge_id,
                "source": edge.source_document_id,
                "target": edge.target_document_id,
                "relationship_type": rt,
                "reason": edge.transformation_reason,
                "created_at": getattr(edge, 'created_at', None) or "2026-08-10 10:30"
            })

        total = len(nodes)
        verified = sum(1 for n in nodes if n["integrity_status"] == "VERIFIED")
        warning = sum(1 for n in nodes if n["integrity_status"] == "REVIEW_REQUIRED")
        critical = sum(1 for n in nodes if n["integrity_status"] == "INTEGRITY_ISSUE")

        case_summary = {
            "case_id": case_id,
            "total_documents": total,
            "provenance_links": len(links),
            "verified_documents": verified,
            "review_required_documents": warning,
            "integrity_issues": critical
        }

        return {
            "case": case_summary,
            "nodes": nodes,
            "links": links
        }

    def analyze_downstream_impact(self, compromised_doc_id: str) -> Dict[str, Any]:
        """
        Traverses downstream from compromised_doc_id.
        Returns:
            - direct_dependents: List of document IDs directly derived/merged/etc.
            - indirect_dependents: List of document IDs transitively dependent.
            - total_affected_count: Int
            - affected_nodes_map: doc_id -> depth
        """
        if compromised_doc_id not in self.documents:
            return {"error": "Document not found"}
        
        visited: Dict[str, int] = {}  # doc_id -> depth
        queue = deque([(compromised_doc_id, 0)])
        
        direct_dependents = []
        indirect_dependents = []
        
        while queue:
            curr_id, depth = queue.popleft()
            if curr_id in visited:
                continue
            visited[curr_id] = depth
            
            if depth == 1:
                direct_dependents.append(curr_id)
            elif depth > 1:
                indirect_dependents.append(curr_id)
                
            for child_id, _ in self.downstream_adj.get(curr_id, []):
                if child_id not in visited:
                    queue.append((child_id, depth + 1))
                    
        return {
            "source_document_id": compromised_doc_id,
            "direct_dependents": direct_dependents,
            "indirect_dependents": indirect_dependents,
            "total_affected_count": len(direct_dependents) + len(indirect_dependents),
            "affected_node_ids": direct_dependents + indirect_dependents,
            "depth_map": visited
        }

    def explain_impact(self, target_doc_id: str, compromised_source_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns the exact dependency path from compromised_source_id (or any upstream compromised node)
        to target_doc_id.
        """
        if target_doc_id not in self.documents:
            return {"error": "Target document not found"}
            
        # Find upstream nodes that are in INTEGRITY_ISSUE if source not specified
        sources_to_check = []
        if compromised_source_id:
            sources_to_check.append(compromised_source_id)
        else:
            for doc_id, doc in self.documents.items():
                if doc.integrity_status == IntegrityStatus.INTEGRITY_ISSUE:
                    sources_to_check.append(doc_id)

        for src_id in sources_to_check:
            path = self._find_path_bfs(src_id, target_doc_id)
            if path:
                # Format path details
                path_steps = []
                for i in range(len(path) - 1):
                    u = path[i]
                    v = path[i+1]
                    # find edge
                    rel_type = "derived_from"
                    reason = ""
                    for child_id, edge in self.downstream_adj.get(u, []):
                        if child_id == v:
                            rel_type = edge.relationship_type.value
                            reason = edge.transformation_reason
                            break
                    path_steps.append({
                        "from_doc_id": u,
                        "from_title": self.documents[u].title,
                        "to_doc_id": v,
                        "to_title": self.documents[v].title,
                        "relationship_type": rel_type,
                        "reason": reason
                    })
                return {
                    "compromised_source_id": src_id,
                    "target_document_id": target_doc_id,
                    "path_found": True,
                    "path_nodes": path,
                    "steps": path_steps,
                    "human_explanation": self._generate_human_explanation(path_steps)
                }

        return {
            "target_document_id": target_doc_id,
            "path_found": False,
            "human_explanation": "No upstream integrity issue is currently affecting this document."
        }

    def _find_path_bfs(self, start_id: str, target_id: str) -> Optional[List[str]]:
        if start_id == target_id:
            return [start_id]
        queue = deque([[start_id]])
        visited = {start_id}
        while queue:
            path = queue.popleft()
            node = path[-1]
            for child_id, _ in self.downstream_adj.get(node, []):
                if child_id == target_id:
                    return path + [child_id]
                if child_id not in visited:
                    visited.add(child_id)
                    queue.append(path + [child_id])
        return None

    def _generate_human_explanation(self, path_steps: List[Dict[str, Any]]) -> str:
        if not path_steps:
            return ""
        src_title = path_steps[0]['from_title']
        src_id = path_steps[0]['from_doc_id']
        target_title = path_steps[-1]['to_title']
        target_id = path_steps[-1]['to_doc_id']
        
        explanation = f"Document '{target_title}' ({target_id}) is marked for REVIEW REQUIRED because upstream source '{src_title}' ({src_id}) has an integrity mismatch.\nChain of dependency:\n"
        for step in path_steps:
            explanation += f" • {step['to_title']} ({step['to_doc_id']}) is [{step['relationship_type']}] from {step['from_title']} ({step['from_doc_id']})\n"
        return explanation

    def trace_origin(self, doc_id: str) -> Dict[str, Any]:
        """
        Traverses upstream to find all ancestor source documents.
        """
        if doc_id not in self.documents:
            return {"error": "Document not found"}

        ancestors = []
        visited = set()
        queue = deque([doc_id])

        while queue:
            curr = queue.popleft()
            if curr in visited:
                continue
            visited.add(curr)
            if curr != doc_id:
                ancestors.append(curr)

            for parent_id, _ in self.upstream_adj.get(curr, []):
                if parent_id not in visited:
                    queue.append(parent_id)

        return {
            "document_id": doc_id,
            "ancestor_document_ids": ancestors,
            "ancestors": [self.documents[a] for a in ancestors if a in self.documents]
        }

    def simulate_impact(self, doc_id: str, action: str = "INTEGRITY_FAILURE") -> Dict[str, Any]:
        """
        Counterfactual impact simulation without modifying stored document state.
        """
        impact_result = self.analyze_downstream_impact(doc_id)
        
        simulated_states = {}
        simulated_states[doc_id] = {
            "simulated_status": IntegrityStatus.INTEGRITY_ISSUE.value,
            "action": action,
            "role": "Source of Compromise"
        }
        
        for dep_id in impact_result.get("affected_node_ids", []):
            simulated_states[dep_id] = {
                "simulated_status": IntegrityStatus.REVIEW_REQUIRED.value,
                "action": "FLAGGED_FOR_HUMAN_REVIEW",
                "role": "Downstream Dependent"
            }
            
        return {
            "simulation": True,
            "target_doc_id": doc_id,
            "simulated_action": action,
            "affected_summary": {
                "direct_count": len(impact_result.get("direct_dependents", [])),
                "indirect_count": len(impact_result.get("indirect_dependents", [])),
                "total_affected": impact_result.get("total_affected_count", 0)
            },
            "simulated_nodes": simulated_states
        }
