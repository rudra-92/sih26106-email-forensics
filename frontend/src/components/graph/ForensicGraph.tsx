import React, { useState, useMemo, useCallback } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useReactFlow,
  ReactFlowProvider,
  type NodeMouseHandler,
  type EdgeMouseHandler,
  type NodeTypes,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import './graph.css';

import type { EntityItem, RelationshipItem, EvidenceItem } from '../../types';
import type { GraphFilterState, SelectedElement } from './graphTypes';
import { ForensicNodeComponent } from './ForensicNode';
import { GraphToolbar } from './GraphToolbar';
import { GraphDetailsPanel } from './GraphDetailsPanel';
import { transformForensicGraph } from './graphTransform';

const nodeTypes: NodeTypes = {
  forensic: ForensicNodeComponent,
};

interface ForensicGraphInnerProps {
  entities: EntityItem[];
  relationships: RelationshipItem[];
  evidenceList?: EvidenceItem[];
}

const ForensicGraphInner: React.FC<ForensicGraphInnerProps> = ({
  entities,
  relationships,
  evidenceList = [],
}) => {
  const { fitView, zoomIn, zoomOut } = useReactFlow();

  const [filters, setFilters] = useState<GraphFilterState>({
    searchQuery: '',
    entityType: '',
    relationshipType: '',
    sourceModule: '',
    showEdgeLabels: true,
  });

  const [selectedElement, setSelectedElement] = useState<SelectedElement>(null);

  // Available Filter Options (derived dynamically from case data)
  const availableEntityTypes = useMemo(() => {
    const types = new Set<string>();
    entities.forEach((e) => {
      if (e.entity_type) types.add(e.entity_type);
    });
    return Array.from(types).sort();
  }, [entities]);

  const availableRelationshipTypes = useMemo(() => {
    const types = new Set<string>();
    relationships.forEach((r) => {
      if (r.relationship_type) types.add(r.relationship_type);
    });
    return Array.from(types).sort();
  }, [relationships]);

  const availableSourceModules = useMemo(() => {
    const mods = new Set<string>();
    entities.forEach((e) => (e.source_modules || []).forEach((m) => mods.add(m)));
    relationships.forEach((r) => (r.source_modules || []).forEach((m) => mods.add(m)));
    return Array.from(mods).sort();
  }, [entities, relationships]);

  const { nodes, edges } = useMemo(() => {
    const result = transformForensicGraph(
      entities,
      relationships,
      evidenceList,
      filters.searchQuery,
      filters.entityType,
      filters.relationshipType,
      filters.sourceModule,
      filters.showEdgeLabels,
      selectedElement
    );
    return result;
  }, [entities, relationships, evidenceList, filters, selectedElement]);



  // Match count for search query
  const matchCount = useMemo(() => {
    if (!filters.searchQuery.trim()) return undefined;
    return nodes.filter((n) => n.data.isMatched).length;
  }, [nodes, filters.searchQuery]);

  // Evidence Map by ID for quick lookup
  const evidenceById = useMemo(() => {
    const map = new Map<string, EvidenceItem>();
    evidenceList.forEach((ev) => map.set(ev.evidence_id, ev));
    return map;
  }, [evidenceList]);

  // Node Click: Highlight node and its connected trail
  const handleNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      const ent = entities.find((e) => e.entity_id === node.id);
      if (!ent) return;

      const outgoing = relationships.filter((r) => r.source_entity_id === ent.entity_id);
      const incoming = relationships.filter((r) => r.target_entity_id === ent.entity_id);

      setSelectedElement({
        type: 'node',
        data: ent,
        outgoing,
        incoming,
      });
    },
    [entities, relationships]
  );

  // Edge Click: Highlight edge, its source & target nodes, and open rich evidence details
  const handleEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      const rel = relationships.find((r) => r.relationship_id === edge.id);
      if (!rel) return;

      const sourceEntity = entities.find((e) => e.entity_id === rel.source_entity_id);
      const targetEntity = entities.find((e) => e.entity_id === rel.target_entity_id);

      const relatedEvidence: EvidenceItem[] = (rel.evidence_ids || [])
        .map((id) => evidenceById.get(id))
        .filter((ev): ev is EvidenceItem => Boolean(ev));

      setSelectedElement({
        type: 'edge',
        data: rel,
        sourceEntity,
        targetEntity,
        relatedEvidence,
      });
    },
    [entities, relationships, evidenceById]
  );

  // Canvas Click (Deselect / Clear trail)
  const handlePaneClick = useCallback(() => {
    setSelectedElement(null);
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedElement(null);
  }, []);

  // Jump to specific entity from connected relationships in details panel
  const handleSelectEntityId = useCallback(
    (entityId: string) => {
      const ent = entities.find((e) => e.entity_id === entityId);
      if (!ent) return;

      const outgoing = relationships.filter((r) => r.source_entity_id === ent.entity_id);
      const incoming = relationships.filter((r) => r.target_entity_id === ent.entity_id);

      setSelectedElement({
        type: 'node',
        data: ent,
        outgoing,
        incoming,
      });

      const targetNode = nodes.find((n) => n.id === entityId);
      if (targetNode) {
        fitView({
          nodes: [targetNode],
          duration: 400,
          padding: 1.5,
        });
      }
    },
    [entities, relationships, nodes, fitView]
  );

  const handleFitView = useCallback(() => {
    fitView({ padding: 0.15, duration: 400 });
  }, [fitView]);

  const handleZoomIn = useCallback(() => {
    zoomIn({ duration: 250 });
  }, [zoomIn]);

  const handleZoomOut = useCallback(() => {
    zoomOut({ duration: 250 });
  }, [zoomOut]);

  const handleReset = useCallback(() => {
    setSelectedElement(null);
    setTimeout(() => {
      fitView({ padding: 0.15, duration: 400 });
    }, 50);
  }, [fitView]);

  // Empty state: no entities in case
  if (entities.length === 0) {
    return (
      <div className="graph-wrapper" style={{ justifyContent: 'center', alignItems: 'center' }}>
        <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
          No entities were extracted from this case.
        </p>
      </div>
    );
  }

  return (
    <div className="graph-wrapper">
      {/* Top Controls Toolbar */}
      <GraphToolbar
        filters={filters}
        onFilterChange={setFilters}
        availableEntityTypes={availableEntityTypes}
        availableRelationshipTypes={availableRelationshipTypes}
        availableSourceModules={availableSourceModules}
        matchCount={matchCount}
        totalNodes={nodes.length}
        hasSelection={Boolean(selectedElement)}
        onFitView={handleFitView}
        onZoomIn={handleZoomIn}
        onZoomOut={handleZoomOut}
        onReset={handleReset}
        onClearSelection={handleClearSelection}
      />

      {/* Notice if entities exist but no relationships */}
      {entities.length > 0 && relationships.length === 0 && (
        <div
          style={{
            backgroundColor: '#EFF6FF',
            color: '#1E40AF',
            fontSize: '11px',
            padding: '6px 12px',
            borderBottom: '1px solid #BFDBFE',
          }}
        >
          Entities were extracted, but no relationships were established from the available evidence.
        </div>
      )}

      {/* React Flow Canvas */}
      <div className="graph-canvas-container">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={handleNodeClick}
          onEdgeClick={handleEdgeClick}
          onPaneClick={handlePaneClick}
          nodesDraggable={true}
          nodesConnectable={false}
          elementsSelectable={true}
          deleteKeyCode={null}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.15}
          maxZoom={2.5}
        >
          <Background color="#CBD5E1" gap={16} size={1} />
          <Controls showInteractive={false} position="bottom-left" />
          <MiniMap
            nodeColor={(n) => {
              const type = (n.data?.entityType as string)?.toLowerCase() || '';
              if (type.includes('domain')) return '#F97316';
              if (type.includes('email')) return '#2563EB';
              if (type.includes('ip')) return '#64748B';
              if (type.includes('url')) return '#0284C7';
              return '#94A3B8';
            }}
            position="bottom-right"
            zoomable
            pannable
          />
        </ReactFlow>

        {/* Selected Node / Edge Details Panel */}
        <GraphDetailsPanel
          selected={selectedElement}
          onClose={() => setSelectedElement(null)}
          onSelectEntityId={handleSelectEntityId}
        />
      </div>
    </div>
  );
};

export const ForensicGraph: React.FC<ForensicGraphInnerProps> = (props) => {
  return (
    <ReactFlowProvider>
      <ForensicGraphInner {...props} />
    </ReactFlowProvider>
  );
};
