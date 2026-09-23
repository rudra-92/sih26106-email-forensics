import type { Node, Edge } from '@xyflow/react';
import type { EntityItem, RelationshipItem, EvidenceItem } from '../../types';

export interface ForensicNodeData extends Record<string, unknown> {
  entity: EntityItem;
  entityType: string;
  canonicalValue: string;
  isMatched?: boolean;
  isDimmed?: boolean;
  isReference?: boolean;
  isSelected?: boolean;
  isInTrail?: boolean;
}

export type ForensicNode = Node<ForensicNodeData, 'forensic'>;

export interface ForensicEdgeData extends Record<string, unknown> {
  relationship: RelationshipItem;
  relationshipType: string;
  evidenceIds: string[];
  sourceModules: string[];
  trustState: string;
  isDimmed?: boolean;
  isSelected?: boolean;
  isInTrail?: boolean;
  showLabels?: boolean;
  relatedEvidence?: EvidenceItem[];
}

export type ForensicEdge = Edge<ForensicEdgeData>;

export interface GraphFilterState {
  searchQuery: string;
  entityType: string;
  relationshipType: string;
  sourceModule: string;
  showEdgeLabels: boolean;
}

export type SelectedElement =
  | {
      type: 'node';
      data: EntityItem;
      incoming: RelationshipItem[];
      outgoing: RelationshipItem[];
    }
  | {
      type: 'edge';
      data: RelationshipItem;
      sourceEntity?: EntityItem;
      targetEntity?: EntityItem;
      relatedEvidence?: EvidenceItem[];
    }
  | null;
