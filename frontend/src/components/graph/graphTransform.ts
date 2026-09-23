import { MarkerType } from '@xyflow/react';
import type { EntityItem, RelationshipItem, EvidenceItem } from '../../types';
import type { ForensicNode, ForensicEdge, SelectedElement } from './graphTypes';

const TIER_ORDER: Record<string, number> = {
  email_address: 0,
  email: 1,
  message_id: 1,
  url: 2,
  attachment: 2,
  hash: 2,
  domain: 3,
  hostname: 3,
  ip: 5,
  ip_address: 5,
  infrastructure: 6,
  asn: 6,
  country: 6,
  case: 7,
};

function getTier(entityType: string, isReference: boolean = false): number {
  if (isReference) return 4; // Place lookalike reference domains on Tier 4 (directly below observed domains)
  const norm = entityType.toLowerCase();
  return TIER_ORDER[norm] !== undefined ? TIER_ORDER[norm] : 7;
}

export function transformForensicGraph(
  entities: EntityItem[],
  relationships: RelationshipItem[],
  evidenceList: EvidenceItem[] = [],
  searchQuery: string = '',
  entityTypeFilter: string = '',
  relationshipTypeFilter: string = '',
  sourceModuleFilter: string = '',
  showEdgeLabels: boolean = true,
  selectedElement: SelectedElement = null
): { nodes: ForensicNode[]; edges: ForensicEdge[] } {
  const query = searchQuery.trim().toLowerCase();

  // 1. Identify which entity IDs are targeted by a 'resembles' relationship (e.g. protected reference brands)
  const referenceEntityIds = new Set<string>();
  const lookalikeSourceMap = new Map<string, string>(); // refId -> sourceId
  relationships.forEach((rel) => {
    if (rel.relationship_type.toLowerCase() === 'resembles') {
      referenceEntityIds.add(rel.target_entity_id);
      lookalikeSourceMap.set(rel.target_entity_id, rel.source_entity_id);
    }
  });

  // 2. Identify Selection / Trail Highlight State
  let activeNodeId: string | null = null;
  let activeEdgeId: string | null = null;
  const connectedEdgeIds = new Set<string>();
  const connectedNodeIds = new Set<string>();

  if (selectedElement) {
    if (selectedElement.type === 'node') {
      activeNodeId = selectedElement.data.entity_id;
      connectedNodeIds.add(activeNodeId);
      relationships.forEach((rel) => {
        if (rel.source_entity_id === activeNodeId || rel.target_entity_id === activeNodeId) {
          connectedEdgeIds.add(rel.relationship_id);
          connectedNodeIds.add(rel.source_entity_id);
          connectedNodeIds.add(rel.target_entity_id);
        }
      });
    } else if (selectedElement.type === 'edge') {
      activeEdgeId = selectedElement.data.relationship_id;
      connectedEdgeIds.add(activeEdgeId);
      connectedNodeIds.add(selectedElement.data.source_entity_id);
      connectedNodeIds.add(selectedElement.data.target_entity_id);
    }
  }

  const isTrailActive = Boolean(selectedElement);

  // 3. Filter relationships
  const activeRelationships = relationships.filter((rel) => {
    if (relationshipTypeFilter && rel.relationship_type !== relationshipTypeFilter) {
      return false;
    }
    if (
      sourceModuleFilter &&
      (!rel.source_modules || !rel.source_modules.includes(sourceModuleFilter))
    ) {
      return false;
    }
    return true;
  });

  // 4. Filter entities
  const filteredEntities = entities.filter((ent) => {
    if (entityTypeFilter && ent.entity_type !== entityTypeFilter) {
      return false;
    }
    if (
      sourceModuleFilter &&
      (!ent.source_modules || !ent.source_modules.includes(sourceModuleFilter))
    ) {
      return false;
    }
    return true;
  });

  const filteredEntityIds = new Set(filteredEntities.map((e) => e.entity_id));

  // 5. Organize entities by Tier
  const tierMap: Map<number, EntityItem[]> = new Map();
  filteredEntities.forEach((ent) => {
    const isReference = referenceEntityIds.has(ent.entity_id);
    const tier = getTier(ent.entity_type, isReference);
    if (!tierMap.has(tier)) {
      tierMap.set(tier, []);
    }
    tierMap.get(tier)!.push(ent);
  });

  const sortedTiers = Array.from(tierMap.keys()).sort((a, b) => a - b);

  // Layout Constants for Forensic SOC presentation
  const NODE_WIDTH = 210;
  const NODE_HEIGHT = 54;
  const HORIZONTAL_GAP = 50;
  const VERTICAL_GAP = 100;

  // 6. Build Nodes with Deterministic Coordinates
  const nodes: ForensicNode[] = [];
  const nodePositionMap = new Map<string, { x: number; y: number }>();

  sortedTiers.forEach((tierNumber, tierRowIndex) => {
    const tierEntities = tierMap.get(tierNumber)!;
    tierEntities.sort((a, b) => a.canonical_value.localeCompare(b.canonical_value));

    const totalWidth =
      tierEntities.length * NODE_WIDTH + (tierEntities.length - 1) * HORIZONTAL_GAP;
    const startX = -totalWidth / 2;
    const y = tierRowIndex * (NODE_HEIGHT + VERTICAL_GAP);

    tierEntities.forEach((ent, colIndex) => {
      let x = startX + colIndex * (NODE_WIDTH + HORIZONTAL_GAP);

      // If this is a reference domain (e.g. paypal.com), align it near its resembling domain
      if (tierNumber === 4 && lookalikeSourceMap.has(ent.entity_id)) {
        const sourceId = lookalikeSourceMap.get(ent.entity_id)!;
        const sourcePos = nodePositionMap.get(sourceId);
        if (sourcePos) {
          x = sourcePos.x;
        }
      }

      nodePositionMap.set(ent.entity_id, { x, y });

      const isReference = referenceEntityIds.has(ent.entity_id);
      const isSelected = activeNodeId === ent.entity_id;
      const isInTrail = isTrailActive ? connectedNodeIds.has(ent.entity_id) : false;

      let isMatched = false;
      if (query) {
        const matchesVal = ent.canonical_value.toLowerCase().includes(query);
        const matchesType = ent.entity_type.toLowerCase().includes(query);
        const matchesId = ent.entity_id.toLowerCase().includes(query);
        isMatched = matchesVal || matchesType || matchesId;
      }

      // Dimming rule: if trail is active and node is not in trail, dim it. If search is active and not matched, dim it.
      let isDimmed = false;
      if (isTrailActive && !isInTrail) {
        isDimmed = true;
      } else if (query && !isMatched) {
        isDimmed = true;
      }

      nodes.push({
        id: ent.entity_id,
        type: 'forensic',
        position: { x, y },
        data: {
          entity: ent,
          entityType: ent.entity_type,
          canonicalValue: ent.canonical_value,
          isMatched,
          isDimmed,
          isReference,
          isSelected,
          isInTrail,
        },
      });
    });
  });

  // Map evidence items by evidence_id for rich edge inspection
  const evidenceById = new Map<string, EvidenceItem>();
  evidenceList.forEach((ev) => {
    evidenceById.set(ev.evidence_id, ev);
  });

  // 7. Build Edges
  const edges: ForensicEdge[] = [];

  activeRelationships.forEach((rel) => {
    if (!filteredEntityIds.has(rel.source_entity_id) || !filteredEntityIds.has(rel.target_entity_id)) {
      return;
    }

    const relTypeNorm = rel.relationship_type.toLowerCase();
    const isResembles = relTypeNorm === 'resembles';
    const isTransmission = ['sent_by', 'sends', 'observed_from', 'routed_through'].includes(relTypeNorm);
    const isMembership = ['belongs_to', 'contains', 'references', 'hosted_on'].includes(relTypeNorm);

    const isSelected = activeEdgeId === rel.relationship_id;
    const isInTrail = isTrailActive ? connectedEdgeIds.has(rel.relationship_id) : false;
    const isDimmed = isTrailActive ? !isInTrail : false;

    // Resolve matching evidence items
    const relatedEvidence: EvidenceItem[] = (rel.evidence_ids || [])
      .map((id) => evidenceById.get(id))
      .filter((ev): ev is EvidenceItem => Boolean(ev));

    // Visual edge hierarchy
    let strokeColor = '#64748B';
    let strokeWidth = 1.75;
    let strokeDash: string | undefined = undefined;
    let labelBgFill = '#FFFFFF';
    let labelBgStroke = '#CBD5E1';
    let labelTextColor = '#334155';

    if (isResembles) {
      strokeColor = '#EA580C'; // Vivid amber/orange
      strokeWidth = isSelected || isInTrail ? 3.5 : 2.5;
      strokeDash = '6 4';
      labelBgFill = '#FEF3C7';
      labelBgStroke = '#F59E0B';
      labelTextColor = '#9A3412';
    } else if (isTransmission) {
      strokeColor = '#2563EB'; // Vibrant forensic blue
      strokeWidth = isSelected || isInTrail ? 3 : 2;
      labelBgFill = '#EFF6FF';
      labelBgStroke = '#BFDBFE';
      labelTextColor = '#1E40AF';
    } else if (isMembership) {
      strokeColor = '#475569'; // Slate
      strokeWidth = isSelected || isInTrail ? 2.5 : 1.75;
      labelBgFill = '#F8FAFC';
      labelBgStroke = '#E2E8F0';
      labelTextColor = '#334155';
    } else {
      // Infrastructure / resolution
      strokeColor = '#64748B';
      strokeWidth = isSelected || isInTrail ? 2.5 : 1.5;
      strokeDash = '4 3';
      labelBgFill = '#FFFFFF';
      labelBgStroke = '#E2E8F0';
      labelTextColor = '#475569';
    }

    if (isSelected) {
      strokeColor = isResembles ? '#EA580C' : '#2563EB';
      strokeWidth = 3.5;
    }

    const shouldShowLabel = showEdgeLabels || isResembles || isSelected;

    edges.push({
      id: rel.relationship_id,
      source: rel.source_entity_id,
      target: rel.target_entity_id,
      animated: isResembles,
      style: {
        stroke: strokeColor,
        strokeWidth,
        strokeDasharray: strokeDash,
        opacity: isDimmed ? 0.14 : 1,
        transition: 'opacity 0.2s ease, stroke-width 0.2s ease',
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: strokeColor,
        width: isResembles || isSelected ? 16 : 14,
        height: isResembles || isSelected ? 16 : 14,
      },
      label: shouldShowLabel ? rel.relationship_type : undefined,
      labelStyle: {
        fill: labelTextColor,
        fontSize: isResembles ? 10.5 : 9.5,
        fontWeight: isResembles || isSelected ? 700 : 600,
        fontFamily: 'inherit',
      },
      labelBgStyle: {
        fill: labelBgFill,
        stroke: labelBgStroke,
        strokeWidth: isResembles || isSelected ? 1.5 : 1,
        fillOpacity: 0.98,
      },
      labelBgPadding: [5, 2.5],
      labelBgBorderRadius: 3,
      data: {
        relationship: rel,
        relationshipType: rel.relationship_type,
        evidenceIds: rel.evidence_ids || [],
        sourceModules: rel.source_modules || [],
        trustState: rel.trust_state || 'observed',
        isDimmed,
        isSelected,
        isInTrail,
        relatedEvidence,
      },
    });
  });

  return { nodes, edges };
}
