/**
 * Forensic Evidence, Graph, Hypothesis, and Summary Types
 * Matches backend schemas in backend/schemas/analysis.py
 */

export interface EvidenceItem {
  evidence_id: string;
  source_module: string;
  rule_id: string;
  trust_state: string;
  severity: string;
  description: string;
  entity_ids?: string[];
  timestamp?: string | null;
  provenance?: string[];
  supporting_fields?: Record<string, unknown>;
}

export interface EvidenceListResponse {
  case_id: string;
  total: number;
  evidence: EvidenceItem[];
}

export interface EntityItem {
  entity_id: string;
  entity_type: string;
  canonical_value: string;
  source_modules?: string[];
  first_observed_timestamp?: string | null;
  attributes?: Record<string, unknown>;
}

export interface EntityListResponse {
  case_id: string;
  total: number;
  entities: EntityItem[];
}

export interface RelationshipItem {
  relationship_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship_type: string;
  evidence_ids?: string[];
  source_modules?: string[];
  trust_state: string;
  timestamp?: string | null;
  provenance?: string[];
}

export interface RelationshipListResponse {
  case_id: string;
  total: number;
  relationships: RelationshipItem[];
}

export interface HypothesisItem {
  hypothesis_id: string;
  hypothesis_type: string;
  confidence: number;
  confidence_metric: string;
  supporting_evidence_ids?: string[];
  contradicting_evidence_ids?: string[];
  description?: string | null;
  provenance?: string[];
}

export interface HypothesisListResponse {
  case_id: string;
  total: number;
  hypotheses: HypothesisItem[];
}

export interface OriginData {
  case_id: string;
  earliest_reliable_peer?: string | null;
  source_visibility?: string | null;
  confidence?: number | null;
  assessment_reason?: string | null;
  infrastructure?: Record<string, unknown>;
  geolocation?: Record<string, unknown>;
  asn?: Record<string, unknown>;
  hops?: Array<Record<string, unknown>>;
  rdap?: Record<string, unknown> | null;
  reverse_dns?: Record<string, unknown> | null;
  threat_feed?: Record<string, unknown> | null;
  provenance?: Record<string, unknown>;
  semantic_note?: string;
}

export interface CaseSummary {
  case_id: string;
  threat_label?: string | null;
  threat_confidence?: number | null;
  threat_confidence_metric?: string | null;
  important_forensic_findings?: Array<{
    rule_id?: string;
    description?: string;
    severity?: string;
    trust_state?: string;
    [key: string]: unknown;
  }>;
  top_hypotheses?: Array<{
    hypothesis_id?: string;
    hypothesis_type?: string;
    confidence?: number;
    confidence_metric?: string;
    description?: string;
    [key: string]: unknown;
  }>;
  origin_infrastructure_summary?: Record<string, unknown>;
  evidence_counts?: Record<string, number>;
  entity_counts?: Record<string, number>;
  key_domains?: string[];
  key_ips?: string[];
  key_urls?: string[];
  suspicious_attachments?: string[];
  authentication_observations?: Array<Record<string, unknown>>;
}
