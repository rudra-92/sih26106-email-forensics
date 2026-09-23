/**
 * Case and Investigation Container Types
 */

export type CaseStatus = 'open' | 'closed' | 'archived' | string;

export type AnalysisStatus = 'pending' | 'running' | 'completed' | 'failed' | string;

export type ThreatLabel = 'phishing' | 'fraud_related' | 'legitimate' | 'suspicious' | 'unknown' | string;

export interface Case {
  case_id: string;
  owner_user_id?: string;
  title: string;
  status: CaseStatus;
  created_at: string;
  updated_at: string;
  original_filename?: string | null;
  file_sha256?: string | null;
  file_size_bytes?: number | null;
  analysis_status: AnalysisStatus;
  threat_label?: ThreatLabel | null;
  threat_confidence?: number | null;
  threat_confidence_metric?: string | null;
  summary?: string | null;
  evidence_count: number;
  entity_count: number;
  relationship_count: number;
  hypothesis_count: number;
  error_message?: string | null;
}

export interface CaseListResponse {
  total: number;
  cases: Case[];
}

export interface CaseCreatePayload {
  title: string;
}

export interface FileUploadResponse {
  case_id: string;
  original_filename: string;
  file_sha256: string;
  file_size_bytes: number;
  message: string;
}

export interface AnalysisTriggerResponse {
  case_id: string;
  analysis_status: string;
  message: string;
  threat_label?: string | null;
  threat_confidence?: number | null;
}
