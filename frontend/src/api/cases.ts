import axios from 'axios';
import { apiClient } from './client';
import type {
  Case,
  CaseListResponse,
  CaseCreatePayload,
  FileUploadResponse,
  AnalysisTriggerResponse,
  CaseSummary,
  EvidenceListResponse,
  EntityListResponse,
  RelationshipListResponse,
  HypothesisListResponse,
  OriginData,
} from '../types';

/**
 * Format backend and HTTP errors for case operations
 */
export function formatCaseError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    if (error.code === 'ECONNABORTED' || error.message?.toLowerCase().includes('timeout')) {
      return 'The investigation service is taking longer than usual to respond (the server may be waking up from sleep). Please retry in a few seconds.';
    }

    if (!error.response) {
      return 'Unable to reach the investigation service. The cloud server may be starting up or network connectivity was lost. Please retry.';
    }

    const { status, data } = error.response;

    if (status === 401) {
      return 'Your session has expired. Please sign in again.';
    }

    if (status === 403) {
      return 'You do not have access to this investigation.';
    }

    if (status === 404) {
      return 'Investigation not found.';
    }

    if (status === 409) {
      return (
        data?.detail ||
        'Analysis is already running for this investigation.'
      );
    }

    if (status === 422) {
      if (typeof data?.detail === 'string') {
        return data.detail;
      }
      if (Array.isArray(data?.detail)) {
        const msgs = data.detail.map((d: { msg?: string }) => d.msg).filter(Boolean);
        if (msgs.length > 0) return msgs.join('. ');
      }
      return 'Validation error. Please verify input parameters.';
    }

    if (typeof data?.detail === 'string' && data.detail.trim().length > 0) {
      return data.detail;
    }

    if (typeof data?.message === 'string' && data.message.trim().length > 0) {
      return data.message;
    }

    if (typeof data === 'string' && data.trim().length > 0 && !data.includes('<!DOCTYPE') && !data.includes('<html')) {
      return data;
    }

    if (status === 502 || status === 503 || status === 504) {
      return 'The backend service is currently waking up on Render (~30–45s). Please wait a few seconds and try again.';
    }

    if (status >= 500) {
      return 'The investigation service encountered a temporary server error. Please try again in a few moments.';
    }
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'An unexpected case error occurred.';
}

/**
 * Retrieve cases list for current authenticated investigator (or all for admin)
 * GET /api/cases
 */
export async function fetchCases(): Promise<CaseListResponse> {
  const { data } = await apiClient.get<CaseListResponse>('/api/cases');
  return data;
}

/**
 * Retrieve single case record by case_id
 * GET /api/cases/{case_id}
 */
export async function fetchCaseById(caseId: string): Promise<Case> {
  const { data } = await apiClient.get<Case>(`/api/cases/${caseId}`);
  return data;
}

/**
 * Create a new investigation case
 * POST /api/cases
 */
export async function createCase(payload: CaseCreatePayload): Promise<Case> {
  const { data } = await apiClient.post<Case>('/api/cases', {
    title: payload.title.trim(),
  });
  return data;
}

/**
 * Upload original .eml file to case
 * POST /api/cases/{case_id}/email
 */
export async function uploadCaseEmail(
  caseId: string,
  file: File,
  onUploadProgress?: (percent: number) => void
): Promise<FileUploadResponse> {
  const formData = new FormData();
  formData.append('file', file, file.name);

  const { data } = await apiClient.post<FileUploadResponse>(
    `/api/cases/${caseId}/email`,
    formData,
    {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
      onUploadProgress: (progressEvent) => {
        if (onUploadProgress && progressEvent.total) {
          const percent = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onUploadProgress(percent);
        }
      },
    }
  );
  return data;
}

/**
 * Trigger full forensic analysis pipeline (Modules 1-6, ML Fusion, Enrichment)
 * POST /api/cases/{case_id}/analyze
 */
export async function analyzeCase(caseId: string): Promise<AnalysisTriggerResponse> {
  const { data } = await apiClient.post<AnalysisTriggerResponse>(
    `/api/cases/${caseId}/analyze`
  );
  return data;
}

/**
 * Retrieve executive investigation summary
 * GET /api/cases/{case_id}/summary
 */
export async function fetchCaseSummary(caseId: string): Promise<CaseSummary> {
  const { data } = await apiClient.get<CaseSummary>(`/api/cases/${caseId}/summary`);
  return data;
}

/**
 * Retrieve normalized forensic evidence items
 * GET /api/cases/{case_id}/evidence
 */
export async function fetchCaseEvidence(caseId: string): Promise<EvidenceListResponse> {
  const { data } = await apiClient.get<EvidenceListResponse>(`/api/cases/${caseId}/evidence`);
  return data;
}

/**
 * Retrieve resolved entities
 * GET /api/cases/{case_id}/entities
 */
export async function fetchCaseEntities(caseId: string): Promise<EntityListResponse> {
  const { data } = await apiClient.get<EntityListResponse>(`/api/cases/${caseId}/entities`);
  return data;
}

/**
 * Retrieve graph relationships between entities
 * GET /api/cases/{case_id}/relationships
 */
export async function fetchCaseRelationships(caseId: string): Promise<RelationshipListResponse> {
  const { data } = await apiClient.get<RelationshipListResponse>(`/api/cases/${caseId}/relationships`);
  return data;
}

/**
 * Retrieve generated hypotheses
 * GET /api/cases/{case_id}/hypotheses
 */
export async function fetchCaseHypotheses(caseId: string): Promise<HypothesisListResponse> {
  const { data } = await apiClient.get<HypothesisListResponse>(`/api/cases/${caseId}/hypotheses`);
  return data;
}

/**
 * Retrieve origin and network infrastructure data
 * GET /api/cases/{case_id}/origin
 */
export async function fetchCaseOrigin(caseId: string): Promise<OriginData> {
  const { data } = await apiClient.get<OriginData>(`/api/cases/${caseId}/origin`);
  return data;
}

/**
 * Permanently delete an investigation case
 * DELETE /api/cases/{case_id}
 */
export async function deleteCase(caseId: string): Promise<{ status: string; message: string }> {
  const { data } = await apiClient.delete<{ status: string; message: string }>(`/api/cases/${caseId}`);
  return data;
}

