import { createContext, useContext } from 'react';
import type { Case, CaseSummary } from '../../types';

export interface CaseWorkspaceContextType {
  caseId: string;
  caseData: Case;
  summary: CaseSummary | null;
  isLoading: boolean;
  error: string | null;
  refreshCase: (quiet?: boolean) => Promise<void>;
  // Analysis actions
  handleRunAnalysis: () => Promise<void>;
  isAnalyzing: boolean;
  analysisError: string | null;
  analysisNotice: string | null;
  // Upload actions
  selectedFile: File | null;
  isUploading: boolean;
  uploadError: string | null;
  uploadSuccess: string | null;
  handleFileSelect: (file: File) => void;
  handleUpload: () => Promise<void>;
  clearUploadFile: () => void;
}

export const CaseWorkspaceContext = createContext<CaseWorkspaceContextType | null>(null);

export function useCaseWorkspace(): CaseWorkspaceContextType {
  const context = useContext(CaseWorkspaceContext);
  if (!context) {
    throw new Error('useCaseWorkspace must be used within a CaseWorkspaceLayout');
  }
  return context;
}
