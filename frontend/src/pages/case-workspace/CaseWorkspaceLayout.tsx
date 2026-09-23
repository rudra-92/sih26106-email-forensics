import React, { useEffect, useState, useCallback } from 'react';
import { useParams, Outlet } from 'react-router-dom';
import { Breadcrumb, LoadingState, ErrorState } from '../../components';
import {
  fetchCaseById,
  fetchCaseSummary,
  uploadCaseEmail,
  analyzeCase,
  formatCaseError,
} from '../../api/cases';
import type { Case, CaseSummary } from '../../types';
import { CaseWorkspaceContext } from './CaseWorkspaceContext';
import { CaseWorkspaceHeader } from './CaseWorkspaceHeader';
import { CaseWorkspaceNav } from './CaseWorkspaceNav';
import './CaseWorkspace.css';

export const CaseWorkspaceLayout: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [summary, setSummary] = useState<CaseSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // File Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);

  // Analysis Trigger State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisNotice, setAnalysisNotice] = useState<string | null>(null);

  const loadCase = useCallback(async (quiet = false) => {
    if (!caseId) return;
    if (!quiet) setIsLoading(true);
    else setIsRefreshing(true);
    setError(null);

    try {
      const data = await fetchCaseById(caseId);
      setCaseData(data);

      // Attempt to load summary if analysis is completed
      if (data.analysis_status === 'completed') {
        try {
          const sum = await fetchCaseSummary(caseId);
          setSummary(sum);
        } catch {
          setSummary(null);
        }
      }
    } catch (err: unknown) {
      setError(formatCaseError(err));
    } finally {
      if (!quiet) setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadCase();
  }, [loadCase]);

  // Polling when analysis is marked "running"
  useEffect(() => {
    if (caseData?.analysis_status !== 'running') return;

    const interval = setInterval(() => {
      loadCase(true);
    }, 2500);

    return () => clearInterval(interval);
  }, [caseData?.analysis_status, loadCase]);

  // Upload validation & handler
  const handleFileSelect = (file: File) => {
    setUploadError(null);
    setUploadSuccess(null);

    if (!file.name.toLowerCase().endsWith('.eml')) {
      setUploadError('Invalid artifact format. Only raw .eml RFC 822 email files are accepted.');
      return;
    }

    if (file.size === 0) {
      setUploadError('Artifact file is empty (0 bytes). Please select a valid evidence file.');
      return;
    }

    const maxBytes = 25 * 1024 * 1024; // 25 MB
    if (file.size > maxBytes) {
      setUploadError('File exceeds maximum size limit (25 MB).');
      return;
    }

    setSelectedFile(file);
  };

  const handleUpload = async () => {
    if (!caseId || !selectedFile) return;

    setIsUploading(true);
    setUploadError(null);
    setUploadSuccess(null);

    try {
      const res = await uploadCaseEmail(caseId, selectedFile);
      setUploadSuccess(`Artifact '${res.original_filename}' uploaded successfully. SHA-256 digest recorded.`);
      setSelectedFile(null);
      await loadCase(true);
    } catch (err: unknown) {
      setUploadError(formatCaseError(err));
    } finally {
      setIsUploading(false);
    }
  };

  const clearUploadFile = () => {
    setSelectedFile(null);
    setUploadError(null);
  };

  // Run analysis trigger
  const handleRunAnalysis = async () => {
    if (!caseId) return;

    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysisNotice(null);

    try {
      const res = await analyzeCase(caseId);
      setAnalysisNotice(res.message || 'Forensic analysis completed successfully.');
      await loadCase(true);
    } catch (err: unknown) {
      setAnalysisError(formatCaseError(err));
    } finally {
      setIsAnalyzing(false);
    }
  };

  if (isLoading) {
    return <LoadingState label="Loading investigation case workspace..." />;
  }

  if (error || !caseData) {
    return (
      <div className="case-workspace-container">
        <Breadcrumb
          items={[
            { label: 'Cases', to: '/cases' },
            { label: caseId || 'Investigation' },
          ]}
        />
        <ErrorState
          title="Case Workspace Error"
          message={error || 'The requested investigation record could not be loaded.'}
          onRetry={() => loadCase()}
        />
      </div>
    );
  }

  const contextValue = {
    caseId: caseData.case_id,
    caseData,
    summary,
    isLoading: false,
    error: null,
    refreshCase: loadCase,
    handleRunAnalysis,
    isAnalyzing,
    analysisError,
    analysisNotice,
    selectedFile,
    isUploading,
    uploadError,
    uploadSuccess,
    handleFileSelect,
    handleUpload,
    clearUploadFile,
  };

  return (
    <CaseWorkspaceContext.Provider value={contextValue}>
      <div className="case-workspace-container">
        {/* Persistent Case-Level Header */}
        <CaseWorkspaceHeader
          caseData={caseData}
          onRefresh={() => loadCase(true)}
          isRefreshing={isRefreshing}
          onRunAnalysis={handleRunAnalysis}
          isAnalyzing={isAnalyzing}
        />

        {/* Section Navigation Tabs */}
        <CaseWorkspaceNav caseId={caseData.case_id} caseData={caseData} />

        {/* Dynamic Nested Route Section Content */}
        <Outlet />
      </div>
    </CaseWorkspaceContext.Provider>
  );
};
