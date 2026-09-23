import React from 'react';
import { RefreshCw, Play, FileCheck } from 'lucide-react';
import { Breadcrumb, Button, StatusBadge, Badge } from '../../components';
import type { Case } from '../../types';

interface CaseWorkspaceHeaderProps {
  caseData: Case;
  onRefresh: () => void;
  isRefreshing: boolean;
  onRunAnalysis?: () => void;
  isAnalyzing?: boolean;
}

export const CaseWorkspaceHeader: React.FC<CaseWorkspaceHeaderProps> = ({
  caseData,
  onRefresh,
  isRefreshing,
  onRunAnalysis,
  isAnalyzing = false,
}) => {
  const isRunning = caseData.analysis_status === 'running' || isAnalyzing;
  const hasArtifact = Boolean(caseData.file_sha256);

  return (
    <header className="case-workspace-header">
      {/* Breadcrumb Navigation */}
      <Breadcrumb
        items={[
          { label: 'Cases', to: '/cases' },
          { label: caseData.case_id },
        ]}
      />

      {/* Primary Case Banner & Actions */}
      <div className="case-header-main">
        <div className="case-header-left">
          <div className="case-header-title-row">
            <h1 className="case-workspace-title">{caseData.title}</h1>
          </div>

          <div className="case-header-identity-row">
            <span className="case-header-id mono-text">{caseData.case_id}</span>
            <span className="case-header-dot">•</span>

            <div className="case-header-status-group">
              <StatusBadge status={caseData.status} type="case" />
              <StatusBadge status={caseData.analysis_status} type="analysis" />
              {caseData.threat_label && (
                <StatusBadge status={caseData.threat_label} type="threat" />
              )}
            </div>

            {caseData.threat_confidence != null && (
              <>
                <span className="case-header-dot">•</span>
                <div className="case-header-metric-pill">
                  <span className="case-header-metric-label">Model Confidence:</span>
                  <span className="case-header-metric-val mono-text">
                    {(caseData.threat_confidence * 100).toFixed(2)}%
                  </span>
                </div>
              </>
            )}
          </div>
        </div>

        <div className="case-header-actions">
          {onRunAnalysis && hasArtifact && caseData.analysis_status !== 'running' && (
            <Button
              variant="primary"
              size="sm"
              icon={<Play size={14} />}
              onClick={onRunAnalysis}
              isLoading={isAnalyzing}
              disabled={isRunning}
            >
              {caseData.analysis_status === 'completed' ? 'Re-run Analysis' : 'Run Analysis'}
            </Button>
          )}

          <Button
            variant="outline"
            size="sm"
            icon={<RefreshCw size={14} className={isRefreshing ? 'spin-icon' : ''} />}
            onClick={onRefresh}
            disabled={isRefreshing || isRunning}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Compact Metadata Sub-row */}
      <div className="case-header-meta-bar">
        <div className="case-meta-cell">
          <span className="case-meta-label">Created:</span>
          <span className="case-meta-value">{new Date(caseData.created_at).toLocaleString()}</span>
        </div>
        <div className="case-meta-cell">
          <span className="case-meta-label">Updated:</span>
          <span className="case-meta-value">{new Date(caseData.updated_at).toLocaleString()}</span>
        </div>
        {caseData.original_filename && (
          <div className="case-meta-cell">
            <span className="case-meta-label">Artifact:</span>
            <span className="case-meta-value mono-text">{caseData.original_filename}</span>
            {caseData.file_sha256 && (
              <Badge variant="success">
                <FileCheck size={11} style={{ marginRight: '3px' }} />
                SHA-256 Verified
              </Badge>
            )}
          </div>
        )}
      </div>
    </header>
  );
};
