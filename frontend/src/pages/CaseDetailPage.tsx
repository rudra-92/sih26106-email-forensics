import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useParams } from 'react-router-dom';
import {
  RefreshCw,
  UploadCloud,
  Play,
  FileCheck,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Network,
  Share2,
  GitBranch,
  Layers,
  MapPin,
  FileText,
} from 'lucide-react';
import {
  Breadcrumb,
  Button,
  Panel,
  StatusBadge,
  Badge,
  LoadingState,
  ErrorState,
  EmptyState,
} from '../components';
import {
  fetchCaseById,
  uploadCaseEmail,
  analyzeCase,
  fetchCaseSummary,
  formatCaseError,
} from '../api/cases';
import type { Case, CaseSummary } from '../types';
import './CaseDetailPage.css';

export const CaseDetailPage: React.FC = () => {
  const { caseId } = useParams<{ caseId: string }>();

  const [caseData, setCaseData] = useState<Case | null>(null);
  const [summary, setSummary] = useState<CaseSummary | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // File Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const [isDragActive, setIsDragActive] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Analysis Trigger State
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [analysisNotice, setAnalysisNotice] = useState<string | null>(null);

  const loadCase = useCallback(async (quiet = false) => {
    if (!caseId) return;
    if (!quiet) setIsLoading(true);
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
          // Summary might be pending or unpopulated
          setSummary(null);
        }
      }
    } catch (err: unknown) {
      setError(formatCaseError(err));
    } finally {
      if (!quiet) setIsLoading(false);
    }
  }, [caseId]);

  useEffect(() => {
    loadCase();
  }, [loadCase]);

  // Careful polling when analysis is marked "running"
  useEffect(() => {
    if (caseData?.analysis_status !== 'running') return;

    const interval = setInterval(() => {
      loadCase(true);
    }, 2500);

    return () => clearInterval(interval);
  }, [caseData?.analysis_status, loadCase]);

  // File selection validation
  const validateAndSelectFile = (file: File) => {
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

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSelectFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSelectFile(e.dataTransfer.files[0]);
    }
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
      <div>
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

  const hasArtifact = Boolean(caseData.file_sha256);
  const isRunning = caseData.analysis_status === 'running' || isAnalyzing;
  const isCompleted = caseData.analysis_status === 'completed';

  // Threat banner styling
  const threatType = (caseData.threat_label || 'neutral').toLowerCase();
  let threatBannerClass = 'threat-banner-neutral';
  let ThreatIcon = HelpCircle;

  if (threatType.includes('phish') || threatType.includes('malicious')) {
    threatBannerClass = 'threat-banner-malicious';
    ThreatIcon = ShieldAlert;
  } else if (threatType.includes('suspicious') || threatType.includes('fraud')) {
    threatBannerClass = 'threat-banner-suspicious';
    ThreatIcon = AlertTriangle;
  } else if (threatType.includes('legit') || threatType.includes('benign')) {
    threatBannerClass = 'threat-banner-benign';
    ThreatIcon = ShieldCheck;
  }

  return (
    <div className="case-detail-container">
      {/* Breadcrumb Navigation */}
      <Breadcrumb
        items={[
          { label: 'Cases', to: '/cases' },
          { label: caseData.case_id },
        ]}
      />

      {/* Case Header Panel */}
      <div className="case-header-panel">
        <div className="case-header-top">
          <div className="case-header-title-area">
            <h1 className="case-header-title">{caseData.title}</h1>
            <div className="case-header-id-row">
              <span className="mono-text" style={{ fontWeight: 600 }}>{caseData.case_id}</span>
              <span>•</span>
              <div className="case-header-badges">
                <StatusBadge status={caseData.status} type="case" />
                <StatusBadge status={caseData.analysis_status} type="analysis" />
                {caseData.threat_label && (
                  <StatusBadge status={caseData.threat_label} type="threat" />
                )}
              </div>
            </div>
          </div>

          <div className="case-header-actions">
            <Button
              variant="outline"
              size="sm"
              icon={<RefreshCw size={14} />}
              onClick={() => loadCase(true)}
              disabled={isRunning}
            >
              Refresh Case
            </Button>
          </div>
        </div>

        <div className="case-header-meta-row">
          <div className="case-meta-item">
            <span style={{ color: 'var(--text-dim)' }}>Created:</span>
            <span>{new Date(caseData.created_at).toLocaleString()}</span>
          </div>
          <div className="case-meta-item">
            <span style={{ color: 'var(--text-dim)' }}>Updated:</span>
            <span>{new Date(caseData.updated_at).toLocaleString()}</span>
          </div>
          {caseData.original_filename && (
            <div className="case-meta-item">
              <span style={{ color: 'var(--text-dim)' }}>Artifact:</span>
              <span className="mono-text">{caseData.original_filename}</span>
            </div>
          )}
        </div>
      </div>

      {/* Threat Summary Banner */}
      {isCompleted ? (
        <div className={`threat-banner ${threatBannerClass}`}>
          <div className="threat-banner-info">
            <div className="threat-banner-icon">
              <ThreatIcon size={20} />
            </div>
            <div>
              <div className="threat-banner-title">
                {caseData.threat_label?.toUpperCase() || 'ASSESSED'}
              </div>
              <div className="threat-banner-subtitle">
                Forensic classification determined via ML fusion and rule correlation.
              </div>
            </div>
          </div>

          <div className="threat-banner-metrics">
            <div className="threat-metric-card">
              <span className="threat-metric-label">Model Confidence</span>
              <span className="threat-metric-value">
                {caseData.threat_confidence != null
                  ? `${(caseData.threat_confidence * 100).toFixed(2)}%`
                  : '—'}
              </span>
            </div>
            {caseData.threat_confidence_metric && (
              <div className="threat-metric-card">
                <span className="threat-metric-label">Confidence Metric</span>
                <span className="threat-metric-value" style={{ fontSize: 'var(--text-xs)' }}>
                  {caseData.threat_confidence_metric.replace(/_/g, ' ')}
                </span>
              </div>
            )}
          </div>
        </div>
      ) : isRunning ? (
        <div className="threat-banner threat-banner-neutral">
          <div className="threat-banner-info">
            <LoadingState label="Forensic analysis pipeline in progress..." />
          </div>
        </div>
      ) : (
        <div className="threat-banner threat-banner-neutral">
          <div className="threat-banner-info">
            <HelpCircle size={20} style={{ color: 'var(--text-muted)' }} />
            <div>
              <div style={{ fontWeight: 600 }}>Forensic analysis has not been run.</div>
              <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                {hasArtifact
                  ? 'Evidence artifact is preserved. Click "Run Forensic Analysis" to initiate Modules 1–6.'
                  : 'Upload a raw .eml artifact below to begin forensic investigation.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Real Counts Grid */}
      <div className="stat-counters-grid">
        <div className="stat-counter-card">
          <div className="stat-counter-icon">
            <FileText size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.evidence_count}</span>
            <span className="stat-counter-title">Evidence Artifacts</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon">
            <Layers size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.entity_count}</span>
            <span className="stat-counter-title">Extracted Entities</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon">
            <Share2 size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.relationship_count}</span>
            <span className="stat-counter-title">Graph Relationships</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon">
            <GitBranch size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.hypothesis_count}</span>
            <span className="stat-counter-title">Formulated Hypotheses</span>
          </div>
        </div>
      </div>

      {/* Evidence Ingress and Pipeline Execution */}
      <div className="case-operations-grid">
        {/* Email Artifact Upload */}
        <Panel
          title="Evidence Ingress (.eml Artifact)"
          subtitle="Cryptographically preserve raw RFC 822 email payload"
        >
          {hasArtifact ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div className="artifact-verified-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <FileCheck size={18} style={{ color: 'var(--threat-benign)' }} />
                  <strong style={{ fontSize: 'var(--text-sm)' }}>Preserved Artifact</strong>
                  <Badge variant="success">SHA-256 Verified</Badge>
                </div>

                <div className="artifact-meta-row" style={{ marginTop: 'var(--space-2)' }}>
                  <span className="artifact-meta-label">Original Filename:</span>
                  <span className="artifact-meta-val mono-text">{caseData.original_filename}</span>
                </div>

                <div className="artifact-meta-row">
                  <span className="artifact-meta-label">File Size:</span>
                  <span className="artifact-meta-val">
                    {caseData.file_size_bytes
                      ? `${(caseData.file_size_bytes / 1024).toFixed(1)} KB`
                      : '—'}
                  </span>
                </div>

                <div style={{ marginTop: 'var(--space-1)' }}>
                  <span className="artifact-meta-label" style={{ display: 'block', marginBottom: '2px' }}>
                    Cryptographic Digest (SHA-256):
                  </span>
                  <span className="hash-badge" style={{ wordBreak: 'break-all' }}>
                    {caseData.file_sha256}
                  </span>
                </div>
              </div>

              {/* Option to replace/re-upload */}
              <div style={{ marginTop: 'var(--space-2)' }}>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileChange}
                  accept=".eml"
                  style={{ display: 'none' }}
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isRunning}
                >
                  Replace Artifact (.eml)
                </Button>
              </div>
            </div>
          ) : (
            <div>
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                accept=".eml"
                style={{ display: 'none' }}
              />

              <div
                className={`upload-dropzone ${isDragActive ? 'drag-active' : ''}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  setIsDragActive(true);
                }}
                onDragLeave={() => setIsDragActive(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <UploadCloud size={32} className="upload-icon" />
                <span className="upload-instruction">
                  Click or drag and drop raw .eml artifact
                </span>
                <span className="upload-subtext">
                  Strictly RFC 822 .eml format • Max file size: 25 MB
                </span>
              </div>

              {selectedFile && (
                <div className="upload-file-selected">
                  <div>
                    <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>
                      {selectedFile.name}
                    </strong>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                      {(selectedFile.size / 1024).toFixed(1)} KB
                    </span>
                  </div>

                  <Button
                    variant="primary"
                    size="sm"
                    onClick={handleUpload}
                    isLoading={isUploading}
                  >
                    Upload Artifact
                  </Button>
                </div>
              )}
            </div>
          )}

          {uploadError && (
            <div
              style={{
                marginTop: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                backgroundColor: 'var(--threat-malicious-bg)',
                border: '1px solid var(--threat-malicious-border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--threat-malicious-text)',
                fontSize: 'var(--text-xs)',
              }}
            >
              {uploadError}
            </div>
          )}

          {uploadSuccess && (
            <div
              style={{
                marginTop: 'var(--space-3)',
                padding: 'var(--space-2) var(--space-3)',
                backgroundColor: 'var(--threat-benign-bg)',
                border: '1px solid var(--threat-benign-border)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--threat-benign-text)',
                fontSize: 'var(--text-xs)',
              }}
            >
              {uploadSuccess}
            </div>
          )}
        </Panel>

        {/* Pipeline Execution Action */}
        <Panel
          title="Pipeline Execution"
          subtitle="Execute Modules 1–6 (Hop Extraction, Content, Threat Intel, Graph Fusion)"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', marginBottom: 'var(--space-3)' }}>
                Analysis extracts chronological Received hop sequences, verifies SPF/DKIM authentication, parses body URLs, resolves infrastructure ASN/GeoIP data, and evaluates competing Bayesian hypotheses.
              </p>

              <Button
                variant="primary"
                size="md"
                icon={<Play size={15} />}
                onClick={handleRunAnalysis}
                disabled={!hasArtifact || isRunning}
                isLoading={isRunning}
              >
                {isRunning
                  ? 'Analysis in progress...'
                  : isCompleted
                  ? 'Re-run Forensic Analysis'
                  : 'Run Forensic Analysis'}
              </Button>

              {!hasArtifact && (
                <span
                  style={{
                    display: 'block',
                    marginTop: 'var(--space-2)',
                    fontSize: 'var(--text-xs)',
                    color: 'var(--text-dim)',
                  }}
                >
                  Upload an .eml artifact before executing pipeline analysis.
                </span>
              )}
            </div>

            {analysisError && (
              <div
                style={{
                  padding: 'var(--space-2) var(--space-3)',
                  backgroundColor: 'var(--threat-malicious-bg)',
                  border: '1px solid var(--threat-malicious-border)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--threat-malicious-text)',
                  fontSize: 'var(--text-xs)',
                }}
              >
                {analysisError}
              </div>
            )}

            {analysisNotice && (
              <div
                style={{
                  padding: 'var(--space-2) var(--space-3)',
                  backgroundColor: 'var(--action-primary-subtle)',
                  border: '1px solid var(--action-primary-border)',
                  borderRadius: 'var(--radius-sm)',
                  color: 'var(--action-primary)',
                  fontSize: 'var(--text-xs)',
                }}
              >
                {analysisNotice}
              </div>
            )}
          </div>
        </Panel>
      </div>

      {/* Forensic Findings Summary */}
      <Panel
        title="Executive Forensic Findings"
        subtitle="Deterministic evidence rules, formulated hypotheses, and IOC correlations"
      >
        {summary && summary.important_forensic_findings && summary.important_forensic_findings.length > 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
            {/* Rules Triggered */}
            <div>
              <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-2)' }}>
                Triggered Forensic Evidence Rules:
              </strong>
              <div className="findings-list">
                {summary.important_forensic_findings.map((item, idx) => (
                  <div key={idx} className="finding-item">
                    <div className="finding-item-header">
                      <span className="finding-rule">{item.rule_id || `Finding #${idx + 1}`}</span>
                      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                        {item.severity && <Badge variant="danger">{item.severity.toUpperCase()}</Badge>}
                        {item.trust_state && <Badge variant="neutral">{item.trust_state}</Badge>}
                      </div>
                    </div>
                    <span className="finding-desc">{item.description}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Key IOCs */}
            <div>
              <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-2)' }}>
                Extracted Indicators of Compromise (IOCs):
              </strong>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                {summary.key_domains && summary.key_domains.length > 0 && (
                  <div>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Domains:</span>
                    <div className="ioc-tags-container">
                      {summary.key_domains.map((dom, i) => (
                        <span key={i} className="ioc-tag">{dom}</span>
                      ))}
                    </div>
                  </div>
                )}

                {summary.key_ips && summary.key_ips.length > 0 && (
                  <div>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>IP Addresses:</span>
                    <div className="ioc-tags-container">
                      {summary.key_ips.map((ip, i) => (
                        <span key={i} className="ioc-tag">{ip}</span>
                      ))}
                    </div>
                  </div>
                )}

                {summary.key_urls && summary.key_urls.length > 0 && (
                  <div>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Extracted URLs:</span>
                    <div className="ioc-tags-container">
                      {summary.key_urls.map((url, i) => (
                        <span key={i} className="ioc-tag" title={url}>
                          {url.length > 60 ? `${url.substring(0, 60)}...` : url}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : isCompleted ? (
          <EmptyState
            icon={<FileCheck size={24} />}
            title="Analysis Completed with Clean Baseline"
            description="The analysis pipeline finished. No high-severity malicious indicators were flagged in this evidence artifact."
          />
        ) : (
          <EmptyState
            icon={<FileText size={24} />}
            title="No forensic findings are available."
            description="Upload an .eml artifact and click 'Run Forensic Analysis' to extract headers, IPs, entities, and hypotheses."
          />
        )}
      </Panel>

      {/* Structural Placeholders Reserved for Future Phases */}
      <Panel
        title="Advanced Investigation Visualizations (Reserved)"
        subtitle="Structural workstations prepared for subsequent integration phases"
      >
        <div className="phase-placeholder-grid">
          <div className="phase-placeholder-card">
            <Network size={28} className="phase-placeholder-icon" />
            <div className="phase-placeholder-title">Evidence & Entity Relationship Graph</div>
            <p className="phase-placeholder-desc">
              Interactive node-link graph mapping hops, sender identity, and multi-case entity linkages. Reserved for Phase 5 (React Flow).
            </p>
            <Badge variant="neutral">Phase 5 Integration</Badge>
          </div>

          <div className="phase-placeholder-card">
            <MapPin size={28} className="phase-placeholder-icon" />
            <div className="phase-placeholder-title">Origin Infrastructure Geospatial Map</div>
            <p className="phase-placeholder-desc">
              PoP routing geolocation, relay trajectory projection, and Autonomous System (ASN) intelligence. Reserved for Phase 6 (MapLibre).
            </p>
            <Badge variant="neutral">Phase 6 Integration</Badge>
          </div>
        </div>
      </Panel>
    </div>
  );
};
