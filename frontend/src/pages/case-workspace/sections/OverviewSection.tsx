import React, { useRef, useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  FileCheck,
  UploadCloud,
  Play,
  FileText,
  Layers,
  Share2,
  GitBranch,
  Globe,
  Server,
  Link,
} from 'lucide-react';
import { Panel, Button, Badge, EmptyState } from '../../../components';
import { useCaseWorkspace } from '../CaseWorkspaceContext';

export const OverviewSection: React.FC = () => {
  const {
    caseData,
    summary,
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
  } = useCaseWorkspace();

  const [isDragActive, setIsDragActive] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  const onFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleFileSelect(e.target.files[0]);
    }
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="case-workspace-body">
      {/* High-Level Threat Assessment Banner */}
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
                Forensic classification determined via ML threat model and deterministic evidence correlation.
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
                <span className="threat-metric-value" style={{ fontSize: '11px' }}>
                  {caseData.threat_confidence_metric.replace(/_/g, ' ')}
                </span>
              </div>
            )}
          </div>
        </div>
      ) : isRunning ? (
        <div className="threat-banner threat-banner-neutral">
          <div className="threat-banner-info">
            <div className="threat-banner-title">Pipeline Analysis Running</div>
            <div className="threat-banner-subtitle">
              Processing email forensic analysis pipeline across sender identity, lookalike-domain, URL, attachment, origin/infrastructure, evidence correlation, and ML analysis...
            </div>
          </div>
        </div>
      ) : (
        <div className="threat-banner threat-banner-unexecuted">
          <div className="threat-banner-info">
            <HelpCircle size={20} className="threat-banner-unexecuted-icon" />
            <div>
              <div className="threat-banner-unexecuted-title">Forensic analysis has not been executed.</div>
              <div className="threat-banner-unexecuted-desc">
                {hasArtifact
                  ? 'Artifact is preserved. Click "Run Forensic Analysis" to initiate Modules 1–6.'
                  : 'Upload a raw .eml artifact below to begin the investigation.'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Real Forensic Entity & Evidence Counters */}
      <div className="stat-counters-grid">
        <div className="stat-counter-card">
          <div className="stat-counter-icon stat-counter-icon-evidence">
            <FileText size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.evidence_count}</span>
            <span className="stat-counter-title">Evidence Artifacts</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon stat-counter-icon-entities">
            <Layers size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.entity_count}</span>
            <span className="stat-counter-title">Extracted Entities</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon stat-counter-icon-graph">
            <Share2 size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.relationship_count}</span>
            <span className="stat-counter-title">Graph Relationships</span>
          </div>
        </div>

        <div className="stat-counter-card">
          <div className="stat-counter-icon stat-counter-icon-hypotheses">
            <GitBranch size={18} />
          </div>
          <div className="stat-counter-data">
            <span className="stat-counter-number">{caseData.hypothesis_count}</span>
            <span className="stat-counter-title">Formulated Hypotheses</span>
          </div>
        </div>
      </div>

      {/* Artifact Ingress & Analysis Execution Controls */}
      <div className="case-operations-grid">
        {/* Upload / Artifact Preservation */}
        <Panel
          title="Evidence Ingress (.eml Artifact)"
          subtitle="Cryptographically preserve raw RFC 822 email payload"
        >
          {hasArtifact ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div className="artifact-verified-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                  <FileCheck size={16} style={{ color: 'var(--threat-benign)' }} />
                  <strong style={{ fontSize: 'var(--text-xs)' }}>Preserved Artifact</strong>
                  <Badge variant="success">SHA-256 Verified</Badge>
                </div>

                <div className="artifact-meta-row" style={{ marginTop: 'var(--space-1)' }}>
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
                    SHA-256 Digest:
                  </span>
                  <span className="hash-badge" style={{ wordBreak: 'break-all' }}>
                    {caseData.file_sha256}
                  </span>
                </div>
              </div>

              {/* Option to replace artifact */}
              <div>
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={onFileInputChange}
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
                onChange={onFileInputChange}
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
                onDrop={onDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <UploadCloud size={28} className="upload-icon" />
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
                    <strong style={{ fontSize: 'var(--text-xs)', display: 'block' }}>
                      {selectedFile.name}
                    </strong>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
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
                marginTop: 'var(--space-2)',
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
                marginTop: 'var(--space-2)',
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

        {/* Pipeline Execution */}
        <Panel
          title="Pipeline Execution"
          subtitle="Execute the email forensic analysis pipeline across sender identity, lookalike-domain, URL, attachment, origin/infrastructure, evidence correlation, and ML analysis."
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }}>
              Analysis extracts chronological Received hop sequences, analyzes SPF/DKIM/DMARC authentication evidence, parses body URLs, resolves infrastructure ASN/GeoIP data, and evaluates competing forensic hypotheses.
            </p>

            <div>
              <Button
                variant="primary"
                size="md"
                icon={<Play size={14} />}
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

      {/* Important Forensic Findings */}
      <Panel
        title="Important Forensic Findings"
        subtitle="Deterministic evidence rules and corroborated threat signals"
      >
        {summary && summary.important_forensic_findings && summary.important_forensic_findings.length > 0 ? (
          <div className="findings-list">
            {summary.important_forensic_findings.map((item, idx) => {
              let desc = item.description || '';
              if (desc.startsWith('Identified lookalike/impersonation domain corroborates')) {
                desc = desc.replace(
                  'Identified lookalike/impersonation domain corroborates',
                  'An identified lookalike/impersonation domain corroborates'
                );
              }
              if (desc.includes('deceptive domain registration')) {
                desc = desc.replace(
                  'deceptive domain registration',
                  'lookalike-domain and sender-identity deception indicators'
                );
              }

              return (
                <div key={idx} className="finding-item">
                  <div className="finding-item-header">
                    <span className="finding-rule">{item.rule_id || `Finding #${idx + 1}`}</span>
                    <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                      {item.severity && <Badge variant="danger">{item.severity.toUpperCase()}</Badge>}
                      {item.trust_state && <Badge variant="neutral">{item.trust_state}</Badge>}
                    </div>
                  </div>
                  <span className="finding-desc">{desc}</span>
                </div>
              );
            })}
          </div>
        ) : isCompleted ? (
          <EmptyState
            icon={<FileCheck size={20} />}
            title="Clean Forensic Baseline"
            description="The analysis pipeline finished. No high-severity malicious indicators were flagged."
          />
        ) : (
          <EmptyState
            icon={<FileText size={20} />}
            title="No forensic findings available"
            description="Upload an .eml artifact and run forensic analysis to generate findings."
          />
        )}
      </Panel>

      {/* Key Indicators (IOCs) */}
      <Panel
        title="Key Indicators of Compromise (IOCs)"
        subtitle="Critical domains, IP addresses, and URLs observed during analysis"
      >
        {summary && (
          (summary.key_domains && summary.key_domains.length > 0) ||
          (summary.key_ips && summary.key_ips.length > 0) ||
          (summary.key_urls && summary.key_urls.length > 0) ||
          (summary.suspicious_attachments && summary.suspicious_attachments.length > 0)
        ) ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {summary.key_domains && summary.key_domains.length > 0 && (
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Observed Domains:</span>
                <div className="ioc-chips-grid">
                  {summary.key_domains.map((dom, i) => (
                    <div key={i} className="ioc-chip-card">
                      <Globe size={13} className="ioc-chip-icon" />
                      <span className="mono-text">{dom}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {summary.key_ips && summary.key_ips.length > 0 && (
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Observed IP Addresses:</span>
                <div className="ioc-chips-grid">
                  {summary.key_ips.map((ip, i) => {
                    const isDocNet = ip === '198.51.100.99' || ip.startsWith('198.51.100.');
                    return (
                      <div key={i} className="ioc-chip-card">
                        <Server size={13} className="ioc-chip-icon" />
                        <span className="mono-text">{ip}</span>
                        {isDocNet && (
                          <Badge variant="warning">Documentation/Test Network</Badge>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {summary.key_urls && summary.key_urls.length > 0 && (
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Extracted URLs:</span>
                <div className="ioc-chips-grid">
                  {summary.key_urls.map((url, i) => (
                    <div key={i} className="ioc-chip-card" title={url}>
                      <Link size={13} className="ioc-chip-icon" />
                      <span className="mono-text">
                        {url.length > 60 ? `${url.substring(0, 60)}...` : url}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {summary.suspicious_attachments && summary.suspicious_attachments.length > 0 && (
              <div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Suspicious Attachments:</span>
                <div className="ioc-chips-grid">
                  {summary.suspicious_attachments.map((att, i) => (
                    <div key={i} className="ioc-chip-card">
                      <span className="mono-text">{att}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <EmptyState
            title="No Key Indicators Identified"
            description="Extracted IOCs will be listed here after pipeline execution."
          />
        )}
      </Panel>
    </div>
  );
};
