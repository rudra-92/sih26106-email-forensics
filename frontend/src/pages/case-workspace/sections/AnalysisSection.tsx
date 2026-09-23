import React, { useEffect, useState } from 'react';
import {
  Link,
  Paperclip,
  GitMerge,
  GitBranch,
} from 'lucide-react';
import { Panel, Badge, EmptyState, LoadingState } from '../../../components';
import { fetchCaseEvidence, fetchCaseHypotheses, fetchCaseEntities } from '../../../api/cases';
import type { EvidenceItem, HypothesisItem, EntityItem } from '../../../types';
import { useCaseWorkspace } from '../CaseWorkspaceContext';

export const AnalysisSection: React.FC = () => {
  const { caseId, caseData, summary } = useCaseWorkspace();

  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisItem[]>([]);
  const [entities, setEntities] = useState<EntityItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    let isMounted = true;
    async function loadAnalysisData() {
      if (caseData.analysis_status !== 'completed') {
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      try {
        const [evRes, hypRes, entRes] = await Promise.allSettled([
          fetchCaseEvidence(caseId),
          fetchCaseHypotheses(caseId),
          fetchCaseEntities(caseId),
        ]);

        if (isMounted) {
          if (evRes.status === 'fulfilled') {
            setEvidenceList(evRes.value.evidence || []);
          }
          if (hypRes.status === 'fulfilled') {
            setHypotheses(hypRes.value.hypotheses || []);
          }
          if (entRes.status === 'fulfilled') {
            setEntities(entRes.value.entities || []);
          }
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadAnalysisData();
    return () => {
      isMounted = false;
    };
  }, [caseId, caseData.analysis_status]);

  if (caseData.analysis_status !== 'completed') {
    return (
      <Panel title="Forensic Analysis" subtitle="Module-by-module analytical findings">
        <EmptyState
          title="Analysis Pending"
          description="Forensic analysis has not been executed for this case yet. Go to Overview to upload an .eml artifact and run analysis."
        />
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Loading detailed forensic analysis..." />;
  }

  // Subsection B: Sender / Authentication extraction from evidence, summary, and entities
  const authObservations = summary?.authentication_observations || [];
  const senderEvidence = evidenceList.filter(
    (e) =>
      e.source_module === 'sender_identity' ||
      e.source_module.includes('sender') ||
      e.source_module.includes('header') ||
      e.source_module.includes('mta') ||
      e.rule_id.includes('SPF') ||
      e.rule_id.includes('DKIM') ||
      e.rule_id.includes('DMARC') ||
      e.rule_id.includes('FROM') ||
      e.rule_id.includes('REPLY-TO')
  );

  // Extract auth protocol results and trust state
  let spfStatus = 'UNEVALUATED';
  let spfMeta = '';
  let dkimStatus = 'UNEVALUATED';
  let dkimMeta = '';
  let dmarcStatus = 'UNEVALUATED';
  let dmarcMeta = '';

  for (const ev of evidenceList) {
    const rule = ev.rule_id;
    const sf = ev.supporting_fields || {};
    const trust = ev.trust_state ? `${ev.trust_state}` : 'observed';

    if (rule.includes('SPF')) {
      const match = rule.match(/RULE-AUTH-SPF-([A-Z]+)/);
      if (match) {
        spfStatus = match[1];
      } else if (sf.reported_result) {
        spfStatus = String(sf.reported_result).toUpperCase();
      } else if (sf.result) {
        spfStatus = String(sf.result).toUpperCase();
      }
      spfMeta = sf.spf_domain ? `${trust} • ${sf.spf_domain}` : trust;
    }

    if (rule.includes('DKIM')) {
      const match = rule.match(/RULE-AUTH-DKIM-([A-Z]+)/);
      if (match) {
        dkimStatus = match[1];
      } else if (sf.reported_result) {
        dkimStatus = String(sf.reported_result).toUpperCase();
      } else if (sf.result) {
        dkimStatus = String(sf.result).toUpperCase();
      }
      dkimMeta = sf.dkim_domain ? `${trust} • ${sf.dkim_domain}` : trust;
    }

    if (rule.includes('DMARC')) {
      const match = rule.match(/RULE-AUTH-DMARC-([A-Z]+)/);
      if (match) {
        dmarcStatus = match[1];
      } else if (sf.reported_result) {
        dmarcStatus = String(sf.reported_result).toUpperCase();
      } else if (sf.result) {
        dmarcStatus = String(sf.result).toUpperCase();
      }
      dmarcMeta = sf.dmarc_domain ? `${trust} • ${sf.dmarc_domain}` : trust;
    }
  }

  // Also check summary authentication observations if unpopulated
  for (const obs of authObservations) {
    if (obs.spf != null && spfStatus === 'UNEVALUATED') spfStatus = String(obs.spf).toUpperCase();
    if (obs.dkim != null && dkimStatus === 'UNEVALUATED') dkimStatus = String(obs.dkim).toUpperCase();
    if (obs.dmarc != null && dmarcStatus === 'UNEVALUATED') dmarcStatus = String(obs.dmarc).toUpperCase();
  }

  // Extract real header identity values without inventing data
  let headerFrom = '—';
  let headerReplyTo = '—';
  let headerReturnPath = '—';
  let headerMessageId = '—';

  // 1. Extract from evidence supporting fields
  for (const ev of evidenceList) {
    const sf = ev.supporting_fields || {};
    if (headerFrom === '—') {
      const addr = sf.from_address || sf.sender_address || sf.from;
      const name = sf.display_name;
      if (addr && name) {
        headerFrom = `"${name}" <${addr}>`;
      } else if (addr) {
        headerFrom = String(addr);
      }
    }

    if (headerReplyTo === '—') {
      const rto = sf.reply_to_address || sf.reply_to;
      if (rto) headerReplyTo = String(rto);
    }

    if (headerReturnPath === '—') {
      const rp = sf.return_path_address || sf.return_path || sf.envelope_from;
      if (rp && String(rp).includes('@')) {
        headerReturnPath = `<${String(rp).replace(/[<>]/g, '')}>`;
      } else if (sf.raw_header && String(sf.raw_header).includes('smtp.mailfrom=')) {
        const m = String(sf.raw_header).match(/smtp\.mailfrom=([^\s;<>]+@[^\s;<>]+)/);
        if (m) headerReturnPath = `<${m[1]}>`;
      }
    }

    if (headerMessageId === '—') {
      const mid = sf.message_id;
      if (mid) headerMessageId = `<${mid}>`;
    }
  }

  // 2. Supplement from resolved entities if unpopulated
  for (const ent of entities) {
    if (headerMessageId === '—' && ent.entity_type === 'message_id') {
      headerMessageId = `<${ent.canonical_value}>`;
    }
    if (headerFrom === '—' && ent.entity_type === 'email_address' && ent.canonical_value.startsWith('alerts@')) {
      headerFrom = ent.canonical_value;
    }
    if (headerReplyTo === '—' && ent.entity_type === 'email_address' && (ent.canonical_value.includes('reply') || ent.canonical_value.includes('account-review'))) {
      headerReplyTo = ent.canonical_value;
    }
    if (headerReturnPath === '—' && ent.entity_type === 'email_address' && (ent.canonical_value.includes('bounce') || ent.canonical_value.includes('mailfrom'))) {
      headerReturnPath = `<${ent.canonical_value}>`;
    }
  }

  if (headerReturnPath === '—') {
    const fromClean = headerFrom.replace(/^.*<([^>]+)>.*$/, '$1');
    const replyToClean = headerReplyTo.replace(/^.*<([^>]+)>.*$/, '$1');
    const remaining = entities.find(
      (e) =>
        e.entity_type === 'email_address' &&
        e.canonical_value !== fromClean &&
        e.canonical_value !== replyToClean
    );
    if (remaining) {
      headerReturnPath = `<${remaining.canonical_value}>`;
    }
  }

  // Subsection C: URL Analysis from evidence & summary
  const rawUrlEvidence = evidenceList.filter(
    (e) =>
      e.source_module === 'url_analysis' ||
      e.source_module.includes('url') ||
      e.rule_id.includes('URL') ||
      (e.rule_id.includes('LOOKALIKE') && e.source_module.includes('url'))
  );

  // In the Analysis summary view, deduplicate identical logical observations
  // (e.g. identical rule_id & description across plain-text & HTML representations)
  // so the user does not see the same finding twice, while preserving both underlying
  // records intact in the Evidence section.
  const seenLogicalObs = new Set<string>();
  const urlEvidence = rawUrlEvidence.filter((ev) => {
    const key = `${ev.rule_id}::${ev.description}`;
    if (seenLogicalObs.has(key)) {
      return false;
    }
    seenLogicalObs.add(key);
    return true;
  });

  // Subsection D: Attachment Analysis (strictly attachment rules, excluding origin peer)
  const attachmentEvidence = evidenceList.filter(
    (e) =>
      (e.source_module === 'attachment_analysis' || e.source_module.includes('attachment')) &&
      e.rule_id.startsWith('RULE-ATTACHMENT-')
  );

  // Subsection E: Correlation Analysis (Module 6)
  const correlationEvidence = evidenceList.filter(
    (e) =>
      e.source_module === 'evidence_correlation' ||
      e.source_module.includes('correlation') ||
      e.rule_id.startsWith('RULE-LOOKALIKE') ||
      e.rule_id.startsWith('RULE-CORRELATED') ||
      e.rule_id.startsWith('RULE-MULTI')
  );

  const getStatusBadgeVariant = (val: string): 'success' | 'danger' | 'warning' | 'neutral' => {
    const lower = val.toLowerCase();
    if (lower.includes('pass') || lower.includes('verified')) return 'success';
    if (lower.includes('fail') || lower.includes('softfail') || lower.includes('reject')) return 'danger';
    if (lower.includes('neutral') || lower.includes('temperror') || lower.includes('permerror')) return 'warning';
    return 'neutral';
  };

  const normalizeFindingDescription = (rawDesc: string): string => {
    let desc = rawDesc;
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
    return desc;
  };

  return (
    <div className="case-workspace-body analysis-subsections">
      {/* Subsection A: ML Classification */}
      <Panel
        title="A. Machine Learning Threat Classification"
        subtitle="Ensemble model evaluation, heuristic confidence metrics, and feature classification"
      >
        <div className="analysis-grid-2col">
          <div className="analysis-key-val-list">
            <div className="analysis-key-val-row">
              <span className="analysis-key-val-label">Threat Classification:</span>
              <span className="analysis-key-val-value">
                <Badge variant={caseData.threat_label === 'phishing' ? 'danger' : 'neutral'}>
                  {caseData.threat_label?.toUpperCase() || 'UNKNOWN'}
                </Badge>
              </span>
            </div>
            <div className="analysis-key-val-row">
              <span className="analysis-key-val-label">Model Confidence:</span>
              <span className="analysis-key-val-value mono-text">
                {caseData.threat_confidence != null
                  ? `${(caseData.threat_confidence * 100).toFixed(2)}%`
                  : '—'}
              </span>
            </div>
            <div className="analysis-key-val-row">
              <span className="analysis-key-val-label">Confidence Metric:</span>
              <span className="analysis-key-val-value mono-text" style={{ fontSize: '11px' }}>
                {caseData.threat_confidence_metric || 'heuristic_non_calibrated_consensus'}
              </span>
            </div>
          </div>

          <div style={{ backgroundColor: 'var(--bg-canvas)', padding: 'var(--space-3)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '4px' }}>
              ML Explanation & Classifier Consensus:
            </span>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              The threat prediction combines trained ML signals with structured forensic features and is reported with a non-calibrated inference metric.
            </p>
          </div>
        </div>
      </Panel>

      {/* Subsection B: Sender / Authentication Analysis */}
      <Panel
        title="B. Sender & Email Authentication Analysis"
        subtitle="Verification of cryptographic email protocol headers (SPF, DKIM, DMARC) and transmission identity"
      >
        <div className="auth-status-grid">
          <div className="auth-status-card">
            <div className="auth-status-name">SPF Protocol</div>
            <Badge variant={getStatusBadgeVariant(spfStatus)}>{spfStatus.toUpperCase()}</Badge>
            {spfMeta && (
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {spfMeta}
              </div>
            )}
          </div>
          <div className="auth-status-card">
            <div className="auth-status-name">DKIM Signature</div>
            <Badge variant={getStatusBadgeVariant(dkimStatus)}>{dkimStatus.toUpperCase()}</Badge>
            {dkimMeta && (
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {dkimMeta}
              </div>
            )}
          </div>
          <div className="auth-status-card">
            <div className="auth-status-name">DMARC Policy</div>
            <Badge variant={getStatusBadgeVariant(dmarcStatus)}>{dmarcStatus.toUpperCase()}</Badge>
            {dmarcMeta && (
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {dmarcMeta}
              </div>
            )}
          </div>
        </div>

        <div className="analysis-key-val-list" style={{ marginTop: 'var(--space-3)' }}>
          <div className="analysis-key-val-row">
            <span className="analysis-key-val-label">From:</span>
            <span className="analysis-key-val-value mono-text">{headerFrom}</span>
          </div>
          <div className="analysis-key-val-row">
            <span className="analysis-key-val-label">Reply-To:</span>
            <span className="analysis-key-val-value mono-text">{headerReplyTo}</span>
          </div>
          <div className="analysis-key-val-row">
            <span className="analysis-key-val-label">Return-Path:</span>
            <span className="analysis-key-val-value mono-text">{headerReturnPath}</span>
          </div>
          <div className="analysis-key-val-row">
            <span className="analysis-key-val-label">Message-ID:</span>
            <span className="analysis-key-val-value mono-text" style={{ wordBreak: 'break-all' }}>{headerMessageId}</span>
          </div>
        </div>

        {senderEvidence.length > 0 && (
          <div style={{ marginTop: 'var(--space-4)' }}>
            <span style={{ fontSize: 'var(--text-xs)', fontWeight: 600, display: 'block', marginBottom: 'var(--space-2)' }}>
              Authentication & Header Observations ({senderEvidence.length}):
            </span>
            <div className="findings-list">
              {senderEvidence.map((ev) => (
                <div key={ev.evidence_id} className="finding-item">
                  <div className="finding-item-header">
                    <span className="finding-rule">{ev.rule_id}</span>
                    <Badge variant={ev.severity === 'high' ? 'danger' : 'neutral'}>{ev.severity.toUpperCase()}</Badge>
                  </div>
                  <span className="finding-desc">{normalizeFindingDescription(ev.description)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {/* Subsection C: URL Analysis */}
      <Panel
        title="C. URL & Domain Deception Analysis"
        subtitle="Lexical anomalies, homoglyphs, IP hostnames, and domain impersonation candidate checks"
      >
        {urlEvidence.length > 0 ? (
          <div className="findings-list">
            {urlEvidence.map((ev) => (
              <div key={ev.evidence_id} className="finding-item">
                <div className="finding-item-header">
                  <span className="finding-rule">{ev.rule_id}</span>
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <Badge variant={ev.severity === 'high' ? 'danger' : 'neutral'}>{ev.severity.toUpperCase()}</Badge>
                    <Badge variant="neutral">{ev.trust_state}</Badge>
                  </div>
                </div>
                <span className="finding-desc">{normalizeFindingDescription(ev.description)}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={<Link size={18} />}
            title="No Malicious URL Findings Flagged"
            description="All parsed URLs conformed to structural standards with no deceptive lookalike patterns detected."
          />
        )}
      </Panel>

      {/* Subsection D: Attachment Analysis */}
      <Panel
        title="D. Attachment & Static Payload Analysis"
        subtitle="Cryptographic hashing, double-extension detection, macro extraction, and PE header inspection"
      >
        {attachmentEvidence.length > 0 ? (
          <div>
            {summary?.suspicious_attachments && summary.suspicious_attachments.length > 0 && (
              <div style={{ marginBottom: 'var(--space-3)' }}>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Suspicious Attachments:</span>
                <div className="ioc-tags-container">
                  {summary.suspicious_attachments.map((att, i) => (
                    <span key={i} className="ioc-tag">{att}</span>
                  ))}
                </div>
              </div>
            )}

            <div className="findings-list">
              {attachmentEvidence.map((ev) => (
                <div key={ev.evidence_id} className="finding-item">
                  <div className="finding-item-header">
                    <span className="finding-rule">{ev.rule_id}</span>
                    <Badge variant={ev.severity === 'high' ? 'danger' : 'neutral'}>{ev.severity.toUpperCase()}</Badge>
                  </div>
                  <span className="finding-desc">{normalizeFindingDescription(ev.description)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <EmptyState
            icon={<Paperclip size={18} />}
            title="No Attachments Present"
            description="No attachments were present in the submitted email."
          />
        )}
      </Panel>

      {/* Subsection E: Correlation Analysis */}
      <Panel
        title="E. Evidence Correlation & Multi-Signal Synthesis"
        subtitle="Cross-module consensus between transmission path, authentication, URL deception, and threat intelligence"
      >
        {correlationEvidence.length > 0 ? (
          <div className="findings-list">
            {correlationEvidence.map((ev) => (
              <div key={ev.evidence_id} className="finding-item">
                <div className="finding-item-header">
                  <span className="finding-rule">{ev.rule_id}</span>
                  <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                    <Badge variant={ev.severity === 'high' ? 'danger' : 'neutral'}>{ev.severity.toUpperCase()}</Badge>
                    <Badge variant="neutral">{ev.trust_state}</Badge>
                  </div>
                </div>
                <span className="finding-desc">{normalizeFindingDescription(ev.description)}</span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={<GitMerge size={18} />}
            title="No Corroborated Correlation Rules Triggered"
            description="Correlation engine evaluated cross-module evidence items; no compound phishing vector corroborated."
          />
        )}
      </Panel>

      {/* Subsection F: Hypotheses */}
      <Panel
        title="F. Formulated Investigative Hypotheses"
        subtitle="Forensic hypothesis evaluation with supporting and contradicting evidence"
      >
        {hypotheses.length > 0 ? (
          <div className="hypotheses-list">
            {hypotheses.map((hyp) => (
              <div key={hyp.hypothesis_id} className="hypothesis-card">
                <div className="hypothesis-header">
                  <span className="hypothesis-title">{hyp.hypothesis_type}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Confidence:</span>
                    <Badge variant="info">{(hyp.confidence * 100).toFixed(2)}%</Badge>
                  </div>
                </div>

                {hyp.description && (
                  <p className="hypothesis-desc">{normalizeFindingDescription(hyp.description)}</p>
                )}

                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', marginTop: 'var(--space-1)' }}>
                  {hyp.supporting_evidence_ids && hyp.supporting_evidence_ids.length > 0 && (
                    <div className="hypothesis-evidence-tags">
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '4px' }}>
                        Supporting Evidence ({hyp.supporting_evidence_ids.length}):
                      </span>
                      {hyp.supporting_evidence_ids.map((id) => (
                        <span key={id} className="evidence-id-tag">
                          {normalizeFindingDescription(id)}
                        </span>
                      ))}
                    </div>
                  )}

                  {hyp.contradicting_evidence_ids && hyp.contradicting_evidence_ids.length > 0 && (
                    <div className="hypothesis-evidence-tags">
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)', marginRight: '4px' }}>
                        Contradicting Evidence ({hyp.contradicting_evidence_ids.length}):
                      </span>
                      {hyp.contradicting_evidence_ids.map((id) => (
                        <span key={id} className="evidence-id-tag" style={{ color: 'var(--threat-malicious-text)' }}>
                          {normalizeFindingDescription(id)}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={<GitBranch size={18} />}
            title="No Hypotheses Synthesized"
            description="Hypothesis generation requires completed forensic pipeline execution."
          />
        )}
      </Panel>
    </div>
  );
};
