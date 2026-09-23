import React, { useEffect, useState, useMemo } from 'react';
import { Panel, Badge, LoadingState, EmptyState } from '../../../components';
import { fetchCaseEvidence, fetchCaseHypotheses, fetchCaseOrigin } from '../../../api/cases';
import type { EvidenceItem, HypothesisItem, OriginData } from '../../../types';
import { useCaseWorkspace } from '../CaseWorkspaceContext';

interface TimelineEvent {
  id: string;
  category: string;
  title: string;
  description: string;
  timestamp: string | null;
  timestampType: 'rfc822_received' | 'system_recorded' | 'unspecified';
  badge: string;
  badgeVariant?: 'accent' | 'danger' | 'warning' | 'success' | 'neutral' | 'info';
}

export const TimelineSection: React.FC = () => {
  const { caseId, caseData } = useCaseWorkspace();

  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisItem[]>([]);
  const [originData, setOriginData] = useState<OriginData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    let isMounted = true;
    async function loadTimelineData() {
      if (caseData.analysis_status !== 'completed') {
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      try {
        const [evRes, hypRes, origRes] = await Promise.allSettled([
          fetchCaseEvidence(caseId),
          fetchCaseHypotheses(caseId),
          fetchCaseOrigin(caseId),
        ]);

        if (isMounted) {
          if (evRes.status === 'fulfilled') setEvidenceList(evRes.value.evidence || []);
          if (hypRes.status === 'fulfilled') setHypotheses(hypRes.value.hypotheses || []);
          if (origRes.status === 'fulfilled') setOriginData(origRes.value || null);
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadTimelineData();
    return () => {
      isMounted = false;
    };
  }, [caseId, caseData.analysis_status]);

  // Construct structured timeline events without fabricating fake timestamps
  const events = useMemo(() => {
    const list: TimelineEvent[] = [];

    // 1. Email transmission hops from Origin data (if timestamps exist in Received headers)
    if (originData?.hops && Array.isArray(originData.hops)) {
      originData.hops.forEach((hop, idx) => {
        const hopBy = hop.by || hop.recipient || 'Relay Server';
        const hopFrom = hop.from || hop.sender || 'Previous Hop';
        const hopTime = (hop.timestamp as string) || null;
        list.push({
          id: `hop-${idx}`,
          category: 'Transmission Relay Hop',
          title: `Hop #${idx + 1}: ${hopFrom} → ${hopBy}`,
          description: hop.delay ? `Observed transit delay: ${hop.delay}` : 'MTA transmission relay hop recorded in Received headers.',
          timestamp: hopTime,
          timestampType: hopTime ? 'rfc822_received' : 'unspecified',
          badge: `Hop ${idx + 1}`,
          badgeVariant: 'neutral',
        });
      });
    }

    // 2. Email Ingestion Event
    list.push({
      id: 'case-created',
      category: 'Email Ingestion',
      title: 'Investigation Ingestion & Case Initialization',
      description: `Case record created. Artifact '${caseData.original_filename || 'raw.eml'}' assigned cryptographic SHA-256 reference.`,
      timestamp: caseData.created_at,
      timestampType: 'system_recorded',
      badge: 'Ingestion',
      badgeVariant: 'info',
    });

    // 3. Evidence Extraction Events
    evidenceList.forEach((ev) => {
      let variant: 'accent' | 'danger' | 'warning' | 'success' | 'neutral' | 'info' = 'neutral';
      if (ev.severity === 'high' || ev.severity === 'critical') variant = 'danger';
      else if (ev.severity === 'medium') variant = 'warning';

      list.push({
        id: ev.evidence_id,
        category: 'Evidence Observation',
        title: `${ev.rule_id} (${ev.source_module})`,
        description: ev.description,
        timestamp: ev.timestamp || null,
        timestampType: ev.timestamp ? 'system_recorded' : 'unspecified',
        badge: ev.severity.toUpperCase(),
        badgeVariant: variant,
      });
    });

    // 4. ML Classification Event
    if (caseData.threat_label) {
      list.push({
        id: 'ml-classification',
        category: 'ML Classification',
        title: `Ensemble Threat Assessment: ${caseData.threat_label.toUpperCase()}`,
        description: `Threat model produced ${caseData.threat_confidence != null ? `${(caseData.threat_confidence * 100).toFixed(2)}%` : 'unspecified'} confidence under metric '${caseData.threat_confidence_metric || 'heuristic_consensus'}'.`,
        timestamp: caseData.updated_at,
        timestampType: 'system_recorded',
        badge: 'ML Ensemble',
        badgeVariant: caseData.threat_label === 'phishing' ? 'danger' : 'success',
      });
    }

    // 5. Hypothesis Formulation Events
    hypotheses.forEach((hyp) => {
      list.push({
        id: hyp.hypothesis_id,
        category: 'Hypothesis Formulation',
        title: `Formulated Hypothesis: ${hyp.hypothesis_type}`,
        description: hyp.description || `Evaluated with ${(hyp.confidence * 100).toFixed(2)}% confidence. Supported by ${hyp.supporting_evidence_ids?.length || 0} evidence items.`,
        timestamp: null,
        timestampType: 'unspecified',
        badge: 'Hypothesis',
        badgeVariant: 'info',
      });
    });

    return list;
  }, [caseData, originData, evidenceList, hypotheses]);

  if (caseData.analysis_status !== 'completed') {
    return (
      <Panel title="Forensic Timeline" subtitle="Structured timeline of transmission, ingestion, and evidence extraction">
        <EmptyState
          title="Analysis Not Run"
          description="Timeline events will be populated after evidence extraction and pipeline execution."
        />
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Constructing forensic timeline..." />;
  }

  return (
    <div className="case-workspace-body">
      <Panel
        title="Forensic Timeline"
        subtitle="Chronological sequence of email transmission, artifact ingestion, and forensic observations"
      >
        <div style={{ marginBottom: 'var(--space-3)', fontSize: '11px', color: 'var(--text-muted)' }}>
          Showing <strong>{events.length}</strong> forensic progression items. Timestamps are displayed strictly where recorded in RFC 822 headers or system storage; unrecorded steps maintain structural sequence without synthetic timestamps.
        </div>

        <div className="timeline-list">
          {events.map((evt) => (
            <div key={evt.id} className="timeline-event-item">
              <div className="timeline-event-bullet" />
              <div className="timeline-event-header">
                <span className="timeline-event-title">{evt.title}</span>
                <Badge variant={evt.badgeVariant || 'neutral'}>{evt.badge}</Badge>
                <span className="timeline-event-badge">{evt.category}</span>
                {evt.timestamp ? (
                  <span className="timeline-event-time">
                    {new Date(evt.timestamp).toLocaleString()}
                  </span>
                ) : (
                  <span className="timeline-event-time" style={{ fontStyle: 'italic' }}>
                    [Analysis Sequence]
                  </span>
                )}
              </div>
              <p className="timeline-event-desc">{evt.description}</p>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
};
