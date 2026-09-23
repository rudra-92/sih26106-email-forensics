import React, { useEffect, useState, useCallback } from 'react';
import { Layers, Share2, Shield, GitBranch, RefreshCw, AlertCircle } from 'lucide-react';
import { Panel, Badge, LoadingState, EmptyState } from '../../../components';
import { fetchCaseEntities, fetchCaseRelationships, fetchCaseEvidence } from '../../../api/cases';
import type { EntityItem, RelationshipItem, EvidenceItem } from '../../../types';
import { useCaseWorkspace } from '../CaseWorkspaceContext';
import { ForensicGraph } from '../../../components/graph';

export const GraphSection: React.FC = () => {
  const { caseId, caseData } = useCaseWorkspace();

  const [entities, setEntities] = useState<EntityItem[]>([]);
  const [relationships, setRelationships] = useState<RelationshipItem[]>([]);
  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [hasError, setHasError] = useState<boolean>(false);

  const loadGraphData = useCallback(async () => {
    if (caseData.analysis_status !== 'completed') {
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    setHasError(false);
    try {
      const [entitiesRes, relationshipsRes, evidenceRes] = await Promise.all([
        fetchCaseEntities(caseId),
        fetchCaseRelationships(caseId),
        fetchCaseEvidence(caseId).catch(() => ({ evidence: [] as EvidenceItem[], total: 0, case_id: caseId })),
      ]);
      setEntities(entitiesRes.entities || []);
      setRelationships(relationshipsRes.relationships || []);
      setEvidenceList(evidenceRes.evidence || []);
    } catch {
      setHasError(true);
      setEntities([]);
      setRelationships([]);
      setEvidenceList([]);
    } finally {
      setIsLoading(false);
    }
  }, [caseId, caseData.analysis_status]);

  useEffect(() => {
    loadGraphData();
  }, [loadGraphData]);

  if (caseData.analysis_status !== 'completed') {
    return (
      <Panel
        title="FORENSIC EVIDENCE GRAPH"
        subtitle="Forensic entity-relationship projection based strictly on pipeline observations."
      >
        <EmptyState
          title="Analysis Not Run"
          description="Graph nodes and edges will be populated after evidence extraction and pipeline execution."
        />
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Loading forensic graph…" />;
  }

  if (hasError) {
    return (
      <Panel
        title="FORENSIC EVIDENCE GRAPH"
        subtitle="Forensic entity-relationship projection based strictly on pipeline observations."
      >
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--space-8)',
            textAlign: 'center',
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
          }}
        >
          <AlertCircle size={32} style={{ color: 'var(--action-danger)', marginBottom: 'var(--space-2)' }} />
          <h4 style={{ margin: '0 0 var(--space-1) 0', fontSize: 'var(--text-sm)', color: 'var(--text-primary)' }}>
            Unable to load the evidence graph.
          </h4>
          <p style={{ margin: '0 0 var(--space-4) 0', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
            The case entity and relationship endpoints could not be retrieved.
          </p>
          <button
            type="button"
            className="graph-toolbar-btn"
            onClick={loadGraphData}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <RefreshCw size={12} />
            <span>Retry</span>
          </button>
        </div>
      </Panel>
    );
  }

  const threatLabel = (caseData.threat_label || 'unknown').toUpperCase();
  const confidenceScore =
    caseData.threat_confidence != null ? `${(caseData.threat_confidence * 100).toFixed(1)}%` : '—';

  return (
    <div className="case-workspace-body">
      <Panel
        title="FORENSIC EVIDENCE GRAPH"
        subtitle="Forensic entity-relationship projection based strictly on pipeline observations."
      >
        {/* Compact Forensic Threat & Evidence Context Bar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 'var(--space-3)',
            paddingBottom: 'var(--space-2)',
            borderBottom: '1px solid var(--border-subtle)',
            marginBottom: 'var(--space-3)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Shield size={13} style={{ color: 'var(--action-primary)' }} />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Threat Classification:</span>
              <Badge variant={threatLabel === 'PHISHING' ? 'danger' : threatLabel === 'LEGITIMATE' ? 'success' : 'neutral'}>
                {threatLabel}
              </Badge>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                ({confidenceScore} <span title="non_calibrated_ml_inference" style={{ fontSize: '10px' }}>non-calibrated ML inference</span>)
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Layers size={13} style={{ color: 'var(--action-primary)' }} />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Entities:</span>
              <strong className="mono-text" style={{ fontSize: '11px' }}>
                {entities.length}
              </strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Share2 size={13} style={{ color: 'var(--action-primary)' }} />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Relationships:</span>
              <strong className="mono-text" style={{ fontSize: '11px' }}>
                {relationships.length}
              </strong>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <GitBranch size={13} style={{ color: 'var(--action-primary)' }} />
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Hypotheses:</span>
              <strong className="mono-text" style={{ fontSize: '11px' }}>
                {caseData.hypothesis_count ?? '—'}
              </strong>
            </div>
          </div>

          <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
            Case ID: <span className="mono-text" style={{ fontWeight: 600 }}>{caseId}</span>
          </div>
        </div>

        {/* Real Interactive Forensic Evidence Graph */}
        <ForensicGraph
          entities={entities}
          relationships={relationships}
          evidenceList={evidenceList}
        />
      </Panel>
    </div>
  );
};
