import React, { useState } from 'react';
import { X, Code, Check } from 'lucide-react';
import { Badge, Button } from '../../../components';
import type { EvidenceItem } from '../../../types';

interface EvidenceDetailDrawerProps {
  evidence: EvidenceItem | null;
  onClose: () => void;
}

export const EvidenceDetailDrawer: React.FC<EvidenceDetailDrawerProps> = ({
  evidence,
  onClose,
}) => {
  const [showRawJson, setShowRawJson] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  if (!evidence) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(evidence, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadgeVariant = (sev: string): 'danger' | 'warning' | 'neutral' => {
    const s = sev.toLowerCase();
    if (s === 'critical' || s === 'high') return 'danger';
    if (s === 'medium') return 'warning';
    return 'neutral';
  };

  return (
    <aside className="evidence-detail-drawer" aria-label="Evidence Detail Panel">
      <div className="drawer-header">
        <div>
          <span style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700 }}>
            Evidence Detail
          </span>
          <div className="drawer-title mono-text">{evidence.evidence_id}</div>
        </div>
        <button className="drawer-close-btn" onClick={onClose} title="Close panel">
          <X size={16} />
        </button>
      </div>

      <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap' }}>
        <Badge variant={getSeverityBadgeVariant(evidence.severity)}>
          {evidence.severity.toUpperCase()}
        </Badge>
        <Badge variant="neutral">{evidence.trust_state}</Badge>
        <Badge variant="info">{evidence.source_module}</Badge>
      </div>

      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Rule Identifier:</span>
        <div className="mono-text" style={{ fontSize: 'var(--text-xs)', fontWeight: 700, marginTop: '2px' }}>
          {evidence.rule_id}
        </div>
      </div>

      <div>
        <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Description:</span>
        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', lineHeight: 1.4, marginTop: '2px' }}>
          {evidence.description}
        </p>
      </div>

      {evidence.timestamp && (
        <div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>Observation Timestamp:</span>
          <div className="mono-text" style={{ fontSize: '11px', marginTop: '2px' }}>
            {evidence.timestamp}
          </div>
        </div>
      )}

      {evidence.entity_ids && evidence.entity_ids.length > 0 && (
        <div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>
            Linked Entity IDs ({evidence.entity_ids.length}):
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
            {evidence.entity_ids.map((id) => (
              <span key={id} className="evidence-id-tag">{id}</span>
            ))}
          </div>
        </div>
      )}

      {evidence.provenance && evidence.provenance.length > 0 && (
        <div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>
            Provenance Trail:
          </span>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
            {evidence.provenance.map((p, idx) => (
              <span key={idx} className="evidence-id-tag" style={{ fontSize: '10px' }}>{p}</span>
            ))}
          </div>
        </div>
      )}

      {evidence.supporting_fields && Object.keys(evidence.supporting_fields).length > 0 && (
        <div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>
            Supporting Fields:
          </span>
          <div style={{ marginTop: '4px', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-xs)', overflow: 'hidden' }}>
            {Object.entries(evidence.supporting_fields).map(([k, v]) => (
              <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 8px', borderBottom: '1px solid var(--border-subtle)', fontSize: '11px' }}>
                <span className="mono-text" style={{ color: 'var(--text-muted)' }}>{k}:</span>
                <span className="mono-text" style={{ fontWeight: 600, color: 'var(--text-primary)', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ marginTop: 'auto', paddingTop: 'var(--space-3)', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: 'var(--space-2)' }}>
        <Button
          variant="outline"
          size="sm"
          icon={<Code size={13} />}
          onClick={() => setShowRawJson(!showRawJson)}
        >
          {showRawJson ? 'Hide JSON' : 'Raw JSON'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          icon={copied ? <Check size={13} style={{ color: 'var(--threat-benign)' }} /> : undefined}
          onClick={handleCopy}
        >
          {copied ? 'Copied' : 'Copy Record'}
        </Button>
      </div>

      {showRawJson && (
        <pre
          className="mono-text"
          style={{
            fontSize: '10px',
            backgroundColor: 'var(--bg-canvas)',
            padding: '8px',
            borderRadius: 'var(--radius-xs)',
            overflowX: 'auto',
            maxHeight: '160px',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {JSON.stringify(evidence, null, 2)}
        </pre>
      )}
    </aside>
  );
};
