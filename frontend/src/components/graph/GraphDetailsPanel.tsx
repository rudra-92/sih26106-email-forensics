import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  ArrowRight,
  ShieldCheck,
  Database,
  Layers,
  FileText,
  Percent,
  Tag,
  AlertTriangle,
} from 'lucide-react';
import type { SelectedElement } from './graphTypes';

interface GraphDetailsPanelProps {
  selected: SelectedElement;
  onClose: () => void;
  onSelectEntityId?: (entityId: string) => void;
}

export const GraphDetailsPanel: React.FC<GraphDetailsPanelProps> = ({
  selected,
  onClose,
  onSelectEntityId,
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  if (!selected) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => {
      setCopiedKey(null);
    }, 1800);
  };

  const isResembles =
    selected.type === 'edge' && selected.data.relationship_type.toLowerCase() === 'resembles';

  return (
    <aside className="graph-details-panel" aria-label="Forensic Investigation Details">
      <div className="graph-details-header">
        <div className="graph-details-title-group">
          <span
            className={`graph-details-badge ${
              isResembles ? 'badge-resembles' : selected.type === 'node' ? 'badge-node' : 'badge-edge'
            }`}
          >
            {selected.type === 'node'
              ? selected.data.entity_type.toUpperCase()
              : isResembles
              ? 'LOOKALIKE RELATIONSHIP'
              : 'FORENSIC RELATIONSHIP'}
          </span>
          <h3 className="graph-details-title mono-text">
            {selected.type === 'node' ? selected.data.canonical_value : selected.data.relationship_type}
          </h3>
        </div>
        <button
          type="button"
          className="graph-details-close-btn"
          onClick={onClose}
          title="Close details panel"
          aria-label="Close"
        >
          <X size={15} />
        </button>
      </div>

      <div className="graph-details-content">
        {selected.type === 'node' ? (
          <>
            {/* Canonical Value Section */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">Canonical Value</div>
              <div className="graph-details-copyable-box">
                <span className="mono-text">{selected.data.canonical_value}</span>
                <button
                  type="button"
                  className="graph-copy-btn"
                  onClick={() => handleCopy(selected.data.canonical_value, 'val')}
                  title="Copy canonical value"
                >
                  {copiedKey === 'val' ? <Check size={12} className="copy-success" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Entity Identifier */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">Entity Identifier</div>
              <div className="graph-details-copyable-box">
                <span className="mono-text" style={{ fontSize: '11px' }}>
                  {selected.data.entity_id}
                </span>
                <button
                  type="button"
                  className="graph-copy-btn"
                  onClick={() => handleCopy(selected.data.entity_id, 'id')}
                  title="Copy entity ID"
                >
                  {copiedKey === 'id' ? <Check size={12} className="copy-success" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Source Modules */}
            {selected.data.source_modules && selected.data.source_modules.length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Emitting Modules</div>
                <div className="graph-tag-list">
                  {selected.data.source_modules.map((mod) => (
                    <span key={mod} className="graph-tag">
                      <Database size={10} style={{ marginRight: '3px' }} />
                      {mod}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* First Observed Timestamp */}
            {selected.data.first_observed_timestamp && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">First Observed</div>
                <div className="mono-text" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {selected.data.first_observed_timestamp}
                </div>
              </div>
            )}

            {/* Forensic Attributes */}
            {selected.data.attributes && Object.keys(selected.data.attributes).length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Forensic Attributes</div>
                <div className="graph-attributes-table">
                  {Object.entries(selected.data.attributes).map(([k, v]) => (
                    <div key={k} className="graph-attribute-row">
                      <span className="graph-attr-key">{k}:</span>
                      <span className="graph-attr-val mono-text">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Connected Relationships */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">
                Connected Trail ({selected.outgoing.length + selected.incoming.length})
              </div>

              {selected.outgoing.length > 0 && (
                <div style={{ marginBottom: 'var(--space-2)' }}>
                  <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '4px' }}>
                    OUTGOING RELATIONSHIPS
                  </div>
                  {selected.outgoing.map((rel) => (
                    <div key={rel.relationship_id} className="graph-conn-row">
                      <span className="graph-conn-type mono-text">{rel.relationship_type}</span>
                      <ArrowRight size={10} style={{ color: 'var(--text-muted)' }} />
                      <button
                        type="button"
                        className="graph-conn-target mono-text"
                        onClick={() => onSelectEntityId?.(rel.target_entity_id)}
                        title={`Select ${rel.target_entity_id}`}
                      >
                        {rel.target_entity_id}
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {selected.incoming.length > 0 && (
                <div>
                  <div style={{ fontSize: '9px', color: 'var(--text-muted)', fontWeight: 700, marginBottom: '4px' }}>
                    INCOMING RELATIONSHIPS
                  </div>
                  {selected.incoming.map((rel) => (
                    <div key={rel.relationship_id} className="graph-conn-row">
                      <button
                        type="button"
                        className="graph-conn-target mono-text"
                        onClick={() => onSelectEntityId?.(rel.source_entity_id)}
                        title={`Select ${rel.source_entity_id}`}
                      >
                        {rel.source_entity_id}
                      </button>
                      <ArrowRight size={10} style={{ color: 'var(--text-muted)' }} />
                      <span className="graph-conn-type mono-text">{rel.relationship_type}</span>
                    </div>
                  ))}
                </div>
              )}

              {selected.outgoing.length === 0 && selected.incoming.length === 0 && (
                <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                  No relationships connected to this entity.
                </div>
              )}
            </div>
          </>
        ) : (
          <>
            {/* Relationship Overview */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">Relationship Type</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexWrap: 'wrap' }}>
                <span
                  className="mono-text"
                  style={{
                    fontSize: '13px',
                    fontWeight: 700,
                    color: isResembles ? '#D97706' : 'var(--text-primary)',
                  }}
                >
                  {selected.data.relationship_type}
                </span>
                <span className="graph-tag tag-trust">
                  <ShieldCheck size={10} style={{ marginRight: '3px' }} />
                  {selected.data.trust_state || 'observed'}
                </span>
              </div>
            </div>

            {/* Lookalike Alert Banner if resembles */}
            {isResembles && (
              <div className="graph-lookalike-alert">
                <AlertTriangle size={14} className="lookalike-alert-icon" />
                <div className="lookalike-alert-text">
                  <strong>Domain Impersonation Candidate</strong>
                  <p>
                    Algorithmic candidate resemblance corroborating brand deception between source and target reference domain.
                  </p>
                </div>
              </div>
            )}

            {/* Source Entity */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">Source Entity (Origin)</div>
              <div className="graph-details-copyable-box">
                <span className="mono-text" style={{ fontSize: '11px' }}>
                  {selected.data.source_entity_id}
                </span>
                <button
                  type="button"
                  className="graph-copy-btn"
                  onClick={() => handleCopy(selected.data.source_entity_id, 'src')}
                  title="Copy source entity ID"
                >
                  {copiedKey === 'src' ? <Check size={12} className="copy-success" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Target Entity */}
            <div className="graph-details-section">
              <div className="graph-details-field-label">Target Entity (Destination)</div>
              <div className="graph-details-copyable-box">
                <span className="mono-text" style={{ fontSize: '11px' }}>
                  {selected.data.target_entity_id}
                </span>
                <button
                  type="button"
                  className="graph-copy-btn"
                  onClick={() => handleCopy(selected.data.target_entity_id, 'tgt')}
                  title="Copy target entity ID"
                >
                  {copiedKey === 'tgt' ? <Check size={12} className="copy-success" /> : <Copy size={12} />}
                </button>
              </div>
            </div>

            {/* Rich Lookalike / Corroborating Forensic Metrics */}
            {selected.relatedEvidence && selected.relatedEvidence.length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Forensic Metrics & Evidence Details</div>
                {selected.relatedEvidence.map((ev) => {
                  const sf = ev.supporting_fields || {};
                  const simScore = sf.similarity_score ?? sf.candidate_score;
                  const claimedBrand = sf.claimed_brand;
                  const observedToken = sf.observed_token;
                  const targetBrand = sf.reference_brand || sf.target_brand;

                  return (
                    <div key={ev.evidence_id} className="graph-evidence-card">
                      <div className="graph-evidence-card-header">
                        <span className="mono-text graph-evidence-id">{ev.evidence_id}</span>
                        <span className="graph-evidence-rule">{ev.rule_id}</span>
                      </div>

                      {/* Prominent Lookalike Metrics */}
                      {Boolean(simScore != null || claimedBrand || observedToken) && (
                        <div className="graph-metrics-grid">
                          {simScore != null && (
                            <div className="graph-metric-cell">
                              <span className="graph-metric-label">SIMILARITY</span>
                              <span className="graph-metric-value mono-text highlight-metric">
                                <Percent size={11} style={{ marginRight: '2px' }} />
                                {typeof simScore === 'number' ? simScore.toFixed(4) : String(simScore)}
                              </span>
                            </div>
                          )}

                          {Boolean(claimedBrand) && (
                            <div className="graph-metric-cell">
                              <span className="graph-metric-label">CLAIMED BRAND</span>
                              <span className="graph-metric-value mono-text">
                                <Tag size={11} style={{ marginRight: '2px' }} />
                                {String(claimedBrand)}
                              </span>
                            </div>
                          )}

                          {Boolean(observedToken) && (
                            <div className="graph-metric-cell">
                              <span className="graph-metric-label">OBSERVED TOKEN</span>
                              <span className="graph-metric-value mono-text">
                                {String(observedToken)}
                              </span>
                            </div>
                          )}

                          {Boolean(targetBrand) && (
                            <div className="graph-metric-cell">
                              <span className="graph-metric-label">TARGET BRAND</span>
                              <span className="graph-metric-value mono-text">
                                {String(targetBrand)}
                              </span>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Description */}
                      <p className="graph-evidence-desc">{ev.description}</p>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Evidence IDs */}
            {selected.data.evidence_ids && selected.data.evidence_ids.length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">
                  Corroborating Evidence IDs ({selected.data.evidence_ids.length})
                </div>
                <div className="graph-tag-list">
                  {selected.data.evidence_ids.map((evId) => (
                    <span key={evId} className="graph-tag mono-text" style={{ fontSize: '10px' }}>
                      <FileText size={10} style={{ marginRight: '3px' }} />
                      {evId}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Source Modules */}
            {selected.data.source_modules && selected.data.source_modules.length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Emitting Modules</div>
                <div className="graph-tag-list">
                  {selected.data.source_modules.map((mod) => (
                    <span key={mod} className="graph-tag">
                      <Layers size={10} style={{ marginRight: '3px' }} />
                      {mod}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Provenance Trail */}
            {selected.data.provenance && selected.data.provenance.length > 0 && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Provenance Trail</div>
                <div className="graph-tag-list">
                  {selected.data.provenance.map((prov, i) => (
                    <span key={i} className="graph-tag mono-text" style={{ fontSize: '10px' }}>
                      {prov}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Timestamp */}
            {selected.data.timestamp && (
              <div className="graph-details-section">
                <div className="graph-details-field-label">Recorded Timestamp</div>
                <div className="mono-text" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {selected.data.timestamp}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </aside>
  );
};
