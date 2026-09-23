import React from 'react';
import { Search, ArrowRight } from 'lucide-react';
import { SectionHeader, Button, EmptyState, Panel, Badge } from '../components';
import { useNavigate } from 'react-router-dom';

export const InvestigationsPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div>
      <SectionHeader
        title="Forensic Investigations"
        description="Deep forensic analysis pipeline, entity correlation, origin infrastructure attribution, and hypothesis evaluation."
      />

      <Panel
        title="Forensic Pipeline Architecture"
        subtitle="Modular analysis sequence executed across forensic cases"
        style={{ marginBottom: 'var(--space-6)' }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
            gap: 'var(--space-4)',
            marginTop: 'var(--space-2)',
          }}
        >
          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 01</span>
              <Badge variant="neutral">Deterministic</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Header & Hop Extraction</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              RFC 5322 parsing, Received chain chronological ordering, and SPF/DKIM/DMARC auth validation.
            </p>
          </div>

          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 02</span>
              <Badge variant="neutral">Deterministic</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Content & Artifact Analysis</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              Body text tokenization, URL redirection unwinding, attachment MIME typing, and SHA-256 hashing.
            </p>
          </div>

          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 03</span>
              <Badge variant="info">Intelligence</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Threat Intelligence</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              IP geolocation, ASN infrastructure mapping, domain age verification, and reputation scoring.
            </p>
          </div>

          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 04</span>
              <Badge variant="neutral">Graph Theory</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Entity Correlation</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              Multi-source entity linking, relationship graphing, and shared infrastructure identification.
            </p>
          </div>

          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 05</span>
              <Badge variant="warning">Probabilistic</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Hypothesis Engine</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              Competing hypothesis evaluation for spoofing, account takeover, or credential harvesting.
            </p>
          </div>

          <div
            style={{
              padding: 'var(--space-3)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--bg-canvas)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
              <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>MODULE 06</span>
              <Badge variant="accent">Auditing</Badge>
            </div>
            <strong style={{ fontSize: 'var(--text-sm)', display: 'block', marginBottom: 'var(--space-1)' }}>Forensic Compilation</strong>
            <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
              Cryptographic chain of custody compilation with timestamped forensic audit trail.
            </p>
          </div>
        </div>
      </Panel>

      <EmptyState
        icon={<Search size={24} />}
        title="No active investigation selected"
        description="Select an existing case from the repository or upload a new .eml artifact to initiate deep investigation."
        action={
          <Button
            variant="primary"
            size="sm"
            icon={<ArrowRight size={14} />}
            onClick={() => navigate('/cases')}
          >
            Go to Case Registry
          </Button>
        }
      />
    </div>
  );
};
