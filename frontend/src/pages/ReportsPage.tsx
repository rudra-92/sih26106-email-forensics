import React from 'react';
import { FileText, ShieldCheck, ArrowRight } from 'lucide-react';
import { SectionHeader, Button, EmptyState, Panel } from '../components';
import { useNavigate } from 'react-router-dom';

export const ReportsPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div>
      <SectionHeader
        title="Forensic Reports"
        description="Cryptographic case summaries, chain-of-custody verification documents, and audit logs."
      />

      <Panel
        title="Evidence Preservation Standard"
        subtitle="Forensic evidentiary standards adhered to during report generation"
        style={{ marginBottom: 'var(--space-6)' }}
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <ShieldCheck size={20} style={{ color: 'var(--action-primary)', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>SHA-256 Digest Immutability</strong>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 'var(--space-1) 0 0 0' }}>
                Every raw .eml evidence payload is digested upon ingress. Digests are preserved to prevent tampering.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <FileText size={20} style={{ color: 'var(--action-primary)', flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Structured Case Output</strong>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 'var(--space-1) 0 0 0' }}>
                Deterministic reports detail extracted hops, SPF/DKIM authentication headers, threat correlations, and attribution scores.
              </p>
            </div>
          </div>
        </div>
      </Panel>

      <EmptyState
        icon={<FileText size={24} />}
        title="No forensic reports generated yet"
        description="Case reports will appear here once forensic pipeline runs have concluded on ingested evidence."
        action={
          <Button
            variant="primary"
            size="sm"
            icon={<ArrowRight size={14} />}
            onClick={() => navigate('/cases')}
          >
            Browse Cases
          </Button>
        }
      />
    </div>
  );
};
