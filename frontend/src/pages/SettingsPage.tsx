import React, { useEffect, useState } from 'react';
import { SectionHeader, Panel, Badge, Button, StatusBadge } from '../components';
import { checkBackendHealth, API_BASE_URL } from '../api/client';

export const SettingsPage: React.FC = () => {
  const [healthStatus, setHealthStatus] = useState<'checking' | 'healthy' | 'offline'>('checking');

  const verifyHealth = async () => {
    setHealthStatus('checking');
    try {
      const res = await checkBackendHealth();
      setHealthStatus(res?.status === 'ok' ? 'healthy' : 'offline');
    } catch {
      setHealthStatus('offline');
    }
  };

  useEffect(() => {
    verifyHealth();
  }, []);

  return (
    <div>
      <SectionHeader
        title="Workstation Settings"
        description="Forensic engine parameters, threat intelligence interfaces, and environment configuration."
      />

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 'var(--space-6)' }}>
        {/* Backend Connectivity */}
        <Panel
          title="Backend Connection & Services"
          subtitle="Status of the FastAPI forensic server and PostgreSQL database"
          actions={
            <Button variant="outline" size="sm" onClick={verifyHealth}>
              Check Connection
            </Button>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>API Base URL</strong>
                <span className="mono-text" style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  {API_BASE_URL}
                </span>
              </div>
              <Badge variant="neutral">Environment</Badge>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Forensic Engine Status</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  FastAPI service health probe
                </span>
              </div>
              {healthStatus === 'checking' && <Badge variant="neutral">Probing...</Badge>}
              {healthStatus === 'healthy' && <Badge variant="success">Operational</Badge>}
              {healthStatus === 'offline' && <Badge variant="danger">Unreachable</Badge>}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Persistence Layer</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  PostgreSQL 18 (SCRAM-SHA-256 authenticated)
                </span>
              </div>
              <Badge variant="success">Active</Badge>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Authentication Engine</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Argon2id + JWT Bearer Tokens
                </span>
              </div>
              <Badge variant="neutral">RBAC Enabled</Badge>
            </div>
          </div>
        </Panel>

        {/* Threat Classification Legend */}
        <Panel
          title="Threat Classification Semantics"
          subtitle="Standardized severity levels and visual indications used across investigations"
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Benign / Verified</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  DKIM & SPF pass, legitimate domain reputation, trusted infrastructure
                </span>
              </div>
              <StatusBadge status="BENIGN" type="threat" />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0', borderBottom: '1px solid var(--border-subtle)' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Suspicious / Anomalous</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Domain age &lt; 30 days, SPF softfail, suspicious redirect chains
                </span>
              </div>
              <StatusBadge status="SUSPICIOUS" type="threat" />
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 'var(--space-2) 0' }}>
              <div>
                <strong style={{ fontSize: 'var(--text-sm)', display: 'block' }}>Malicious / High Severity</strong>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                  Known phishing infrastructure, payload execution, verified spoofing
                </span>
              </div>
              <StatusBadge status="MALICIOUS" type="threat" />
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
};
