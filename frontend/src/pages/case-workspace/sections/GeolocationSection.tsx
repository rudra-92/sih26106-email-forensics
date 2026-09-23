import React, { useEffect, useState } from 'react';
import { Server, Info } from 'lucide-react';
import { Panel, Badge, LoadingState, EmptyState } from '../../../components';
import { fetchCaseOrigin } from '../../../api/cases';
import type { OriginData } from '../../../types';
import { useCaseWorkspace } from '../CaseWorkspaceContext';
import { ForensicGeoMap } from '../../../components/map';

export const GeolocationSection: React.FC = () => {
  const { caseId, caseData } = useCaseWorkspace();

  const [originData, setOriginData] = useState<OriginData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    let isMounted = true;
    async function loadOrigin() {
      if (caseData.analysis_status !== 'completed') {
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      try {
        const res = await fetchCaseOrigin(caseId);
        if (isMounted) {
          setOriginData(res);
        }
      } catch {
        if (isMounted) setOriginData(null);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadOrigin();
    return () => {
      isMounted = false;
    };
  }, [caseId, caseData.analysis_status]);

  if (caseData.analysis_status !== 'completed') {
    return (
      <Panel title="Origin Infrastructure" subtitle="Observed infrastructure geolocation and route visualization will appear here.">
        <EmptyState
          title="Analysis Not Run"
          description="Origin infrastructure and hop trajectory will be reconstructed after pipeline execution."
        />
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Loading origin and network infrastructure data..." />;
  }

  const hasPeer = Boolean(originData?.earliest_reliable_peer && originData.earliest_reliable_peer !== '—');
  const peerIp = hasPeer ? originData!.earliest_reliable_peer! : '—';
  const visibility = originData?.source_visibility || (hasPeer ? '—' : 'insufficient_evidence');
  const semanticNote =
    originData?.semantic_note ||
    'Observed infrastructure geolocation represents routing Point-of-Presence (PoP), NOT human physical attacker location.';

  const asnInfo = originData?.asn || {};
  const geoInfo = originData?.geolocation || {};

  const isDocNet =
    hasPeer &&
    (peerIp === '198.51.100.99' ||
      peerIp.startsWith('198.51.100.') ||
      peerIp.startsWith('192.0.2.') ||
      peerIp.startsWith('203.0.113.') ||
      peerIp.toLowerCase().startsWith('2001:db8:') ||
      Boolean(originData?.infrastructure?.is_documentation_ip) ||
      String(originData?.infrastructure?.infrastructure_classification) === 'documentation_test_net');

  // Peer classification
  let peerClassification = 'Unavailable';
  if (hasPeer) {
    if (isDocNet) {
      peerClassification = 'Synthetic/Documentation Test Relay (RFC 5737)';
    } else if (originData?.confidence != null && originData.confidence > 0) {
      peerClassification = `Confidence ${(originData.confidence * 100).toFixed(0)}%`;
    } else {
      peerClassification = 'Unavailable';
    }
  }

  // ASN / Operator
  let asnDisplay = 'Unavailable';
  if (hasPeer) {
    if (isDocNet) {
      asnDisplay = 'Documentation/Test Network (RFC 5737)';
    } else {
      const rawAsn = asnInfo.asn || asnInfo.autonomous_system_number;
      const rawOrg = asnInfo.organization || asnInfo.autonomous_system_organization;
      const isUnavailable = asnInfo.status === 'unavailable' || (!rawAsn && !rawOrg);
      if (!isUnavailable) {
        if (rawAsn && rawOrg) {
          asnDisplay = `${rawAsn} (${rawOrg})`;
        } else {
          asnDisplay = String(rawAsn || rawOrg);
        }
      }
    }
  }

  // Routing PoP Geolocation
  let geoDisplay = 'Unavailable';
  if (hasPeer) {
    if (isDocNet) {
      geoDisplay = 'Documentation/Test Network (RFC 5737)';
    } else {
      const isUnavailable = geoInfo.status === 'unavailable' || (!geoInfo.country && !geoInfo.country_code && !geoInfo.city);
      if (!isUnavailable) {
        const parts = [geoInfo.city, geoInfo.region, geoInfo.country].filter(Boolean);
        geoDisplay = parts.length > 0 ? parts.join(', ') : String(geoInfo.country_code || 'Recorded');
      }
    }
  }

  // Assessment Rationale
  let rationale = originData?.assessment_reason || '—';
  if (!hasPeer) {
    if (
      !originData?.assessment_reason ||
      originData.assessment_reason === 'No transmission hops available to analyze.' ||
      !originData?.hops?.length ||
      originData.assessment_reason === '—'
    ) {
      rationale = 'No Received headers containing a routable sending peer were present in the submitted .eml.';
    }
  }

  return (
    <div className="case-workspace-body">
      <Panel
        title="Observed Infrastructure Geolocation"
        subtitle="Geospatial Point-of-Presence (PoP) routing reconstructed from observed transmission hops."
      >
        {/* Two-Column Layout */}
        <div className="geo-two-column-grid">
          {/* Left Column: Interactive MapLibre Geospatial Viewport */}
          <div style={{ minHeight: '480px', display: 'flex', flexDirection: 'column' }}>
            <ForensicGeoMap
              originData={originData}
              caseId={caseId}
              isDocNet={isDocNet}
              hasPeer={hasPeer}
            />
          </div>

          {/* Right Column: Selected Infrastructure Technical Details */}
          <div className="geo-details-panel">
            <div style={{ backgroundColor: 'var(--bg-canvas)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: 'var(--space-3)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: 'var(--space-2)' }}>
                <Server size={14} style={{ color: 'var(--action-primary)' }} />
                <strong style={{ fontSize: 'var(--text-xs)', color: 'var(--text-primary)' }}>
                  Reconstructed Origin Observations
                </strong>
              </div>

              <div className="analysis-key-val-list">
                <div className="analysis-key-val-row">
                  <span className="analysis-key-val-label">Earliest Reliable Peer:</span>
                  <span className="analysis-key-val-value mono-text">
                    {peerIp}
                    {hasPeer && isDocNet && (
                      <span style={{ marginLeft: '6px' }}>
                        <Badge variant="warning">Documentation/Test Network</Badge>
                      </span>
                    )}
                  </span>
                </div>

                <div className="analysis-key-val-row">
                  <span className="analysis-key-val-label">Source Visibility:</span>
                  <span className="analysis-key-val-value mono-text">{visibility}</span>
                </div>

                <div className="analysis-key-val-row">
                  <span className="analysis-key-val-label">Peer Classification:</span>
                  <span className="analysis-key-val-value" style={{ fontSize: '11px' }}>
                    {peerClassification}
                  </span>
                </div>

                <div className="analysis-key-val-row">
                  <span className="analysis-key-val-label">ASN / Operator:</span>
                  <span className="analysis-key-val-value mono-text" style={{ fontSize: '11px' }}>
                    {asnDisplay}
                  </span>
                </div>

                <div className="analysis-key-val-row">
                  <span className="analysis-key-val-label">Routing PoP Geolocation:</span>
                  <span className="analysis-key-val-value" style={{ fontSize: '11px' }}>
                    {geoDisplay}
                  </span>
                </div>
              </div>

              {rationale !== '—' && (
                <div style={{ marginTop: 'var(--space-2)', fontSize: '11px', color: 'var(--text-secondary)' }}>
                  <span style={{ fontWeight: 600, color: 'var(--text-muted)' }}>Assessment Rationale: </span>
                  {rationale}
                </div>
              )}
            </div>

            {/* Crucial Forensic Semantic Note Banner */}
            <div className="semantic-note-banner">
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
                <Info size={14} style={{ color: 'var(--action-primary)', flexShrink: 0, marginTop: '2px' }} />
                <span>
                  <strong>Forensic Integrity Note:</strong> {semanticNote}
                </span>
              </div>
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
};
