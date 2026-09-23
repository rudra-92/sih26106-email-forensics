import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  AlertOctagon,
  FileCode2,
  Network,
  Layers,
  Globe2,
} from 'lucide-react';
import { SandeshNavbar } from '../components/SandeshNavbar/SandeshNavbar';
import { MotionButton } from '../components/MotionButton/MotionButton';
import './LandingPage/LandingPage.css';

export const InvestigationPage: React.FC = () => {
  const navigate = useNavigate();
  const [activePreviewTab, setActivePreviewTab] = useState<'assessment' | 'headers' | 'infrastructure' | 'correlation'>('assessment');

  return (
    <div className="sandesh-landing sandesh-page-light">
      <SandeshNavbar />

      <main className="sandesh-section sandesh-page-content">
        <div className="sandesh-container">
          <div className="sandesh-page-topbar">
            <button type="button" className="sandesh-back-btn" onClick={() => navigate('/')}>
              <ArrowLeft size={16} />
              <span>Back to Home</span>
            </button>
          </div>

          <div className="sandesh-section-header">
            <span className="sandesh-section-tag">INVESTIGATION WORKBENCH</span>
            <h1 className="sandesh-section-heading">
              Forensic Analysis & Diagnostic Station
            </h1>
            <p className="sandesh-section-desc">
              Built for security operations centers, incident response units, and law enforcement analysts
              who require transparent diagnostics, reproducible findings, and verifiable chain-of-custody.
            </p>
          </div>

          {/* Workbench Frame */}
          <div className="sandesh-workbench-frame">
            {/* Top Frame Bar */}
            <div className="sandesh-workbench-topbar">
              <div className="sandesh-window-controls">
                <span className="sandesh-dot" />
                <span className="sandesh-dot" />
                <span className="sandesh-dot" />
              </div>
              <div className="sandesh-workbench-case-info">
                <span className="sandesh-case-tag">CASE #SS-2026-0891</span>
                <span className="sandesh-case-name">Urgent_Payroll_Update_Invoice.eml</span>
                <span className="sandesh-case-sha">SHA-256: 8f4a19c...e42b01</span>
              </div>
              <div className="sandesh-workbench-status">
                <span className="sandesh-live-dot" />
                <span>ANALYSIS COMPLETE</span>
              </div>
            </div>

            {/* Sub-nav Tabs */}
            <div className="sandesh-workbench-nav">
              <button
                type="button"
                className={`sandesh-wb-tab ${activePreviewTab === 'assessment' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('assessment')}
              >
                <AlertOctagon size={14} /> Threat Assessment
              </button>
              <button
                type="button"
                className={`sandesh-wb-tab ${activePreviewTab === 'headers' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('headers')}
              >
                <FileCode2 size={14} /> Header &amp; Auth Matrix
              </button>
              <button
                type="button"
                className={`sandesh-wb-tab ${activePreviewTab === 'infrastructure' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('infrastructure')}
              >
                <Network size={14} /> Infrastructure Hops
              </button>
              <button
                type="button"
                className={`sandesh-wb-tab ${activePreviewTab === 'correlation' ? 'active' : ''}`}
                onClick={() => setActivePreviewTab('correlation')}
              >
                <Layers size={14} /> Correlated IOCs &amp; Graph
              </button>
            </div>

            {/* Tab 1: Threat Assessment */}
            {activePreviewTab === 'assessment' && (
              <div className="sandesh-wb-body">
                <div className="sandesh-threat-summary-row">
                  <div className="sandesh-threat-card sandesh-card-verdict">
                    <div className="sandesh-card-label">THREAT CLASSIFICATION</div>
                    <div className="sandesh-verdict-val">
                      <span className="sandesh-badge-malicious">HIGH RISK PHISHING</span>
                    </div>
                    <div className="sandesh-verdict-sub">
                      Confidence: <strong>94.2%</strong> (Fusion Model 3 Ensembled)
                    </div>
                  </div>

                  <div className="sandesh-threat-card sandesh-card-score">
                    <div className="sandesh-card-label">RISK SEVERITY SCORE</div>
                    <div className="sandesh-score-val">
                      <span className="sandesh-score-num">88</span>
                      <span className="sandesh-score-total">/100</span>
                    </div>
                    <div className="sandesh-score-bar-bg">
                      <div className="sandesh-score-bar-fill" style={{ width: '88%' }} />
                    </div>
                  </div>

                  <div className="sandesh-threat-card sandesh-card-origin">
                    <div className="sandesh-card-label">EXTRACTED ORIGIN CLIENT</div>
                    <div className="sandesh-origin-ip">185.220.101.42</div>
                    <div className="sandesh-origin-meta">
                      <Globe2 size={12} /> Frankfurt, Germany (DE) • AS9009
                    </div>
                  </div>
                </div>

                <div className="sandesh-threat-reasons">
                  <div className="sandesh-reasons-title">PRIMARY EVIDENTIARY SIGNALS</div>
                  <ul className="sandesh-reasons-list">
                    <li>
                      <span className="sandesh-reason-bullet crit">CRIT</span>
                      <span>Typosquatted domain <code>acc0unt-microsoft[.]net</code> mimicks legitimate identity provider.</span>
                    </li>
                    <li>
                      <span className="sandesh-reason-bullet crit">CRIT</span>
                      <span>SPF Softfail and DKIM domain mismatch with From header claim.</span>
                    </li>
                    <li>
                      <span className="sandesh-reason-bullet high">HIGH</span>
                      <span>Origin relay mapped to known commercial bulletproof hosting infrastructure.</span>
                    </li>
                  </ul>
                </div>
              </div>
            )}

            {/* Tab 2: Header Matrix */}
            {activePreviewTab === 'headers' && (
              <div className="sandesh-wb-body">
                <div className="sandesh-matrix-table-wrap">
                  <table className="sandesh-matrix-table">
                    <thead>
                      <tr>
                        <th>PROTOCOL / CHECK</th>
                        <th>CLAIMED SENDER</th>
                        <th>EVIDENTIARY RESULT</th>
                        <th>CHAIN STATUS</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><code>SPF</code> (RFC 7208)</td>
                        <td>microsoft.com</td>
                        <td>softfail (185.220.101.42 not designated)</td>
                        <td><span className="sandesh-pill-fail">MISMATCH</span></td>
                      </tr>
                      <tr>
                        <td><code>DKIM</code> (RFC 6376)</td>
                        <td>d=acc0unt-microsoft.net</td>
                        <td>signature pass (domain mismatch with From)</td>
                        <td><span className="sandesh-pill-warn">SUSPICIOUS</span></td>
                      </tr>
                      <tr>
                        <td><code>DMARC</code> (RFC 7489)</td>
                        <td>microsoft.com</td>
                        <td>reject (alignment failed for SPF/DKIM)</td>
                        <td><span className="sandesh-pill-fail">REJECT</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Tab 3: Infrastructure */}
            {activePreviewTab === 'infrastructure' && (
              <div className="sandesh-wb-body">
                <div className="sandesh-hops-tree">
                  <div className="sandesh-hop-item">
                    <span className="sandesh-hop-idx">01</span>
                    <div className="sandesh-hop-info">
                      <div className="sandesh-hop-title">Origin Sending Agent (Client MUA)</div>
                      <div className="sandesh-hop-sub">185.220.101.42 • AS9009 (Frankfurt, DE) • Tor / Proxy Node</div>
                    </div>
                  </div>
                  <div className="sandesh-hop-item">
                    <span className="sandesh-hop-idx">02</span>
                    <div className="sandesh-hop-info">
                      <div className="sandesh-hop-title">Relay MTA (mail.secure-relay-outbound.net)</div>
                      <div className="sandesh-hop-sub">91.198.174.192 • Transit Delay: +142s (Anomalous Spooling)</div>
                    </div>
                  </div>
                  <div className="sandesh-hop-item">
                    <span className="sandesh-hop-idx">03</span>
                    <div className="sandesh-hop-info">
                      <div className="sandesh-hop-title">Recipient Gateway (mx1.victim-organization.com)</div>
                      <div className="sandesh-hop-sub">198.51.100.12 • Ingestion Timestamp: 2026-09-23 18:42:01 UTC</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 4: Correlation */}
            {activePreviewTab === 'correlation' && (
              <div className="sandesh-wb-body">
                <div className="sandesh-correlation-summary">
                  <div className="sandesh-ioc-box">
                    <span className="sandesh-ioc-label">EXTRACTED IOCS</span>
                    <div className="sandesh-ioc-list">
                      <span className="sandesh-tag">185.220.101.42</span>
                      <span className="sandesh-tag">acc0unt-microsoft[.]net</span>
                      <span className="sandesh-tag">SHA-256: 8f4a...e42b</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Bottom Action CTA */}
          <div className="sandesh-cta-strip">
            <div className="sandesh-cta-copy">
              <h3 className="sandesh-cta-title">Start analyzing your live casework</h3>
              <p className="sandesh-cta-sub">
                Open cases, upload raw RFC-5322 eml files, and export court-ready evidence bundles.
              </p>
            </div>
            <div className="sandesh-cta-btn-wrap">
              <MotionButton
                label="Launch Case Workstation"
                variant="primary"
                animate={true}
                onClick={() => navigate('/cases')}
              />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default InvestigationPage;
