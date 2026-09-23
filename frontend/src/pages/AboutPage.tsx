import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  Hash,
  Network,
  Search,
  Globe2,
} from 'lucide-react';
import { SandeshNavbar } from '../components/SandeshNavbar/SandeshNavbar';
import { SandeshSetuLogo } from '../components/brand/SandeshSetuLogo';
import { MotionButton } from '../components/MotionButton/MotionButton';
import './LandingPage/LandingPage.css';

export const AboutPage: React.FC = () => {
  const navigate = useNavigate();

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
            <span className="sandesh-section-tag">ENGINEERING PRINCIPLES</span>
            <h1 className="sandesh-section-heading">
              Forensic Integrity by Design
            </h1>
            <p className="sandesh-section-desc">
              Built on sound cybersecurity principles to provide investigators with non-repudiable,
              tamper-evident results that stand up to institutional and forensic review.
            </p>
          </div>

          <div className="sandesh-pillars-grid">
            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Hash size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Deterministic Evidence Extraction</h3>
              <p className="sandesh-pillar-text">
                Every parsed RFC-5322 header, MIME part, and authentication token is preserved with byte-level
                cryptographic hashing to guarantee strict chain-of-custody compliance.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Network size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Multi-Hop Infrastructure Tracing</h3>
              <p className="sandesh-pillar-text">
                Traverses all MTA Received headers in reverse-relay order, unmasking spoofed proxies,
                calculating transit jitter, and resolving underlying ASNs and jurisdictions.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Search size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Explainable Machine Intelligence</h3>
              <p className="sandesh-pillar-text">
                No opaque black-box verdicts. Machine learning classifications provide local feature attribution
                via SHAP values, explaining exactly why an email was classified as malicious.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Globe2 size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Offline-First Operational Security</h3>
              <p className="sandesh-pillar-text">
                Core analysis pipelines operate without leaking sensitive evidentiary emails to external
                third-party cloud endpoints, utilizing local threat rules and offline MMDB lookups.
              </p>
            </div>
          </div>

          {/* Brand Geometry Section */}
          <div className="sandesh-logo-section" style={{ marginTop: '54px' }}>
            <div className="sandesh-section-header">
              <span className="sandesh-section-tag">BRAND IDENTITY &amp; GEOMETRIC SYSTEM</span>
              <h2 className="sandesh-section-heading">
                The Making of the SandeshSetu Emblem
              </h2>
              <p className="sandesh-section-desc">
                Every curve, vector coordinate, and vertex in the emblem is mathematically structured
                to represent the three foundational tenets of forensic email attribution.
              </p>
            </div>

            <div className="sandesh-logo-showcase-grid">
              {/* Left: Vector Blueprint Diagram */}
              <div className="sandesh-blueprint-card">
                <div className="sandesh-blueprint-header">
                  <div className="sandesh-blueprint-meta">
                    <span className="sandesh-meta-badge">VECTOR BLUEPRINT</span>
                    <span className="sandesh-meta-coord">GRID: 100 × 100 px • ISO 27037 GEOMETRY</span>
                  </div>
                  <div className="sandesh-blueprint-tools">
                    <span className="sandesh-bp-dot" />
                    <span>POLAR COORD v2.4</span>
                  </div>
                </div>

                <div className="sandesh-blueprint-canvas-wrap">
                  <SandeshSetuLogo variant="blueprint" size={260} />
                </div>
              </div>

              {/* Right: Architectural Tenets */}
              <div className="sandesh-anatomy-details">
                <div className="sandesh-anatomy-card">
                  <div className="sandesh-anatomy-num">01</div>
                  <div className="sandesh-anatomy-content">
                    <h3 className="sandesh-anatomy-title">
                      <span className="sandesh-devanagari">संदेश</span> — Sandesh (The Message)
                    </h3>
                    <p className="sandesh-anatomy-desc">
                      The central nested envelope node represents raw RFC-5322 MIME message streams.
                      It preserves cryptographic integrity from point-of-origin through ingestion.
                    </p>
                  </div>
                </div>

                <div className="sandesh-anatomy-card">
                  <div className="sandesh-anatomy-num">02</div>
                  <div className="sandesh-anatomy-content">
                    <h3 className="sandesh-anatomy-title">
                      <span className="sandesh-devanagari">सेतु</span> — Setu (The Bridge)
                    </h3>
                    <p className="sandesh-anatomy-desc">
                      The dashed horizontal relay arc and interconnected telemetry vertices represent the multi-hop transmission bridge
                      across autonomous system BGP routes and intermediary MTA relays.
                    </p>
                  </div>
                </div>

                <div className="sandesh-anatomy-card">
                  <div className="sandesh-anatomy-num">03</div>
                  <div className="sandesh-anatomy-content">
                    <h3 className="sandesh-anatomy-title">
                      The Forensic Shield &amp; Anchor Vertex
                    </h3>
                    <p className="sandesh-anatomy-desc">
                      The outer sovereign shield boundary provides perimeter defense, anchoring into a single verification node representing
                      non-repudiable SHA-256 chain-of-custody proofs.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Action CTA Strip */}
          <div className="sandesh-cta-strip">
            <div className="sandesh-cta-copy">
              <h3 className="sandesh-cta-title">Ready to analyze suspicious email evidence?</h3>
              <p className="sandesh-cta-sub">
                Launch the SandeshSetu forensic workstation and start parsing live cases now.
              </p>
            </div>
            <div className="sandesh-cta-btn-wrap">
              <MotionButton
                label="Launch Workstation"
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

export default AboutPage;
