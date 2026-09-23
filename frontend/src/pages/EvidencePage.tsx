import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ShieldCheck,
  Hash,
  Database,
  Lock,
} from 'lucide-react';
import { SandeshNavbar } from '../components/SandeshNavbar/SandeshNavbar';
import { MotionButton } from '../components/MotionButton/MotionButton';
import './LandingPage/LandingPage.css';

export const EvidencePage: React.FC = () => {
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
            <span className="sandesh-section-tag">EVIDENTIARY INTEGRITY</span>
            <h1 className="sandesh-section-heading">
              Evidence Extraction &amp; Chain of Custody
            </h1>
            <p className="sandesh-section-desc">
              Deterministic, tamper-evident forensic preservation built to adhere strictly to
              NIST SP 800-86 and ISO/IEC 27037 digital evidence standards.
            </p>
          </div>

          <div className="sandesh-pillars-grid">
            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Hash size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Byte-Level SHA-256 Immutability</h3>
              <p className="sandesh-pillar-text">
                Every parsed RFC-5322 raw message stream is cryptographically locked with a SHA-256 hash at ingestion,
                ensuring complete tamper detection and non-repudiation.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <ShieldCheck size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Cryptographic Header Provenance</h3>
              <p className="sandesh-pillar-text">
                Rigorous cryptographic validation of DKIM RSA/Ed25519 signatures, SPF sender IP policy resolution,
                and DMARC organizational domain alignment.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Database size={20} />
              </div>
              <h3 className="sandesh-pillar-title">ISO 27037 Custody Artifacts</h3>
              <p className="sandesh-pillar-text">
                Structured forensic reporting outputting deterministic JSON diagnostic bundles,
                SHA-256 custody receipts, and reproducible hop timelines.
              </p>
            </div>

            <div className="sandesh-pillar-card">
              <div className="sandesh-pillar-icon">
                <Lock size={20} />
              </div>
              <h3 className="sandesh-pillar-title">Offline Threat Extraction</h3>
              <p className="sandesh-pillar-text">
                Air-gapped operation with local ASN, MaxMind GeoIP2 MMDB databases, and offline ML inference.
                Zero evidentiary data leaks to external third-party cloud endpoints.
              </p>
            </div>
          </div>

          {/* Bottom Action CTA */}
          <div className="sandesh-cta-strip">
            <div className="sandesh-cta-copy">
              <h3 className="sandesh-cta-title">Verify digital evidence with SandeshSetu</h3>
              <p className="sandesh-cta-sub">
                Ingest case records, inspect extracted tokens, and generate court-ready diagnostic summaries.
              </p>
            </div>
            <div className="sandesh-cta-btn-wrap">
              <MotionButton
                label="Open Investigation Workstation"
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

export default EvidencePage;
