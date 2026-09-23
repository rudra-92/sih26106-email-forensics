import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowLeft,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  CheckCircle2,
  Terminal,
  Hash,
} from 'lucide-react';
import { SandeshNavbar } from '../components/SandeshNavbar/SandeshNavbar';
import { MotionButton } from '../components/MotionButton/MotionButton';
import './LandingPage/LandingPage.css';

interface EvidenceStep {
  id: string;
  stepNumber: string;
  label: string;
  category: string;
  summary: string;
  forensicArtifacts: string[];
  keyFinding: string;
}

const EVIDENCE_STEPS: EvidenceStep[] = [
  {
    id: 'email',
    stepNumber: '01',
    label: 'Email Ingestion',
    category: 'RFC-5322 Raw Message',
    summary: 'Immutable MIME extraction with SHA-256 byte-level integrity preservation.',
    forensicArtifacts: ['Message-ID', 'Boundary Tree', 'Raw MIME Streams', 'SHA-256 Hash'],
    keyFinding: 'Parsed 14 header lines · 2 body parts · 1 suspicious payload attachment',
  },
  {
    id: 'headers',
    stepNumber: '02',
    label: 'Header Traversal',
    category: 'MTA Relay Sequence',
    summary: 'Chronological hop reconstruction and timestamps across all Received: headers.',
    forensicArtifacts: ['Received: hops', 'Delay calculation', 'X-Originating-IP', 'MTA hostnames'],
    keyFinding: 'Detected 4 hops with abnormal +142s delay between hop 2 and hop 3.',
  },
  {
    id: 'auth',
    stepNumber: '03',
    label: 'Authentication',
    category: 'Cryptographic Provenance',
    summary: 'Strict cryptographic validation of SPF, DKIM signature verification, and DMARC policy alignment.',
    forensicArtifacts: ['Authentication-Results', 'DKIM-Signature', 'SPF header', 'DMARC alignment'],
    keyFinding: 'SPF softfail (IP not permitted); DKIM domain mismatch with From header.',
  },
  {
    id: 'ip',
    stepNumber: '04',
    label: 'Origin IP Isolation',
    category: 'Perimeter Identification',
    summary: 'Deterministic extraction of the authentic public sending client IP address.',
    forensicArtifacts: ['185.220.101.42', 'Reverse DNS ptr', 'Relay socket', 'Public vs Private filter'],
    keyFinding: 'Origin IP identified as 185.220.101.42 (non-RFC1918 routable endpoint).',
  },
  {
    id: 'asn',
    stepNumber: '05',
    label: 'ASN & Autonomous System',
    category: 'Routing & ISP Attribution',
    summary: 'BGP routing, autonomous system number resolution, and ISP infrastructure profiling.',
    forensicArtifacts: ['AS9009', 'M247 Europe Ltd', 'Hosting / VPN tag', 'Subnet 185.220.101.0/24'],
    keyFinding: 'Flagged as High-Risk Commercial Bulletproof/VPN hosting ASN.',
  },
  {
    id: 'geo',
    stepNumber: '06',
    label: 'Geolocation Triangulation',
    category: 'Physical Infrastructure',
    summary: 'MaxMind GeoIP2 local database triangulation of sovereign jurisdiction and coordinates.',
    forensicArtifacts: ['Frankfurt, Germany (DE)', 'Lat: 50.1109, Lon: 8.6821', 'Timezone: Europe/Berlin'],
    keyFinding: 'Sovereign host in Frankfurt; incongruent with sender claim (Seattle, WA).',
  },
  {
    id: 'evidence',
    stepNumber: '07',
    label: 'Correlated Evidence',
    category: 'Threat Attribution & IOCs',
    summary: 'Typosquatting distance, lexical NLP features, ML fusion score, and IOC graph compilation.',
    forensicArtifacts: ['acc0unt-microsoft[.]net', 'Levenshtein dist: 2', 'SHAP feature attribution'],
    keyFinding: 'Correlated to credential phishing campaign targeting enterprise identities.',
  },
];

export const HowItWorksPage: React.FC = () => {
  const navigate = useNavigate();
  const [selectedStep, setSelectedStep] = useState<EvidenceStep>(EVIDENCE_STEPS[0]);

  // Movable flowchart drag-to-scroll refs
  const trackRef = useRef<HTMLDivElement>(null);
  const isDown = useRef(false);
  const startX = useRef(0);
  const scrollLeftPos = useRef(0);
  const [isDragging, setIsDragging] = useState(false);

  const handleMouseDown = (e: React.MouseEvent) => {
    if (!trackRef.current) return;
    isDown.current = true;
    setIsDragging(true);
    startX.current = e.pageX - trackRef.current.offsetLeft;
    scrollLeftPos.current = trackRef.current.scrollLeft;
  };

  const handleMouseLeaveOrUp = () => {
    isDown.current = false;
    setIsDragging(false);
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isDown.current || !trackRef.current) return;
    e.preventDefault();
    const x = e.pageX - trackRef.current.offsetLeft;
    const walk = (x - startX.current) * 1.5;
    trackRef.current.scrollLeft = scrollLeftPos.current - walk;
  };

  const scrollFlowchart = (direction: 'left' | 'right') => {
    if (!trackRef.current) return;
    const scrollAmount = direction === 'left' ? -280 : 280;
    trackRef.current.scrollBy({ left: scrollAmount, behavior: 'smooth' });
  };

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
            <span className="sandesh-section-tag">HOW IT WORKS</span>
            <h1 className="sandesh-section-heading">
              Evidence Correlation Pipeline
            </h1>
            <p className="sandesh-section-desc">
              SandeshSetu decomposes suspicious messages across seven deterministic forensic layers,
              transforming obscure header bytes into court-ready and incident-ready evidentiary records.
            </p>
          </div>

          {/* Interactive Movable Flowchart Navigation Header */}
          <div className="sandesh-flowchart-header-bar">
            <div className="sandesh-flowchart-hint">
              <span className="sandesh-flowchart-pulse-dot" />
              <span>INTERACTIVE FORENSIC FLOWCHART • Drag or scroll to traverse sequence</span>
            </div>
            <div className="sandesh-flowchart-nav-btns">
              <button
                type="button"
                className="sandesh-flow-arrow-btn"
                onClick={() => scrollFlowchart('left')}
                aria-label="Scroll left"
              >
                <ChevronLeft size={16} />
              </button>
              <button
                type="button"
                className="sandesh-flow-arrow-btn"
                onClick={() => scrollFlowchart('right')}
                aria-label="Scroll right"
              >
                <ChevronRight size={16} />
              </button>
            </div>
          </div>

          {/* Movable Flowchart Pipeline with Moving Arrows */}
          <div
            ref={trackRef}
            className={`sandesh-flowchart-track ${isDragging ? 'is-dragging' : ''}`}
            onMouseDown={handleMouseDown}
            onMouseLeave={handleMouseLeaveOrUp}
            onMouseUp={handleMouseLeaveOrUp}
            onMouseMove={handleMouseMove}
            role="region"
            aria-label="Interactive Forensic Pipeline Flowchart"
          >
            <div className="sandesh-flowchart-inner">
              {EVIDENCE_STEPS.map((step, index) => {
                const isSelected = selectedStep.id === step.id;
                const isLast = index === EVIDENCE_STEPS.length - 1;

                return (
                  <React.Fragment key={step.id}>
                    {/* Flowchart Step Node */}
                    <button
                      type="button"
                      role="tab"
                      aria-selected={isSelected}
                      className={`sandesh-flow-node ${isSelected ? 'active' : ''}`}
                      onClick={() => setSelectedStep(step)}
                    >
                      <div className="sandesh-node-top">
                        <span className="sandesh-node-badge">STEP {step.stepNumber}</span>
                        <span className={`sandesh-node-status-dot ${isSelected ? 'active' : ''}`} />
                      </div>
                      <div className="sandesh-node-title">{step.label}</div>
                      <div className="sandesh-node-category">{step.category}</div>
                    </button>

                    {/* Moving Arrow Connector between Nodes */}
                    {!isLast && (
                      <div className="sandesh-flow-connector" aria-hidden="true">
                        <div className="sandesh-flow-line">
                          <div className="sandesh-flow-travel-pulse" />
                        </div>
                        <div className="sandesh-flow-arrowhead">
                          <ArrowRight size={15} className="sandesh-moving-arrow-icon" />
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          </div>

          {/* Step Detail Card */}
          <div className="sandesh-step-detail-card">
            <div className="sandesh-detail-header">
              <div className="sandesh-detail-title-group">
                <span className="sandesh-detail-badge">PHASE {selectedStep.stepNumber}</span>
                <h2 className="sandesh-detail-title">{selectedStep.label}</h2>
                <span className="sandesh-detail-category">{selectedStep.category}</span>
              </div>
              <div className="sandesh-detail-finding-badge">
                <CheckCircle2 size={13} strokeWidth={2.4} />
                <span>Verified Diagnostic</span>
              </div>
            </div>

            <p className="sandesh-detail-summary">{selectedStep.summary}</p>

            <div className="sandesh-detail-grid">
              <div className="sandesh-detail-col">
                <span className="sandesh-col-label">Extracted Evidence</span>
                <div className="sandesh-artifact-tags">
                  {selectedStep.forensicArtifacts.map((art, idx) => (
                    <span key={idx} className="sandesh-tag">
                      <Hash size={11} className="sandesh-tag-icon" />
                      <span>{art}</span>
                    </span>
                  ))}
                </div>
              </div>

              <div className="sandesh-detail-col">
                <span className="sandesh-col-label">Forensic Pipeline Finding</span>
                <div className="sandesh-finding-box">
                  <Terminal size={13} className="sandesh-finding-icon" />
                  <code>{selectedStep.keyFinding}</code>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Action CTA */}
          <div className="sandesh-cta-strip">
            <div className="sandesh-cta-copy">
              <h3 className="sandesh-cta-title">Ready to run this pipeline on your email cases?</h3>
              <p className="sandesh-cta-sub">
                Ingest suspicious EML or MSG files and inspect real-time multi-hop correlation.
              </p>
            </div>
            <div className="sandesh-cta-btn-wrap">
              <MotionButton
                label="Launch Investigation"
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

export default HowItWorksPage;
