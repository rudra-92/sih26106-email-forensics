import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowRight, ShieldCheck, CheckCircle2, Lock } from 'lucide-react';
import { SandeshNavbar } from '../../components/SandeshNavbar/SandeshNavbar';
import { ForensicGlobe } from '../../components/ForensicGlobe/ForensicGlobe';
import { SandeshSetuLogo } from '../../components/brand/SandeshSetuLogo';
import './LandingPage.css';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  // Typing motion for the main headline
  const fullHeadline = 'Turn suspicious emails into clear, traceable evidence.';
  const [typedHeadline, setTypedHeadline] = useState('');
  const [isTypingComplete, setIsTypingComplete] = useState(false);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setTypedHeadline(fullHeadline);
      setIsTypingComplete(true);
      return;
    }

    let currentIndex = 0;
    const startDelay = setTimeout(() => {
      const interval = setInterval(() => {
        currentIndex++;
        setTypedHeadline(fullHeadline.slice(0, currentIndex));
        if (currentIndex >= fullHeadline.length) {
          clearInterval(interval);
          setIsTypingComplete(true);
        }
      }, 42); // Smooth typing cadence

      return () => clearInterval(interval);
    }, 280);

    return () => clearTimeout(startDelay);
  }, []);

  const handleStartInvestigation = () => {
    navigate('/login');
  };

  const handleSeeHowItWorks = () => {
    navigate('/how-it-works');
  };

  return (
    <div className="sandesh-landing-view">
      {/* 1. TOP NAVIGATION BAR */}
      <SandeshNavbar />

      {/* 2. ASYMMETRIC FORENSIC HERO SECTION */}
      <main className="sandesh-hero-stage" id="hero">
        <div className="sandesh-hero-container">
          {/* Left Column: Core Investigation Headline & Action Suite */}
          <div className="sandesh-hero-primary-col">
            
            {/* 1. SandeshSetu Brand Heading with small integrated shield/mail mark */}
            <div className="sandesh-hero-brand-block">
              <div className="sandesh-hero-brand-heading">
                <div className="sandesh-hero-brand-mark">
                  <SandeshSetuLogo variant="icon" size={22} theme="dark" />
                </div>
                <span className="sandesh-hero-brand-name">SandeshSetu</span>
              </div>
              
              {/* 2. Small Eyebrow */}
              <div className="sandesh-hero-eyebrow">
                EMAIL FORENSICS &amp; THREAT INTELLIGENCE
              </div>
            </div>

            {/* 3. Main Headline with Typing Motion & Luminous Glow */}
            <h1 className="sandesh-hero-headline" aria-label={fullHeadline}>
              <span className="headline-text">{typedHeadline}</span>
              {!isTypingComplete && (
                <span className="sandesh-typing-cursor" aria-hidden="true" />
              )}
            </h1>

            {/* 4. Supporting Introduction */}
            <p className="sandesh-hero-description">
              SandeshSetu helps investigators trace senders, map digital footprints,
              correlate evidence, and build investigation-ready reports — from a single email.
            </p>

            {/* 5. Subtle Core Pillars Line */}
            <div className="sandesh-hero-pillars">
              <span className="pillar-item">TRACE</span>
              <span className="pillar-dot">·</span>
              <span className="pillar-item">CORRELATE</span>
              <span className="pillar-dot">·</span>
              <span className="pillar-item">INVESTIGATE</span>
            </div>

            {/* 6. Apple / iPhone-Style CTAs */}
            <div className="sandesh-cta-action-row">
              <button
                type="button"
                className="sandesh-cta-btn sandesh-cta-primary"
                onClick={handleStartInvestigation}
                aria-label="Start Investigation"
              >
                <span>Start Investigation</span>
                <ArrowRight className="cta-arrow-icon" size={15} strokeWidth={2.2} />
              </button>

              <button
                type="button"
                className="sandesh-cta-btn sandesh-cta-secondary"
                onClick={handleSeeHowItWorks}
                aria-label="See How It Works"
              >
                <span>See How It Works</span>
                <ArrowRight className="cta-arrow-icon" size={15} strokeWidth={2.2} />
              </button>
            </div>

            {/* Minimalist Capabilities Footnote */}
            <div className="sandesh-hero-trust-bar">
              <div className="trust-item">
                <CheckCircle2 size={12} className="trust-icon" />
                <span>RFC 5322 MIME Parser</span>
              </div>
              <div className="trust-divider" />
              <div className="trust-item">
                <Lock size={12} className="trust-icon" />
                <span>SHA-256 Custody Proof</span>
              </div>
              <div className="trust-divider" />
              <div className="trust-item">
                <ShieldCheck size={12} className="trust-icon" />
                <span>Zero Hallucinations</span>
              </div>
            </div>
          </div>

          {/* Right Column: Interactive 3D Digital-Forensics Globe & Telemetry Card */}
          <div className="sandesh-hero-visual-col">
            <div className="sandesh-visual-canvas-card">
              {/* Primary Interactive Forensic 3D Globe with Continent Dots, Arcs & Radar Pulses */}
              <div className="globe-viewport">
                <ForensicGlobe />
              </div>

              {/* Refined Secondary Evidence Telemetry Card emerging from lower-right */}
              <div className="forensic-live-spec-card">
                <div className="spec-card-header">
                  <div className="spec-header-left">
                    <span className="spec-indicator-beacon" />
                    <span className="spec-case-tag">Evidence #SETU-089</span>
                  </div>
                  <span className="spec-status-chip">Verified Trace</span>
                </div>

                <div className="spec-card-body">
                  <div className="spec-meta-row">
                    <span className="spec-label">Ingress Relay</span>
                    <span className="spec-value">Frankfurt · AS9009</span>
                  </div>
                  <div className="spec-meta-row">
                    <span className="spec-label">Auth Protocol</span>
                    <div className="spec-auth-state">
                      <span className="auth-item"><span className="auth-dot pass" />SPF</span>
                      <span className="auth-item"><span className="auth-dot warn" />DKIM</span>
                    </div>
                  </div>
                  <div className="spec-meta-row">
                    <span className="spec-label">Chain of Custody</span>
                    <span className="spec-value mono-muted">SHA-256 Validated</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LandingPage;
