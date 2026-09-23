import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { KineticGrid } from '../../components/KineticGrid/KineticGrid';
import { SandeshNavbar } from '../../components/SandeshNavbar/SandeshNavbar';
import { SandeshSetuLogo } from '../../components/brand/SandeshSetuLogo';
import { MotionButton } from '../../components/MotionButton/MotionButton';
import './LandingPage.css';

export const LandingPage: React.FC = () => {
  const navigate = useNavigate();

  // Animation sequence states
  const [logoStage, setLogoStage] = useState<'constructing' | 'settled'>('constructing');
  const [labelRevealed, setLabelRevealed] = useState(false);
  const [startTyping, setStartTyping] = useState(false);

  // Typing effect for the main headline
  const fullHeadline = 'From a suspicious email to investigation-ready evidence.';
  const [typedHeadline, setTypedHeadline] = useState('');
  const [isTypingComplete, setIsTypingComplete] = useState(false);

  useEffect(() => {
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setLogoStage('settled');
      setLabelRevealed(true);
      setStartTyping(true);
      setTypedHeadline(fullHeadline);
      setIsTypingComplete(true);
      return;
    }

    // Step 1: Logo construction resolves (~2.1s)
    const logoTimer = setTimeout(() => {
      setLogoStage('settled');
    }, 2100);

    // Step 2: Reveal "CYBERSECURITY EMAIL FORENSICS PLATFORM" label (~2.5s)
    const labelTimer = setTimeout(() => {
      setLabelRevealed(true);
    }, 2500);

    // Step 3: Start main headline typing animation (~2.9s)
    const typingStartTimer = setTimeout(() => {
      setStartTyping(true);
    }, 2900);

    return () => {
      clearTimeout(logoTimer);
      clearTimeout(labelTimer);
      clearTimeout(typingStartTimer);
    };
  }, []);

  // Headline typing effect trigger
  useEffect(() => {
    if (!startTyping || isTypingComplete) return;

    let currentIndex = 0;
    const interval = setInterval(() => {
      currentIndex++;
      setTypedHeadline(fullHeadline.slice(0, currentIndex));
      if (currentIndex >= fullHeadline.length) {
        clearInterval(interval);
        setIsTypingComplete(true);
      }
    }, 54); // Precise typing cadence

    return () => clearInterval(interval);
  }, [startTyping, isTypingComplete]);

  const handleStartInvestigation = () => {
    navigate('/login');
  };

  return (
    <div className="sandesh-landing sandesh-landing-hero-only">
      {/* 1. COMPACT, CLEAN FORENSIC NAVBAR */}
      <SandeshNavbar />

      {/* 2. FULLSCREEN SIMPLIFIED HERO SECTION */}
      <section className="sandesh-hero" id="hero">
        <KineticGrid className="sandesh-hero-grid" entranceAnimation={true} />

        <div className="sandesh-hero-content">
          {/* Central SandeshSetu Logo Centerpiece formed by the Network */}
          <div className={`sandesh-hero-logo-centerpiece ${logoStage}`} id="sandesh-hero-center-logo">
            <div className="sandesh-hero-logo-halo" />
            <SandeshSetuLogo
              variant="icon"
              size={68}
              theme="dark"
              animated={true}
              animStage={logoStage}
            />
          </div>

          <div className={`sandesh-hero-label ${labelRevealed ? 'revealed' : ''}`}>
            CYBERSECURITY EMAIL FORENSICS PLATFORM
          </div>

          <h1 className="sandesh-hero-title" aria-label={fullHeadline}>
            <span>{typedHeadline}</span>
            {startTyping && !isTypingComplete && (
              <span className="sandesh-typing-cursor" aria-hidden="true" />
            )}
          </h1>

          <div className={`sandesh-hero-fade-group ${isTypingComplete ? 'revealed' : ''}`}>
            <p className="sandesh-hero-subtitle">
              Trace, correlate and investigate email evidence.
            </p>

            <div className="sandesh-hero-cta-group">
              <MotionButton
                label="Start Investigation"
                variant="primary"
                animate={true}
                delay={150}
                onClick={handleStartInvestigation}
              />

              <MotionButton
                label="See How It Works"
                variant="secondary"
                animate={false}
                icon={<ChevronRight size={18} strokeWidth={2.2} />}
                onClick={() => navigate('/how-it-works')}
              />
            </div>

            <div className="sandesh-hero-meta">
              <span className="sandesh-meta-item">Evidence-first</span>
              <span className="sandesh-meta-divider">•</span>
              <span className="sandesh-meta-item">Explainable</span>
              <span className="sandesh-meta-divider">•</span>
              <span className="sandesh-meta-item">Human-in-the-loop</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default LandingPage;
