import React from 'react';

export interface SandeshSetuLogoProps {
  variant?: 'icon' | 'lockup' | 'blueprint';
  size?: number;
  className?: string;
  theme?: 'dark' | 'light';
  showSubtitle?: boolean;
  animated?: boolean;
  animStage?: 'constructing' | 'settled' | 'idle';
}

/**
 * SandeshSetu Master Brand Logo Component
 * 
 * Visual Anatomy:
 * 1. "Sandesh" (संदेश) - The core cryptographic email envelope / evidence packet.
 * 2. "Setu" (सेतु) - The multi-hop relay bridge connecting sender nodes to the gateway.
 * 3. "Forensics" - The outer protective shield perimeter with SHA-256 verification vertex.
 */
export const SandeshSetuLogo: React.FC<SandeshSetuLogoProps> = ({
  variant = 'icon',
  size = 28,
  className = '',
  theme = 'dark',
  showSubtitle = false,
  animated = false,
  animStage = 'idle',
}) => {
  const isDark = theme === 'dark';

  // Palette tokens
  const strokeOuter = isDark ? '#C9ADA7' : '#17243A';
  const strokeInner = isDark ? '#F2E9E4' : '#1683E8';
  const strokeBridge = isDark ? '#9A8C98' : '#64748B';
  const fillNode = isDark ? '#C9ADA7' : '#1683E8';
  const fillCenter = isDark ? 'rgba(74, 78, 105, 0.35)' : 'rgba(22, 131, 232, 0.08)';

  const animClass = animated ? `sandesh-logo-animating sandesh-anim-${animStage}` : '';

  const svgIcon = (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`sandesh-logo-svg ${animClass} ${className}`}
      aria-hidden="true"
      style={{ display: 'block', flexShrink: 0 }}
    >
      {/* 1. Outer Forensic Shield Perimeter */}
      <path
        d="M16 3L6 7V15C6 21.2 10.3 26.9 16 28.5C21.7 26.9 26 21.2 26 15V7L16 3Z"
        stroke={strokeOuter}
        strokeWidth="1.7"
        strokeLinecap="round"
        strokeLinejoin="round"
        fill={fillCenter}
        className="sandesh-logo-elem sandesh-logo-shield"
      />

      {/* 2. "Setu" (Bridge) Multi-Hop Relay Nodes & Connection Lines */}
      <line
        x1="11"
        y1="10"
        x2="21"
        y2="10"
        stroke={strokeBridge}
        strokeWidth="1.2"
        strokeDasharray="1.5 1.5"
        className="sandesh-logo-elem sandesh-logo-bridge-line"
      />
      <circle cx="11" cy="10" r="1.6" fill={fillNode} className="sandesh-logo-elem sandesh-logo-node-left" />
      <circle cx="16" cy="7.5" r="1.6" fill={isDark ? '#F2E9E4' : '#17243A'} className="sandesh-logo-elem sandesh-logo-node-center" />
      <circle cx="21" cy="10" r="1.6" fill={fillNode} className="sandesh-logo-elem sandesh-logo-node-right" />

      {/* 3. "Sandesh" (Message) Cryptographic Envelope Body */}
      <rect
        x="9.5"
        y="13.5"
        width="13"
        height="8.5"
        rx="1"
        stroke={strokeInner}
        strokeWidth="1.4"
        fill={isDark ? '#22223B' : '#FFFFFF'}
        className="sandesh-logo-elem sandesh-logo-envelope-body"
      />

      {/* Envelope V-fold (MIME stream) */}
      <polyline
        points="9.8,14 16,18.2 22.2,14"
        stroke={strokeOuter}
        strokeWidth="1.3"
        strokeLinecap="round"
        strokeLinejoin="round"
        className="sandesh-logo-elem sandesh-logo-envelope-fold"
      />

      {/* 4. Bottom Forensic Verification Anchor Vertex */}
      <line
        x1="16"
        y1="22"
        x2="16"
        y2="24.5"
        stroke={strokeBridge}
        strokeWidth="1.3"
        strokeLinecap="round"
        className="sandesh-logo-elem sandesh-logo-anchor-line"
      />
      <circle cx="16" cy="25" r="1.2" fill={isDark ? '#F2E9E4' : '#17243A'} className="sandesh-logo-elem sandesh-logo-anchor-dot" />
    </svg>
  );

  if (variant === 'icon') {
    return svgIcon;
  }

  if (variant === 'blueprint') {
    return (
      <div className="sandesh-blueprint-view">
        <svg
          width={size}
          height={size}
          viewBox="0 0 100 100"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="sandesh-blueprint-svg"
        >
          {/* Blueprint Construction Grid */}
          <circle cx="50" cy="50" r="46" stroke="rgba(154, 140, 152, 0.2)" strokeWidth="0.8" strokeDasharray="2 2" />
          <circle cx="50" cy="50" r="32" stroke="rgba(154, 140, 152, 0.2)" strokeWidth="0.8" strokeDasharray="2 2" />
          <circle cx="50" cy="50" r="18" stroke="rgba(154, 140, 152, 0.2)" strokeWidth="0.8" strokeDasharray="2 2" />
          
          <line x1="50" y1="2" x2="50" y2="98" stroke="rgba(154, 140, 152, 0.25)" strokeWidth="0.8" strokeDasharray="2 2" />
          <line x1="2" y1="50" x2="98" y2="50" stroke="rgba(154, 140, 152, 0.25)" strokeWidth="0.8" strokeDasharray="2 2" />
          <line x1="16" y1="16" x2="84" y2="84" stroke="rgba(154, 140, 152, 0.15)" strokeWidth="0.8" strokeDasharray="3 3" />
          <line x1="16" y1="84" x2="84" y2="16" stroke="rgba(154, 140, 152, 0.15)" strokeWidth="0.8" strokeDasharray="3 3" />

          {/* Outer Shield Geometry */}
          <path
            d="M50 12L20 24V48C20 66.8 32.8 83.8 50 88.5C67.2 83.8 80 66.8 80 48V24L50 12Z"
            stroke="#C9ADA7"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="rgba(74, 78, 105, 0.2)"
          />

          {/* Setu (Bridge) Vector Network */}
          <line x1="34" y1="32" x2="66" y2="32" stroke="#9A8C98" strokeWidth="1.8" strokeDasharray="3 3" />
          <line x1="34" y1="32" x2="50" y2="24" stroke="#9A8C98" strokeWidth="1.4" />
          <line x1="66" y1="32" x2="50" y2="24" stroke="#9A8C98" strokeWidth="1.4" />
          
          <circle cx="34" cy="32" r="3.5" fill="#C9ADA7" stroke="#22223B" strokeWidth="1.5" />
          <circle cx="50" cy="24" r="3.8" fill="#F2E9E4" stroke="#22223B" strokeWidth="1.5" />
          <circle cx="66" cy="32" r="3.5" fill="#C9ADA7" stroke="#22223B" strokeWidth="1.5" />

          {/* Sandesh (MIME Envelope) Structure */}
          <rect
            x="30"
            y="42"
            width="40"
            height="26"
            rx="3"
            stroke="#F2E9E4"
            strokeWidth="2.2"
            fill="#22223B"
          />
          <polyline
            points="31,44 50,56 69,44"
            stroke="#C9ADA7"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {/* Lower verification anchor */}
          <line x1="50" y1="68" x2="50" y2="76" stroke="#9A8C98" strokeWidth="2" strokeLinecap="round" />
          <circle cx="50" cy="78" r="3" fill="#F2E9E4" stroke="#22223B" strokeWidth="1.5" />

          {/* Dimension Callouts / Coordinate Points */}
          <text x="50" y="8" fill="#9A8C98" fontSize="4.5" fontFamily="monospace" textAnchor="middle">v(0, +38) Crest</text>
          <text x="50" y="94" fill="#9A8C98" fontSize="4.5" fontFamily="monospace" textAnchor="middle">v(0, -38.5) Vertex</text>
          <text x="12" y="48" fill="#9A8C98" fontSize="4.5" fontFamily="monospace">r=28</text>
          <text x="82" y="48" fill="#9A8C98" fontSize="4.5" fontFamily="monospace">r=28</text>
        </svg>
      </div>
    );
  }

  // Full lockup (Clean unboxed icon + 'SandeshSetu' proper casing)
  return (
    <div className={`sandesh-brand-lockup ${className}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
      {svgIcon}
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <span
          style={{
            fontFamily: 'var(--font-sans)',
            fontSize: '16px',
            fontWeight: 700,
            letterSpacing: '-0.02em',
            color: isDark ? '#F2E9E4' : '#17243A',
            lineHeight: 1.1,
          }}
        >
          SandeshSetu
        </span>
        {showSubtitle && (
          <span
            style={{
              fontSize: '10px',
              fontFamily: 'ui-monospace, monospace',
              letterSpacing: '0.06em',
              color: isDark ? '#C9ADA7' : '#64748B',
            }}
          >
            EMAIL FORENSICS
          </span>
        )}
      </div>
    </div>
  );
};

export default SandeshSetuLogo;
