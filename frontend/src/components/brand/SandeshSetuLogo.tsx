import React from 'react';

export interface SandeshSetuLogoProps {
  variant?: 'icon' | 'lockup';
  size?: number;
  showSubtitle?: boolean;
  className?: string;
}

/**
 * Sandesh Setu Brand Identity Component
 * Combines an email message motif with connected forensic evidence nodes & bridge structure.
 */
export const SandeshSetuLogo: React.FC<SandeshSetuLogoProps> = ({
  variant = 'lockup',
  size = 22,
  showSubtitle = true,
  className = '',
}) => {
  const icon = (
    <svg
      width={size}
      height={size}
      viewBox="0 0 28 28"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="sandesh-setu-svg"
      aria-hidden="true"
    >
      {/* Top forensic bridge link */}
      <line x1="7.5" y1="4.5" x2="20.5" y2="4.5" stroke="#2563EB" strokeWidth="1.5" strokeDasharray="1.5 1.5" />
      
      {/* Investigation trace lines into message */}
      <line x1="6" y1="6.5" x2="10" y2="10.5" stroke="#2563EB" strokeWidth="1.3" />
      <line x1="22" y1="6.5" x2="18" y2="10.5" stroke="#2563EB" strokeWidth="1.3" />

      {/* Top connected evidence nodes */}
      <circle cx="6" cy="4.5" r="2" fill="#0F172A" />
      <circle cx="22" cy="4.5" r="2" fill="#2563EB" />

      {/* Forensic Message Envelope Body */}
      <rect
        x="4.5"
        y="10.5"
        width="19"
        height="12"
        rx="1.5"
        fill="#FFFFFF"
        stroke="#0F172A"
        strokeWidth="1.4"
      />

      {/* Envelope V-fold */}
      <polyline
        points="4.8,11.5 14,17.2 23.2,11.5"
        stroke="#2563EB"
        strokeWidth="1.3"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Lower envelope corner folds */}
      <line x1="4.8" y1="21.5" x2="9.8" y2="16.5" stroke="#94A3B8" strokeWidth="1.1" strokeLinecap="round" />
      <line x1="23.2" y1="21.5" x2="18.2" y2="16.5" stroke="#94A3B8" strokeWidth="1.1" strokeLinecap="round" />

      {/* Bottom forensic anchor / trace node */}
      <line x1="14" y1="22.5" x2="14" y2="24.5" stroke="#2563EB" strokeWidth="1.3" />
      <circle cx="14" cy="25.5" r="1.5" fill="#F97316" />
    </svg>
  );

  if (variant === 'icon') {
    return <span className={`sandesh-setu-logo-icon ${className}`}>{icon}</span>;
  }

  return (
    <div className={`sandesh-setu-lockup ${className}`} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: size + 8,
          height: size + 8,
          backgroundColor: '#F8FAFC',
          border: '1px solid #CBD5E1',
          borderRadius: '4px',
          flexShrink: 0,
        }}
      >
        {icon}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1.15 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ fontSize: '13.5px', fontWeight: 600, color: '#0F172A', letterSpacing: '-0.2px' }}>
            Sandesh Setu
          </span>
          <span
            style={{
              fontSize: '9px',
              fontWeight: 700,
              backgroundColor: '#EFF6FF',
              color: '#2563EB',
              border: '1px solid #BFDBFE',
              borderRadius: '2px',
              padding: '1px 4px',
              letterSpacing: '0.4px',
            }}
          >
            SOC v2.0
          </span>
        </div>
        {showSubtitle && (
          <span style={{ fontSize: '9.5px', color: '#64748B', fontWeight: 400 }}>
            Email Forensics &amp; Threat Intelligence
          </span>
        )}
      </div>
    </div>
  );
};
