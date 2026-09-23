import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { SandeshSetuLogo } from '../brand/SandeshSetuLogo';
import './SandeshNavbar.css';

export const SandeshNavbar: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const handleStartInvestigation = () => {
    navigate('/login');
  };

  return (
    <header className="sandesh-nav">
      <div className="sandesh-nav-inner">
        <div className="sandesh-brand" onClick={() => navigate('/')}>
          <div className="sandesh-brand-icon">
            <SandeshSetuLogo variant="icon" size={20} theme="dark" />
          </div>
          <div className="sandesh-brand-text">
            <span className="sandesh-brand-title">SandeshSetu</span>
            <span className="sandesh-brand-badge">EMAIL FORENSICS</span>
          </div>
        </div>

        <nav className="sandesh-nav-links" aria-label="Main Navigation">
          <button
            type="button"
            className={`sandesh-nav-link ${location.pathname === '/how-it-works' ? 'active' : ''}`}
            onClick={() => navigate('/how-it-works')}
          >
            How It Works
          </button>
          <button
            type="button"
            className={`sandesh-nav-link ${location.pathname === '/investigation' ? 'active' : ''}`}
            onClick={() => navigate('/investigation')}
          >
            Investigation
          </button>
          <button
            type="button"
            className={`sandesh-nav-link ${location.pathname === '/evidence' ? 'active' : ''}`}
            onClick={() => navigate('/evidence')}
          >
            Evidence
          </button>
          <button
            type="button"
            className={`sandesh-nav-link ${location.pathname === '/about' ? 'active' : ''}`}
            onClick={() => navigate('/about')}
          >
            About
          </button>
        </nav>

        <div className="sandesh-nav-actions">
          <button
            type="button"
            className="sandesh-btn sandesh-btn-nav"
            onClick={handleStartInvestigation}
          >
            Start Investigation
          </button>
        </div>
      </div>
    </header>
  );
};
