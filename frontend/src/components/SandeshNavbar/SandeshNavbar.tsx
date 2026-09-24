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
        <div className="sandesh-nav-brand" onClick={() => navigate('/')} title="SandeshSetu Home">
          <div className="sandesh-nav-brand-icon">
            <SandeshSetuLogo variant="icon" size={17} theme="dark" />
          </div>
          <span className="sandesh-nav-brand-text">SandeshSetu</span>
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
            className="sandesh-btn-nav"
            onClick={handleStartInvestigation}
          >
            Start Investigation
          </button>
        </div>
      </div>
    </header>
  );
};

export default SandeshNavbar;
