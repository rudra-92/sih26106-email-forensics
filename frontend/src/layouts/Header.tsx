import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LogOut } from 'lucide-react';
import { SandeshSetuLogo } from '../components/brand';
import { checkBackendHealth, type HealthCheckResponse } from '../api/client';
import { useAuth } from '../auth/AuthContext';
import './Header.css';

export const Header: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [health, setHealth] = useState<HealthCheckResponse | null>(null);

  useEffect(() => {
    let mounted = true;
    checkBackendHealth()
      .then((res) => {
        if (mounted) setHealth(res);
      })
      .catch(() => {
        if (mounted) setHealth(null);
      });
    return () => {
      mounted = false;
    };
  }, []);

  const getSectionName = () => {
    if (location.pathname.startsWith('/cases')) return 'Cases';
    if (location.pathname.startsWith('/investigations')) return 'Investigations';
    if (location.pathname.startsWith('/reports')) return 'Reports';
    if (location.pathname.startsWith('/settings')) return 'Settings';
    return 'Console';
  };

  const getInitials = (name?: string): string => {
    if (!name) return 'INV';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  };

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  const roleDisplay = user?.role
    ? user.role.charAt(0).toUpperCase() + user.role.slice(1)
    : 'Investigator';

  return (
    <header className="app-header">
      <div className="header-left">
        <Link to="/cases" className="brand-logo" aria-label="Sandesh Setu Home" style={{ textDecoration: 'none' }}>
          <SandeshSetuLogo variant="lockup" size={18} showSubtitle={false} />
        </Link>
        <span className="header-divider" aria-hidden="true" />
        <span className="header-context-title">{getSectionName()}</span>
      </div>

      <div className="header-right">
        <div className="system-status-indicator" title="Backend API & PostgreSQL Status">
          <span
            className={`status-dot ${health?.status === 'ok' ? '' : 'status-dot-offline'}`}
            aria-hidden="true"
          />
          <span>{health?.status === 'ok' ? 'Engine Online' : 'API Connecting...'}</span>
        </div>

        <div className="user-profile-badge" title={`Signed in as ${user?.email || 'Investigator'}`}>
          <div className="user-avatar" aria-hidden="true">
            {getInitials(user?.full_name)}
          </div>
          <div className="user-info">
            <span className="user-name">{user?.full_name || 'Investigator'}</span>
            <span className="user-role">{roleDisplay}</span>
          </div>
        </div>

        <button
          type="button"
          onClick={handleLogout}
          className="header-logout-btn"
          title="Sign out of workstation"
          aria-label="Sign out of workstation"
        >
          <LogOut size={13} />
          <span>Sign Out</span>
        </button>
      </div>
    </header>
  );
};
