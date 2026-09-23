import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { AlertCircle, LogIn } from 'lucide-react';
import { Button, Input } from '../components';
import { SandeshSetuLogo } from '../components/brand';
import { useAuth } from '../auth/AuthContext';
import { formatAuthError } from '../auth/authService';
import './AuthPages.css';

export const LoginPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Field validation errors
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');

  const validate = (): boolean => {
    let valid = true;
    setEmailError('');
    setPasswordError('');

    if (!email.trim()) {
      setEmailError('Email address is required.');
      valid = false;
    } else if (!/\S+@\S+\.\S+/.test(email.trim())) {
      setEmailError('Please provide a valid email format.');
      valid = false;
    }

    if (!password) {
      setPasswordError('Password is required.');
      valid = false;
    }

    return valid;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!validate()) return;

    setIsSubmitting(true);
    try {
      await login({
        email: email.trim(),
        password,
      });

      // Navigate to return URL if exists, else /cases
      const from = (location.state as { from?: { pathname?: string } })?.from?.pathname || '/cases';
      navigate(from, { replace: true });
    } catch (err: unknown) {
      setErrorMessage(formatAuthError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page-container">
      <div className="auth-card">
        <div className="auth-brand" style={{ display: 'flex', justifyContent: 'center', marginBottom: 'var(--space-4)' }}>
          <SandeshSetuLogo variant="lockup" size={24} showSubtitle={true} />
        </div>

        <div className="auth-header">
          <h1 className="auth-title">Sign in to Investigation Console</h1>
          <p className="auth-subtitle">Authorized personnel only.</p>
        </div>

        {errorMessage && (
          <div className="auth-error-banner" role="alert" aria-live="assertive">
            <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '1px' }} />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          <Input
            id="login-email"
            label="Investigator Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="analyst@forensics.internal"
            error={emailError}
            autoComplete="email"
            autoFocus
            required
          />

          <Input
            id="login-password"
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="••••••••"
            error={passwordError}
            autoComplete="current-password"
            required
          />

          <Button
            type="submit"
            variant="primary"
            size="md"
            icon={<LogIn size={15} />}
            isLoading={isSubmitting}
            className="auth-submit-btn"
          >
            Sign in to Console
          </Button>
        </form>

        <div className="auth-footer">
          <span>Need an investigator account?</span>
          <Link to="/register">Register</Link>
        </div>
      </div>

      <div className="auth-disclaimer">
        Federal & Enterprise Evidence Preservation Standard • Restricted Access
      </div>
    </div>
  );
};
