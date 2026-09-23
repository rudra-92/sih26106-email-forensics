import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AlertCircle, CheckCircle2, UserPlus, ArrowLeft } from 'lucide-react';
import { Button, Input } from '../components';
import { SandeshSetuLogo } from '../components/brand';
import { useAuth } from '../auth/AuthContext';
import { formatAuthError } from '../auth/authService';
import './AuthPages.css';

export const RegisterPage: React.FC = () => {
  const { register, login } = useAuth();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Field validation errors
  const [nameError, setNameError] = useState('');
  const [emailError, setEmailError] = useState('');
  const [passwordError, setPasswordError] = useState('');
  const [confirmError, setConfirmError] = useState('');

  const validate = (): boolean => {
    let valid = true;
    setNameError('');
    setEmailError('');
    setPasswordError('');
    setConfirmError('');

    if (!fullName.trim()) {
      setNameError('Full name is required.');
      valid = false;
    }

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
    } else if (password.length < 6) {
      setPasswordError('Password must be at least 6 characters.');
      valid = false;
    }

    if (!confirmPassword) {
      setConfirmError('Please confirm your password.');
      valid = false;
    } else if (password !== confirmPassword) {
      setConfirmError('Passwords do not match.');
      valid = false;
    }

    return valid;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!validate()) return;

    setIsSubmitting(true);
    try {
      // 1. Register investigator account via Supabase
      await register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
      });

      // 2. Automatically establish session if email confirmation is disabled
      try {
        await login({
          email: email.trim(),
          password,
        });

        navigate('/cases', { replace: true });
      } catch (loginErr: unknown) {
        const msg = formatAuthError(loginErr);
        if (msg.toLowerCase().includes('verify your email')) {
          setSuccessMessage('Registration successful! Please check your email inbox to verify your account before logging in.');
        } else {
          setSuccessMessage('Registration successful! You may now sign in to your account.');
        }
      }
    } catch (err: unknown) {
      setErrorMessage(formatAuthError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page-container">
      <div className="auth-topbar">
        <button type="button" className="sandesh-back-btn" onClick={() => navigate('/')}>
          <ArrowLeft size={16} />
          <span>Back to Home</span>
        </button>
      </div>

      <div className="auth-card">
        <div className="auth-brand" style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
          <SandeshSetuLogo variant="lockup" size={26} theme="light" showSubtitle={true} />
        </div>

        <div className="auth-header">
          <h1 className="auth-title">Register Investigator Account</h1>
          <p className="auth-subtitle">Create workstation credentials for forensic case investigation.</p>
        </div>

        {successMessage && (
          <div 
            style={{
              padding: '10px 12px',
              backgroundColor: '#ecf7ef',
              border: '1px solid #c2e2cc',
              borderRadius: '6px',
              color: '#166534',
              fontSize: '12.5px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              marginBottom: '16px',
              fontFamily: 'Aptos, Segoe UI, system-ui, sans-serif'
            }}
            role="status"
          >
            <CheckCircle2 size={16} style={{ flexShrink: 0 }} />
            <span>{successMessage}</span>
          </div>
        )}

        {errorMessage && (
          <div className="auth-error-banner" role="alert" aria-live="assertive">
            <AlertCircle size={16} style={{ flexShrink: 0, marginTop: '1px' }} />
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="auth-form" noValidate>
          <Input
            id="register-fullname"
            label="Full Name"
            type="text"
            value={fullName}
            onChange={(e) => setFullName(e.target.value)}
            placeholder="e.g. Rudra Sharma"
            error={nameError}
            autoComplete="name"
            autoFocus
            required
          />

          <Input
            id="register-email"
            label="Workstation Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="investigator@agency.gov"
            error={emailError}
            autoComplete="email"
            required
          />

          <Input
            id="register-password"
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Min. 8 characters"
            error={passwordError}
            autoComplete="new-password"
            required
          />

          <Input
            id="register-confirm-password"
            label="Confirm Password"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Re-enter password"
            error={confirmError}
            autoComplete="new-password"
            required
          />

          <Button
            type="submit"
            variant="primary"
            size="md"
            icon={<UserPlus size={15} />}
            isLoading={isSubmitting}
            className="auth-submit-btn"
          >
            Register Account
          </Button>
        </form>

        <div className="auth-footer">
          <span>Already registered?</span>
          <Link to="/login">Sign in to Console</Link>
        </div>
      </div>

      <div className="auth-disclaimer">
        Workstation Credentials Subject to Audit • Role Assigned: Investigator
      </div>
    </div>
  );
};
