import React from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { LoadingState } from '../components/LoadingState/LoadingState';

export const ProtectedRoute: React.FC = () => {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'loading') {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          backgroundColor: 'var(--bg-canvas)',
        }}
      >
        <LoadingState label="Verifying workstation credentials..." />
      </div>
    );
  }

  if (status === 'unauthenticated') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Outlet />;
};
