import React from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './AuthContext';
import { LoadingState } from '../components/LoadingState/LoadingState';

export const PublicOnlyRoute: React.FC = () => {
  const { status } = useAuth();

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

  if (status === 'authenticated') {
    return <Navigate to="/cases" replace />;
  }

  return <Outlet />;
};
