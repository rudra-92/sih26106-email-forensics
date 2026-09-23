import React from 'react';
import './LoadingState.css';

export interface LoadingStateProps {
  label?: string;
  className?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  label = 'Loading forensic data...',
  className = '',
}) => {
  return (
    <div className={`loading-state ${className}`} role="status" aria-live="polite">
      <div className="loading-spinner" aria-hidden="true" />
      <span className="loading-label">{label}</span>
    </div>
  );
};
