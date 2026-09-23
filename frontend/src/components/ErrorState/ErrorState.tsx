import React from 'react';
import { AlertTriangle } from 'lucide-react';
import { Button } from '../Button/Button';
import './ErrorState.css';

export interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'An error occurred',
  message,
  onRetry,
  className = '',
}) => {
  return (
    <div className={`error-state ${className}`} role="alert">
      <div className="error-state-icon">
        <AlertTriangle size={20} />
      </div>
      <h4 className="error-state-title">{title}</h4>
      <p className="error-state-msg">{message}</p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry}>
          Try Again
        </Button>
      )}
    </div>
  );
};
