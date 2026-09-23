import React from 'react';
import './Badge.css';

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'neutral' | 'info' | 'success' | 'warning' | 'danger' | 'accent';
  showDot?: boolean;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'neutral',
  showDot = false,
  className = '',
  ...props
}) => {
  return (
    <span className={`badge badge-${variant} ${className}`} {...props}>
      {showDot && <span className="badge-dot" aria-hidden="true" />}
      {children}
    </span>
  );
};
