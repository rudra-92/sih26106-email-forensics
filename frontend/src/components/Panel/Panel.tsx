import React from 'react';
import './Panel.css';

export interface PanelProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  noPadding?: boolean;
}

export const Panel: React.FC<PanelProps> = ({
  title,
  subtitle,
  actions,
  footer,
  noPadding = false,
  children,
  className = '',
  ...props
}) => {
  return (
    <div className={`panel ${className}`} {...props}>
      {(title || actions) && (
        <div className="panel-header">
          <div className="panel-title-area">
            {title && <h3 className="panel-title">{title}</h3>}
            {subtitle && <p className="panel-subtitle">{subtitle}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      <div className={`panel-body ${noPadding ? 'panel-body-no-padding' : ''}`}>
        {children}
      </div>
      {footer && <div className="panel-footer">{footer}</div>}
    </div>
  );
};
