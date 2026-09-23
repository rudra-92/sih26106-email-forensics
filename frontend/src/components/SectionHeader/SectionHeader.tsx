import React from 'react';
import './SectionHeader.css';

export interface SectionHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  className?: string;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  description,
  actions,
  className = '',
}) => {
  return (
    <div className={`section-header ${className}`}>
      <div className="section-header-title-area">
        <h1 className="section-header-title">{title}</h1>
        {description && <p className="section-header-desc">{description}</p>}
      </div>
      {actions && <div className="section-header-actions">{actions}</div>}
    </div>
  );
};
