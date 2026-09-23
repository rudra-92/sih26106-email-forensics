import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import './SectionHeader.css';

export interface SectionHeaderProps {
  title: string;
  description?: string;
  actions?: React.ReactNode;
  showBack?: boolean;
  onBack?: () => void;
  className?: string;
}

export const SectionHeader: React.FC<SectionHeaderProps> = ({
  title,
  description,
  actions,
  showBack = false,
  onBack,
  className = '',
}) => {
  const navigate = useNavigate();

  const handleBack = () => {
    if (onBack) {
      onBack();
    } else {
      navigate(-1);
    }
  };

  return (
    <div className={`section-header ${className}`}>
      <div className="section-header-title-area">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {showBack && (
            <button
              type="button"
              onClick={handleBack}
              className="section-header-back-btn"
              title="Go back"
              aria-label="Go back"
            >
              <ArrowLeft size={16} />
            </button>
          )}
          <h1 className="section-header-title">{title}</h1>
        </div>
        {description && <p className="section-header-desc">{description}</p>}
      </div>
      {actions && <div className="section-header-actions">{actions}</div>}
    </div>
  );
};
