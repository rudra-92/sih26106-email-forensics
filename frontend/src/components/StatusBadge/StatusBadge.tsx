import React from 'react';
import { Badge, type BadgeProps } from '../Badge/Badge';
import type { AnalysisStatus, ThreatLabel, CaseStatus } from '../../types';

export interface StatusBadgeProps {
  status: AnalysisStatus | ThreatLabel | CaseStatus | string;
  type?: 'analysis' | 'threat' | 'case';
  showDot?: boolean;
  className?: string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  type = 'analysis',
  showDot = true,
  className = '',
}) => {
  const norm = String(status).toLowerCase();

  let variant: BadgeProps['variant'] = 'neutral';
  let label = status;

  if (type === 'threat' || norm === 'phishing' || norm === 'legitimate' || norm === 'fraud_related') {
    switch (norm) {
      case 'phishing':
        variant = 'danger';
        label = 'PHISHING';
        break;
      case 'malicious':
        variant = 'danger';
        label = 'MALICIOUS';
        break;
      case 'fraud_related':
      case 'suspicious':
        variant = 'warning';
        label = norm === 'fraud_related' ? 'FRAUD RELATED' : 'SUSPICIOUS';
        break;
      case 'legitimate':
      case 'benign':
        variant = 'success';
        label = 'LEGITIMATE';
        break;
      default:
        variant = 'neutral';
        label = 'UNKNOWN';
    }
  } else if (type === 'analysis') {
    switch (norm) {
      case 'completed':
        variant = 'success';
        label = 'Analysis Complete';
        break;
      case 'running':
        variant = 'info';
        label = 'Analyzing...';
        break;
      case 'pending':
        variant = 'neutral';
        label = 'Pending Analysis';
        break;
      case 'failed':
        variant = 'danger';
        label = 'Analysis Failed';
        break;
      default:
        variant = 'neutral';
        label = norm;
    }
  } else if (type === 'case') {
    switch (norm) {
      case 'open':
        variant = 'info';
        label = 'Open';
        break;
      case 'active':
        variant = 'accent';
        label = 'Active';
        break;
      case 'closed':
        variant = 'neutral';
        label = 'Closed';
        break;
      case 'archived':
        variant = 'neutral';
        label = 'Archived';
        break;
      default:
        variant = 'neutral';
        label = norm;
    }
  }

  return (
    <Badge variant={variant} showDot={showDot} className={className}>
      {label}
    </Badge>
  );
};
