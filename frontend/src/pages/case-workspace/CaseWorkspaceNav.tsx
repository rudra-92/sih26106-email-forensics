import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Cpu,
  FileSearch,
  Network,
  Globe,
  Clock,
} from 'lucide-react';
import type { Case } from '../../types';

interface CaseWorkspaceNavProps {
  caseId: string;
  caseData: Case;
}

export const CaseWorkspaceNav: React.FC<CaseWorkspaceNavProps> = ({ caseId, caseData }) => {
  const tabs = [
    {
      to: `/cases/${caseId}`,
      label: 'Overview',
      icon: LayoutDashboard,
      end: true,
      badge: null,
    },
    {
      to: `/cases/${caseId}/analysis`,
      label: 'Analysis',
      icon: Cpu,
      end: false,
      badge: null,
    },
    {
      to: `/cases/${caseId}/evidence`,
      label: 'Evidence',
      icon: FileSearch,
      end: false,
      badge: caseData.evidence_count > 0 ? caseData.evidence_count : null,
    },
    {
      to: `/cases/${caseId}/graph`,
      label: 'Graph',
      icon: Network,
      end: false,
      badge: caseData.entity_count > 0 ? caseData.entity_count : null,
    },
    {
      to: `/cases/${caseId}/geolocation`,
      label: 'Geolocation',
      icon: Globe,
      end: false,
      badge: null,
    },
    {
      to: `/cases/${caseId}/timeline`,
      label: 'Timeline',
      icon: Clock,
      end: false,
      badge: null,
    },
  ];

  return (
    <nav className="case-workspace-subnav" aria-label="Investigation Sections">
      <div className="case-workspace-tabs">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <NavLink
              key={tab.to}
              to={tab.to}
              end={tab.end}
              className={({ isActive }) =>
                `case-workspace-tab ${isActive ? 'case-workspace-tab-active' : ''}`
              }
            >
              <Icon size={17} className="case-tab-icon" />
              <span className="case-tab-label">{tab.label}</span>
              {tab.badge != null && (
                <span className="case-tab-badge">{tab.badge}</span>
              )}
            </NavLink>
          );
        })}
      </div>
    </nav>
  );
};
