import React from 'react';
import { NavLink } from 'react-router-dom';
import { FolderLock, Search, FileText, Settings } from 'lucide-react';
import './Sidebar.css';

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  {
    to: '/cases',
    label: 'Cases',
    icon: <FolderLock size={16} />,
  },
  {
    to: '/investigations',
    label: 'Investigations',
    icon: <Search size={16} />,
  },
  {
    to: '/reports',
    label: 'Reports',
    icon: <FileText size={16} />,
  },
  {
    to: '/settings',
    label: 'Settings',
    icon: <Settings size={16} />,
  },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="app-sidebar" aria-label="Main Navigation">
      <div className="sidebar-nav-container">
        <div className="sidebar-nav-label">Investigation Workstation</div>
        <ul className="sidebar-nav-list">
          {navItems.map((item) => (
            <li key={item.to} className="sidebar-nav-item">
              <NavLink
                to={item.to}
                className={({ isActive }) =>
                  `sidebar-nav-link ${isActive ? 'active' : ''}`
                }
              >
                <span className="sidebar-nav-icon">{item.icon}</span>
                <span>{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </div>
    </aside>
  );
};
