import React from 'react';
import { Outlet } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import './AppLayout.css';

export const AppLayout: React.FC = () => {
  return (
    <div className="app-shell">
      <Header />
      <div className="app-body">
        <Sidebar />
        <main className="app-main" id="main-content">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
