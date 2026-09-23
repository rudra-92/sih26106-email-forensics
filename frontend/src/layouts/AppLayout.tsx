import React from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import './AppLayout.css';

export const AppLayout: React.FC = () => {
  const location = useLocation();

  return (
    <div className="app-shell">
      <Header />
      <div className="app-body">
        <Sidebar />
        <main className="app-main" id="main-content">
          <div key={location.pathname} className="sandesh-page-transition">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};
