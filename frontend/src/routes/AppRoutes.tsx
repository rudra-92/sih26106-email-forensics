import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, ProtectedRoute, PublicOnlyRoute } from '../auth';
import { AppLayout } from '../layouts';
import {
  CasesPage,
  CaseWorkspaceLayout,
  OverviewSection,
  AnalysisSection,
  EvidenceSection,
  GraphSection,
  GeolocationSection,
  TimelineSection,
  InvestigationsPage,
  ReportsPage,
  SettingsPage,
  LoginPage,
  RegisterPage,
} from '../pages';

export const AppRoutes: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public-only authentication routes (redirect authenticated users to /cases) */}
          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
          </Route>

          {/* Protected workstation routes (redirect unauthenticated users to /login) */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
              <Route path="/" element={<Navigate to="/cases" replace />} />
              <Route path="/cases" element={<CasesPage />} />
              
              {/* Nested Case Workspace with persistent header and section tabs */}
              <Route path="/cases/:caseId" element={<CaseWorkspaceLayout />}>
                <Route index element={<OverviewSection />} />
                <Route path="analysis" element={<AnalysisSection />} />
                <Route path="evidence" element={<EvidenceSection />} />
                <Route path="graph" element={<GraphSection />} />
                <Route path="geolocation" element={<GeolocationSection />} />
                <Route path="timeline" element={<TimelineSection />} />
              </Route>

              <Route path="/investigations" element={<InvestigationsPage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>
          </Route>

          {/* Fallback route */}
          <Route path="*" element={<Navigate to="/cases" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};
