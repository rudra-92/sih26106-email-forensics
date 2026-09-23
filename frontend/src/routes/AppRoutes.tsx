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
  LandingPage,
  HowItWorksPage,
  InvestigationPage,
  EvidencePage,
  AboutPage,
} from '../pages';

const PageTransition: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return <div className="sandesh-page-transition">{children}</div>;
};

export const AppRoutes: React.FC = () => {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public Landing Page & Dedicated Navigation Sections */}
          <Route path="/" element={<PageTransition><LandingPage /></PageTransition>} />
          <Route path="/how-it-works" element={<PageTransition><HowItWorksPage /></PageTransition>} />
          <Route path="/investigation" element={<PageTransition><InvestigationPage /></PageTransition>} />
          <Route path="/evidence" element={<PageTransition><EvidencePage /></PageTransition>} />
          <Route path="/about" element={<PageTransition><AboutPage /></PageTransition>} />

          {/* Public-only authentication routes (redirect authenticated users to /cases) */}
          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<PageTransition><LoginPage /></PageTransition>} />
            <Route path="/register" element={<PageTransition><RegisterPage /></PageTransition>} />
          </Route>

          {/* Protected workstation routes (redirect unauthenticated users to /login) */}
          <Route element={<ProtectedRoute />}>
            <Route element={<AppLayout />}>
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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
};
