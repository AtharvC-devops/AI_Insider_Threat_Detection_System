import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Navbar } from './components/Navbar';
import { Sidebar } from './components/Sidebar';

import { Login } from './pages/Login';
import { AnalystDashboard } from './pages/AnalystDashboard';
import { SocDashboard } from './pages/SocDashboard';
import { ManagerDashboard } from './pages/ManagerDashboard';
import { SystemAdminPage } from './pages/SystemAdminPage';
import { EmployeesPage } from './pages/EmployeesPage';
import { EmployeeDetailPage } from './pages/EmployeeDetailPage';
import { ActivityPage } from './pages/ActivityPage';
import { AnomaliesPage } from './pages/AnomaliesPage';
import { RiskScoringPage } from './pages/RiskScoringPage';
import { UebaPage } from './pages/UebaPage';
import { AlertsPage } from './pages/AlertsPage';
import { IncidentsPage } from './pages/IncidentsPage';
import { InvestigationDetailPage } from './pages/InvestigationDetailPage';
import { ReportsPage } from './pages/ReportsPage';
import { WasLabPage } from './pages/WasLabPage';
import { isServerlessDeployment } from './services/api';

// Returns the home dashboard path for a given role
const getRoleDashboard = (role) => {
  switch (role) {
    case 'SOC Engineer': return '/soc';
    case 'Security Manager': return '/manager';
    case 'Administrator': return '/admin-dash';
    case 'Security Analyst':
    default: return '/analyst';
  }
};

// Requires authentication
const ProtectedLayout = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div className="min-h-screen bg-[#070b13] flex items-center justify-center text-cyan-400 font-mono text-sm">
        INITIALIZING SOC INTELLIGENCE SUBSYSTEMS...
      </div>
    );
  }
  if (!user) return <Navigate to="/login" replace />;
  return (
    <div className="min-h-screen bg-[#070b13] flex flex-col">
      <Navbar />
      <div className="flex flex-1">
        <Sidebar />
        <main className="flex-1 p-6 max-w-7xl mx-auto w-full overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
};

// Requires authentication AND specific role(s) — redirects unauthorized users to their own dashboard
const RoleRoute = ({ children, allowedRoles }) => {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (!allowedRoles.includes(user.role)) {
    return <Navigate to={getRoleDashboard(user.role)} replace />;
  }
  return children;
};

// Redirects from / to the correct role-based dashboard
const RoleRedirect = () => {
  const { user, loading } = useAuth();
  if (loading) return null;
  if (!user) return <Navigate to="/login" replace />;
  return <Navigate to={getRoleDashboard(user.role)} replace />;
};

export const App = () => {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/login" element={<Login />} />

          {/* Root redirects to role-appropriate dashboard */}
          <Route path="/" element={<ProtectedLayout><RoleRedirect /></ProtectedLayout>} />

          {/* Role-specific dashboards — guarded by role */}
          <Route path="/analyst" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Security Analyst', 'Administrator']}>
                <AnalystDashboard />
              </RoleRoute>
            </ProtectedLayout>
          } />
          <Route path="/soc" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['SOC Engineer', 'Administrator']}>
                <SocDashboard />
              </RoleRoute>
            </ProtectedLayout>
          } />
          <Route path="/manager" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Security Manager', 'Administrator']}>
                <ManagerDashboard />
              </RoleRoute>
            </ProtectedLayout>
          } />
          <Route path="/admin-dash" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Administrator']}>
                <SystemAdminPage />
              </RoleRoute>
            </ProtectedLayout>
          } />
          {!isServerlessDeployment && <Route path="/admin-control" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Administrator']}>
                <SystemAdminPage />
              </RoleRoute>
            </ProtectedLayout>
          } />}

          {/* Shared modules — authenticated users with appropriate role access */}
          <Route path="/employees" element={<ProtectedLayout><EmployeesPage /></ProtectedLayout>} />
          <Route path="/employees/:id" element={<ProtectedLayout><EmployeeDetailPage /></ProtectedLayout>} />
          <Route path="/activities" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['SOC Engineer', 'Administrator']}>
                <ActivityPage />
              </RoleRoute>
            </ProtectedLayout>
          } />
          {!isServerlessDeployment && <Route path="/ueba" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['SOC Engineer', 'Administrator']}>
                <UebaPage />
              </RoleRoute>
            </ProtectedLayout>
          } />}
          {!isServerlessDeployment && <Route path="/anomalies" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['SOC Engineer', 'Security Analyst', 'Administrator']}>
                <AnomaliesPage />
              </RoleRoute>
            </ProtectedLayout>
          } />}
          <Route path="/risk-scoring" element={<ProtectedLayout><RiskScoringPage /></ProtectedLayout>} />
          <Route path="/alerts" element={<ProtectedLayout><AlertsPage /></ProtectedLayout>} />
          <Route path="/incidents" element={<ProtectedLayout><IncidentsPage /></ProtectedLayout>} />
          <Route path="/investigations/:id" element={<ProtectedLayout><InvestigationDetailPage /></ProtectedLayout>} />
          <Route path="/reports" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Security Manager', 'Administrator']}>
                <ReportsPage />
              </RoleRoute>
            </ProtectedLayout>
          } />

          {/* WAS Security Lab — Administrator only (Analyst can view alerts via Alerts page) */}
          {!isServerlessDeployment && <Route path="/was-lab" element={
            <ProtectedLayout>
              <RoleRoute allowedRoles={['Administrator']}>
                <WasLabPage />
              </RoleRoute>
            </ProtectedLayout>
          } />}

          {/* Catch-all: redirect to role dashboard */}
          <Route path="*" element={<ProtectedLayout><RoleRedirect /></ProtectedLayout>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
};

export default App;
