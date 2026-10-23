import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Users, Activity, Cpu, Gauge,
  Radio, AlertTriangle, FileText, Settings, ShieldCheck,
  Zap, ShieldAlert
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { isServerlessDeployment } from '../services/api';

// Role-based navigation — each role only sees its authorized items
const ROLE_NAV = {
  'Security Analyst': [
    { label: 'My Dashboard', path: '/analyst', icon: LayoutDashboard },
    { label: 'Employees & Assets', path: '/employees', icon: Users },
    { label: 'Threat Alerts', path: '/alerts', icon: AlertTriangle },
    { label: 'Incident Management', path: '/incidents', icon: ShieldCheck },
    { label: 'WAS Security Lab', path: '/was-lab', icon: ShieldAlert },
  ],
  'SOC Engineer': [
    { label: 'My Dashboard', path: '/soc', icon: LayoutDashboard },
    { label: 'Activity Monitoring', path: '/activities', icon: Activity },
    { label: 'Behavioral Profiling / UEBA', path: '/ueba', icon: Radio },
    { label: 'AI Anomaly Detection', path: '/anomalies', icon: Cpu },
    { label: 'Insider Risk Scoring', path: '/risk-scoring', icon: Gauge },
  ],
  'Security Manager': [
    { label: 'My Dashboard', path: '/manager', icon: LayoutDashboard },
    { label: 'Insider Risk Scoring', path: '/risk-scoring', icon: Gauge },
    { label: 'Incident Management', path: '/incidents', icon: ShieldCheck },
    { label: 'Reports & Export', path: '/reports', icon: FileText },
  ],
  'Administrator': [
    { label: 'My Dashboard', path: '/admin-dash', icon: LayoutDashboard },
    { label: 'Employees & Assets', path: '/employees', icon: Users },
    { label: 'Threat Alerts', path: '/alerts', icon: AlertTriangle },
    { label: 'Incident Management', path: '/incidents', icon: ShieldCheck },
    { label: 'Attack Simulator', path: '/admin-control', icon: Zap },
    { label: 'WAS Security Lab', path: '/was-lab', icon: ShieldAlert },
  ],
};

export const Sidebar = () => {
  const { role } = useAuth();
  const navItems = (ROLE_NAV[role] || ROLE_NAV['Security Analyst']).filter((item) => (
    !isServerlessDeployment ||
    !['/ueba', '/anomalies', '/was-lab', '/admin-control'].includes(item.path)
  ));

  return (
    <aside className="w-64 bg-[#0d1320] border-r border-slate-800 flex flex-col justify-between p-4 min-h-[calc(100vh-4rem)]">
      <div className="space-y-6">
        <div>
          <p className="px-3 text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-2">SOC Navigation</p>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                      isActive
                        ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-lg shadow-cyan-950/40'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                    }`
                  }
                >
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </nav>
        </div>
      </div>

      {/* System Status Pill */}
      <div className="p-3 bg-slate-900/90 rounded-xl border border-slate-800 text-[11px] text-slate-400 space-y-1">
        <div className="flex items-center justify-between text-slate-300 font-medium">
          <span>{isServerlessDeployment ? 'Deployment' : 'ML Ensemble'}</span>
          <span className={`font-mono ${isServerlessDeployment ? 'text-amber-400' : 'text-emerald-400'}`}>
            {isServerlessDeployment ? 'CORE API' : '100% ONLINE'}
          </span>
        </div>
        <p className="text-[10px] text-slate-500 font-mono">
          {isServerlessDeployment ? 'ML features disabled' : '5 Models Active - FastAPI 2.0'}
        </p>
        <p className="text-[10px] text-slate-600 font-mono">Role: {role}</p>
      </div>
    </aside>
  );
};
