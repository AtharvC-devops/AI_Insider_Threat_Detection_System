import React from 'react';
import { Shield, LogOut } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const Navbar = () => {
  const { user, logout } = useAuth();

  return (
    <header className="h-16 bg-[#111827]/95 border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      {/* Brand */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-white flex items-center gap-1.5">
              <span>INSIDER</span>
              <span className="text-cyan-400">THREAT</span>
              <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">AI SOC 2.0</span>
            </h1>
          </div>
          <p className="text-[10px] text-slate-400 font-mono flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
            DEFCON 4 &bull; LIVE SENSORS ACTIVE &bull; ENTERPRISE UEBA
          </p>
        </div>
      </div>

      {/* User Profile */}
      <div className="flex items-center gap-4">
        {/* User Card */}
        <div className="flex items-center gap-3 pl-2 border-l border-slate-800">
          <div className="text-right hidden md:block">
            <p className="text-xs font-bold text-slate-200">{user?.name || 'SOC User'}</p>
            <p className="text-[10px] text-slate-400 font-mono">{user?.email}</p>
          </div>
          <button
            onClick={logout}
            title="Sign Out"
            className="p-2 rounded-lg bg-slate-800/80 hover:bg-red-500/20 text-slate-400 hover:text-red-400 transition-colors border border-slate-700"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
