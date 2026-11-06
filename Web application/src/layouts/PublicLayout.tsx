import React, { useEffect } from 'react';
import { PublicHeader, PublicRoute } from '../components/public/PublicHeader';
import { PublicFooter } from '../components/public/PublicFooter';

interface PublicLayoutProps {
  currentRoute: PublicRoute;
  onNavigate: (route: PublicRoute) => void;
  onEnterApp?: () => void;
  isAuthenticated: boolean;
  children: React.ReactNode;
}

export const PublicLayout: React.FC<PublicLayoutProps> = ({
  currentRoute,
  onNavigate,
  onEnterApp,
  isAuthenticated,
  children,
}) => {
  // Ensure the page and window scroll position is always placed at the top when navigating between routes
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
      if (document.documentElement) {
        document.documentElement.scrollTop = 0;
      }
      if (document.body) {
        document.body.scrollTop = 0;
      }
    }
  }, [currentRoute]);

  return (
    <div className="min-h-screen bg-[#F4F6FB] dark:bg-[#060814] text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-200 relative overflow-x-hidden">
      {/* Cinematic Cyber Background Lighting & Ambient Fog */}
      <div className="fixed inset-0 pointer-events-none -z-10 overflow-hidden">
        {/* Subtle Cyber Grid Layer */}
        <div className="absolute inset-0 bg-cyber-grid opacity-70 dark:opacity-40" />

        {/* Primary Top Radial Nebula (Soft cool violet-magenta-cyan glow in light mode, neon purple in dark mode) */}
        <div
          className="absolute -top-32 left-1/2 -translate-x-1/2 w-[900px] h-[550px] rounded-full blur-[140px] opacity-35 dark:opacity-45 pointer-events-none transition-opacity duration-700"
          style={{
            background:
              'radial-gradient(circle, rgba(147, 51, 234, 0.25) 0%, rgba(217, 70, 239, 0.15) 45%, rgba(6, 182, 212, 0.1) 75%, transparent 90%)',
          }}
        />

        {/* Ambient Cyan Secondary Core (Lower Left Glow) */}
        <div
          className="absolute top-[800px] -left-48 w-[600px] h-[600px] rounded-full blur-[160px] opacity-15 dark:opacity-25 pointer-events-none"
          style={{
            background:
              'radial-gradient(circle, rgba(6, 182, 212, 0.2) 0%, rgba(59, 130, 246, 0.1) 50%, transparent 80%)',
          }}
        />

        {/* Ambient Violet Tertiary Core (Lower Right Glow) */}
        <div
          className="absolute top-[1600px] -right-48 w-[700px] h-[700px] rounded-full blur-[180px] opacity-15 dark:opacity-25 pointer-events-none"
          style={{
            background:
              'radial-gradient(circle, rgba(168, 85, 247, 0.22) 0%, rgba(139, 92, 246, 0.1) 50%, transparent 80%)',
          }}
        />
      </div>

      <PublicHeader
        currentRoute={currentRoute}
        onNavigate={onNavigate}
        onEnterApp={onEnterApp}
        isAuthenticated={isAuthenticated}
      />
      <main className="flex-1 relative z-0">{children}</main>
      <PublicFooter onNavigate={onNavigate} />
    </div>
  );
};
