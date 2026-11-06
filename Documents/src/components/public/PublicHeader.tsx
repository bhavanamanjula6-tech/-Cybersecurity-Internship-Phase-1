import React, { useState } from 'react';
import { Shield, Menu, X, ArrowRight } from 'lucide-react';
import { ThemeToggle } from '../common/ThemeToggle';

export type PublicRoute = 'home' | 'features' | 'about' | 'contact' | 'login' | 'register';

interface PublicHeaderProps {
  currentRoute: PublicRoute;
  onNavigate: (route: PublicRoute) => void;
  onEnterApp?: () => void;
  isAuthenticated: boolean;
}

export const PublicHeader: React.FC<PublicHeaderProps> = ({
  currentRoute,
  onNavigate,
  onEnterApp,
  isAuthenticated,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navLinks: Array<{ route: PublicRoute; label: string }> = [
    { route: 'home', label: 'Home' },
    { route: 'features', label: 'Features' },
    { route: 'about', label: 'About' },
    { route: 'contact', label: 'Contact' },
  ];

  const handleNav = (route: PublicRoute) => {
    onNavigate(route);
    setMobileMenuOpen(false);
  };

  return (
    <header className="bg-white/90 dark:bg-[#060814]/85 backdrop-blur-xl border-b border-slate-200/90 dark:border-purple-500/20 text-slate-800 dark:text-slate-100 sticky top-0 z-50 select-none transition-colors duration-300 shadow-xs dark:shadow-[0_4px_30px_rgba(0,0,0,0.5)]">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 h-16 flex items-center justify-between gap-4">
        {/* Brand with Cyber Aura */}
        <div
          className="flex items-center gap-3 cursor-pointer group shrink-0"
          onClick={() => handleNav('home')}
        >
          <div className="w-8 h-8 rounded-lg bg-purple-50/90 dark:bg-purple-900/50 border border-purple-200/90 dark:border-purple-500/50 flex items-center justify-center text-purple-700 dark:text-cyan-400 shadow-xs group-hover:border-purple-400 group-hover:shadow-[0_0_15px_rgba(147,51,234,0.35)] transition-all duration-300">
            <Shield className="w-4 h-4" />
          </div>
          <span className="font-heading font-bold tracking-tight text-base text-slate-900 dark:text-white group-hover:text-purple-700 dark:group-hover:text-purple-300 transition-colors whitespace-nowrap">
            KRYPTRION
          </span>
        </div>

        {/* Desktop Navigation with Smooth Cyber Highlights */}
        <nav className="hidden md:flex items-center gap-1.5 text-xs font-sans font-medium">
          {navLinks.map((link) => {
            const isActive = currentRoute === link.route;
            return (
              <button
                key={link.route}
                onClick={() => handleNav(link.route)}
                className={`relative px-3.5 py-1.5 rounded-lg transition-all duration-200 cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-purple-500 ${
                  isActive
                    ? 'text-purple-700 dark:text-purple-200 bg-purple-50/90 dark:bg-purple-950/60 font-semibold border border-purple-200/90 dark:border-purple-500/40 shadow-xs'
                    : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100/90 dark:hover:bg-slate-800/50'
                }`}
              >
                {link.label}
                {isActive && (
                  <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-gradient-to-r from-purple-600 via-fuchsia-500 to-indigo-600 rounded-full shadow-[0_0_8px_rgba(147,51,234,0.4)]" />
                )}
              </button>
            );
          })}
        </nav>

        {/* Right Actions: Theme Toggle, Create Account & Sign In CTA */}
        <div className="hidden md:flex items-center gap-2.5">
          <ThemeToggle />

          {isAuthenticated ? (
            <button
              onClick={onEnterApp}
              className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition-all duration-300 cursor-pointer focus-visible:ring-2 focus-visible:ring-purple-400"
            >
              <span>Enter Workspace</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <>
              <button
                onClick={() => handleNav('register')}
                className="px-3 py-2 rounded-lg text-xs font-medium text-slate-700 dark:text-slate-200 hover:text-purple-700 dark:hover:text-purple-300 hover:bg-purple-50/80 dark:hover:bg-purple-950/40 transition-colors cursor-pointer"
              >
                Create Account
              </button>
              <button
                onClick={() => handleNav('login')}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition-all duration-300 cursor-pointer focus-visible:ring-2 focus-visible:ring-purple-400"
              >
                <span>Sign In</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </>
          )}
        </div>

        {/* Mobile Hamburger Controls */}
        <div className="flex md:hidden items-center gap-2">
          <ThemeToggle />
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="p-1.5 rounded-lg text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-900 border border-slate-200 dark:border-slate-800 cursor-pointer"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden border-b border-slate-200/90 dark:border-slate-800 bg-white/95 dark:bg-[#070918] p-4 space-y-2 text-xs font-sans backdrop-blur-md">
          {navLinks.map((link) => (
            <button
              key={link.route}
              onClick={() => handleNav(link.route)}
              className={`w-full text-left px-3 py-2 rounded-lg transition ${
                currentRoute === link.route
                  ? 'bg-purple-50/90 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 font-bold border border-purple-200/90 dark:border-purple-800/60'
                  : 'text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900'
              }`}
            >
              {link.label}
            </button>
          ))}
          <div className="pt-2 border-t border-slate-200 dark:border-slate-800 space-y-2">
            {isAuthenticated ? (
              <button
                onClick={onEnterApp}
                className="w-full py-2 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg font-bold text-center block shadow-[0_0_15px_rgba(147,51,234,0.3)]"
              >
                Enter SOC Workspace &rarr;
              </button>
            ) : (
              <>
                <button
                  onClick={() => handleNav('login')}
                  className="w-full py-2 bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-lg font-bold text-center block shadow-[0_0_15px_rgba(147,51,234,0.3)]"
                >
                  Sign In to Platform &rarr;
                </button>
                <button
                  onClick={() => handleNav('register')}
                  className="w-full py-2 bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800/80 rounded-lg font-semibold text-center block"
                >
                  Create Operator Account
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
};
