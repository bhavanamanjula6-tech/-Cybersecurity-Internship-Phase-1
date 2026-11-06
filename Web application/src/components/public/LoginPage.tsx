import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Eye,
  EyeOff,
  UserCheck,
  ArrowRight,
  AlertCircle,
  Info,
  Clock,
  UserPlus,
  Mail,
  User,
  KeyRound,
  CheckCircle2,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { UserRole, DEMO_PERSONAS } from '../../types/auth';
import { isSupabaseConfigured } from '../../lib/supabaseClient';

export type AuthPageMode = 'signin' | 'register' | 'forgot_password' | 'reset_password' | 'confirmation';

interface LoginPageProps {
  initialMode?: 'signin' | 'register' | 'forgot_password' | 'reset_password';
  onLoginSuccess: () => void;
  onNavigate?: (route: any) => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({
  initialMode = 'signin',
  onLoginSuccess,
}) => {
  const {
    loginAs,
    loginWithCredentials,
    register,
    requestPasswordReset,
    updatePassword,
    verifyEmailOtp,
    isPasswordRecovery,
    isAuthenticated,
    currentUser,
    rememberMe,
    setRememberMe,
  } = useAuth();
  const isLive = isSupabaseConfigured();

  // Auto-redirect to authorized workspace if already authenticated and approved
  useEffect(() => {
    if (isAuthenticated && currentUser?.accountStatus === 'approved') {
      onLoginSuccess();
    }
  }, [isAuthenticated, currentUser?.accountStatus, onLoginSuccess]);

  // Mode: 'signin' | 'register' | 'forgot_password' | 'reset_password' | 'confirmation'
  const [mode, setMode] = useState<AuthPageMode>(initialMode);

  // Sign In form states
  const [email, setEmail] = useState(isLive ? '' : 'alex.mercer@soc.internal');
  const [password, setPassword] = useState(isLive ? '' : '••••••••••••');
  const [showPassword, setShowPassword] = useState(false);

  // Registration form states
  const [regFullName, setRegFullName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regConfirmPassword, setRegConfirmPassword] = useState('');
  const [showRegPassword, setShowRegPassword] = useState(false);

  // Recovery / Reset Password states
  const [recoveryEmail, setRecoveryEmail] = useState('');
  const [recoveryConfirmation, setRecoveryConfirmation] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [resetSuccessStatus, setResetSuccessStatus] = useState<string | null>(null);

  // Registration Confirmation & Email Verification state
  const [registeredEmail, setRegisteredEmail] = useState('');
  const [requiresEmailConfirmation, setRequiresEmailConfirmation] = useState(false);
  const [isEmailConfirmed, setIsEmailConfirmed] = useState(false);
  const [isVerifyingEmail, setIsVerifyingEmail] = useState(false);

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    setMode(initialMode);
    setErrorMessage(null);
  }, [initialMode]);

  // Check URL search & hash parameters on mount for verification tokens, recovery tokens, or errors
  useEffect(() => {
    if (typeof window === 'undefined') return;

    const extractParam = (name: string): string | null => {
      const searchParams = new URLSearchParams(window.location.search);
      const val = searchParams.get(name);
      if (val) return val;

      const hash = window.location.hash || '';
      const qIdx = hash.indexOf('?');
      if (qIdx !== -1) {
        const hashParams = new URLSearchParams(hash.substring(qIdx));
        const hashVal = hashParams.get(name);
        if (hashVal) return hashVal;
      }
      const cleanHash = hash.replace(/^#/, '');
      if (cleanHash.includes('=')) {
        const directParams = new URLSearchParams(cleanHash);
        return directParams.get(name);
      }
      return null;
    };

    const errorCode = extractParam('error_code');
    const errorDescription = extractParam('error_description') || extractParam('error');
    const tokenHash = extractParam('token_hash');
    const type = extractParam('type');

    if (errorCode || errorDescription) {
      if (errorCode === 'otp_expired' || (errorDescription && errorDescription.toLowerCase().includes('expired'))) {
        setErrorMessage('The verification or recovery link is invalid or has expired. Please request a new link.');
        setMode('signin');
      } else {
        setErrorMessage(decodeURIComponent(errorDescription || errorCode || 'Verification failed.'));
        setMode('signin');
      }
      return;
    }

    if (type === 'recovery' || window.location.hash.includes('reset-password')) {
      setMode('reset_password');
      return;
    }

    // Cross-device email verification via token_hash
    if (tokenHash) {
      setIsVerifyingEmail(true);
      verifyEmailOtp(tokenHash, type === 'email' ? 'email' : 'signup').then((res) => {
        setIsVerifyingEmail(false);
        if (res.success) {
          setIsEmailConfirmed(true);
          setRequiresEmailConfirmation(false);
          setMode('confirmation');
          try {
            window.history.replaceState(null, '', window.location.pathname + '#login');
          } catch {}
        } else {
          setErrorMessage(res.error || 'Email verification link is invalid or has expired.');
          setMode('signin');
        }
      });
      return;
    }

    // Direct redirect from Supabase Auth verify endpoint where backend already confirmed user
    if (type === 'signup') {
      setIsEmailConfirmed(true);
      setRequiresEmailConfirmation(false);
      setMode('confirmation');
      try {
        window.history.replaceState(null, '', window.location.pathname + '#login');
      } catch {}
    }
  }, [verifyEmailOtp]);

  // React to AuthContext recovery signal
  useEffect(() => {
    if (isPasswordRecovery) {
      setMode('reset_password');
      setErrorMessage(null);
    }
  }, [isPasswordRecovery]);

  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setIsLoading(true);

    try {
      const res = await loginWithCredentials(email, password, rememberMe);
      if (res.success) {
        onLoginSuccess();
      } else {
        setErrorMessage(res.error || 'Authentication failed.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!regFullName.trim()) {
      setErrorMessage('Please provide your full legal name.');
      return;
    }

    if (!regEmail.trim() || !regEmail.includes('@')) {
      setErrorMessage('Please provide a valid enterprise email address.');
      return;
    }

    if (regPassword.length < 8) {
      setErrorMessage('Password must be at least 8 characters long.');
      return;
    }

    if (regPassword !== regConfirmPassword) {
      setErrorMessage('Passwords do not match. Please re-enter your confirmation password.');
      return;
    }

    setIsLoading(true);

    try {
      const res = await register(regEmail, regPassword, regFullName);
      if (res.success) {
        setRegisteredEmail(regEmail);
        setRequiresEmailConfirmation(Boolean(res.requiresEmailConfirmation));
        setMode('confirmation');
      } else {
        setErrorMessage(res.error || 'Registration failed.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!recoveryEmail.trim() || !recoveryEmail.includes('@')) {
      setErrorMessage('Please provide a valid enterprise email address.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await requestPasswordReset(recoveryEmail);
      if (res.success) {
        setRecoveryConfirmation(
          'If an account matches that email address, password recovery instructions have been dispatched. Please check your inbox and spam folder.'
        );
      } else {
        setErrorMessage(res.error || 'Password recovery request failed.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (newPassword.length < 8) {
      setErrorMessage('Password must be at least 8 characters long.');
      return;
    }

    if (newPassword !== confirmNewPassword) {
      setErrorMessage('Passwords do not match. Please re-enter your confirmation password.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await updatePassword(newPassword);
      if (res.success) {
        setResetSuccessStatus(res.accountStatus || 'pending');
        if (typeof window !== 'undefined' && window.location.hash) {
          window.history.replaceState(null, '', window.location.pathname);
        }
      } else {
        setErrorMessage(res.error || 'Password update failed. The recovery session may have expired.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const isProd = Boolean(import.meta.env?.PROD);

  const handleFastPersona = (role: UserRole) => {
    if (isProd || isLive) {
      setErrorMessage(
        'Fast demo persona login is disabled in live database mode. Please authenticate with your registered credentials.'
      );
      return;
    }
    loginAs(role, rememberMe);
    onLoginSuccess();
  };

  const showTabs = mode === 'signin' || mode === 'register';

  return (
    <div className="max-w-md mx-auto px-4 py-8 sm:py-14">
      {/* Centered Authentication Card */}
      <div className="bg-white dark:bg-[#080c22]/95 rounded-2xl p-6 sm:p-8 border border-slate-200 dark:border-purple-500/30 shadow-2xl dark:shadow-[0_0_50px_rgba(139,92,246,0.18)] flex flex-col justify-between backdrop-blur-md relative overflow-hidden">
        {/* Subtle Ambient Glow */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-purple-500/15 rounded-full blur-2xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-48 h-48 bg-cyan-500/15 rounded-full blur-2xl pointer-events-none" />

        <div className="space-y-6 relative z-10">
          {/* Card Top Brand & Title */}
          <div className="text-center space-y-2">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl bg-purple-950/80 border border-purple-500/40 text-cyan-400 shadow-[0_0_20px_rgba(168,85,247,0.35)] mb-1">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center justify-center gap-2">
                <h2 className="font-heading font-extrabold tracking-wider text-xl text-slate-900 dark:text-white leading-none">
                  KRYPTRION
                </h2>
                <span className="text-[9px] font-mono font-medium tracking-tight uppercase px-1.5 py-0.5 rounded bg-purple-950/70 text-cyan-300/85 border border-purple-600/40 leading-none inline-flex items-center self-center shadow-xs">
                  AI SOC PLATFORM
                </span>
              </div>
              <p className="text-[11px] font-semibold text-purple-700 dark:text-cyan-400 tracking-wide mt-0.5">
                See the Threat. Understand the Risk. Respond Smarter.
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-sans">
                {mode === 'signin'
                  ? 'Sign in to access authorized operational workspace.'
                  : mode === 'register'
                  ? 'Register for SOC access. Requires administrative approval.'
                  : mode === 'forgot_password'
                  ? 'Enterprise credential recovery and password reset.'
                  : mode === 'reset_password'
                  ? 'Set a new secure access password for your account.'
                  : 'Account registration request status.'}
              </p>
            </div>
          </div>

          {/* Mode Switcher Tabs (Sign In vs Create Account) */}
          {showTabs && (
            <div className="flex items-center p-1 bg-slate-100 dark:bg-slate-950/80 rounded-xl border border-slate-200 dark:border-purple-900/40">
              <button
                type="button"
                onClick={() => {
                  setMode('signin');
                  setErrorMessage(null);
                }}
                className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  mode === 'signin'
                    ? 'bg-white dark:bg-purple-900/60 text-purple-700 dark:text-purple-200 shadow-xs border border-purple-200/80 dark:border-purple-500/40'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setMode('register');
                  setErrorMessage(null);
                }}
                className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  mode === 'register'
                    ? 'bg-white dark:bg-purple-900/60 text-purple-700 dark:text-purple-200 shadow-xs border border-purple-200/80 dark:border-purple-500/40'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                Create Account
              </button>
            </div>
          )}

          {/* Error Message Display */}
          {errorMessage && (
            <div className="p-3 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 rounded-lg text-xs text-rose-700 dark:text-rose-300 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* VIEW A: SIGN IN FORM */}
          {mode === 'signin' && (
            <form onSubmit={handleManualSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Enterprise Work Email
                </label>
                <div className="relative">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="operator@soc.internal"
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <Mail className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Access Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 pr-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <Lock className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Compact Login Options Row: Remember Me (Left) & Forgot Password? (Right) */}
              <div className="flex items-center justify-between text-xs py-1">
                <label
                  htmlFor="remember-me-checkbox"
                  className="flex items-center gap-2 cursor-pointer select-none text-slate-700 dark:text-slate-300"
                >
                  <input
                    id="remember-me-checkbox"
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="w-3.5 h-3.5 rounded border-slate-300 dark:border-purple-900/60 text-purple-600 focus:ring-purple-500 cursor-pointer accent-purple-600"
                  />
                  <span className="font-medium text-xs">Remember me</span>
                </label>
                <button
                  type="button"
                  onClick={() => {
                    setMode('forgot_password');
                    setErrorMessage(null);
                    setRecoveryConfirmation(null);
                  }}
                  className="text-purple-600 dark:text-purple-400 hover:text-purple-700 dark:hover:text-purple-300 font-medium hover:underline cursor-pointer transition text-xs shrink-0"
                >
                  Forgot Password?
                </button>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition cursor-pointer disabled:opacity-50"
              >
                {isLoading ? 'Authenticating...' : 'Sign In to Authorized Session'}
              </button>

              {/* Fast Operational Personas Grid (Development / Demo Mode Only) */}
              {!isProd && !isLive && (
                <div className="pt-2 border-t border-slate-200/90 dark:border-purple-900/30">
                  <div className="flex items-center justify-between text-[11px] font-mono font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
                    <span className="flex items-center gap-1.5">
                      <UserCheck className="w-3.5 h-3.5 text-purple-600 dark:text-cyan-400" />
                      Fast Personas (Dev Demo):
                    </span>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => handleFastPersona('soc_analyst')}
                      className="p-2 bg-slate-50 dark:bg-[#090d24] hover:border-purple-500 dark:hover:border-cyan-400 border border-slate-200/90 dark:border-purple-900/40 rounded-lg text-left transition flex items-center justify-between group cursor-pointer shadow-2xs"
                    >
                      <div className="min-w-0">
                        <div className="text-[11px] font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-purple-700 dark:group-hover:text-cyan-300">
                          {DEMO_PERSONAS.soc_analyst.name}
                        </div>
                        <div className="text-[9px] font-mono text-slate-500 dark:text-slate-400">
                          SOC Analyst
                        </div>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-purple-700 dark:group-hover:text-cyan-400 shrink-0 ml-1" />
                    </button>

                    <button
                      type="button"
                      onClick={() => handleFastPersona('security_engineer')}
                      className="p-2 bg-slate-50 dark:bg-[#090d24] hover:border-purple-500 dark:hover:border-blue-400 border border-slate-200/90 dark:border-purple-900/40 rounded-lg text-left transition flex items-center justify-between group cursor-pointer shadow-2xs"
                    >
                      <div className="min-w-0">
                        <div className="text-[11px] font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-purple-700 dark:group-hover:text-blue-300">
                          {DEMO_PERSONAS.security_engineer.name}
                        </div>
                        <div className="text-[9px] font-mono text-slate-500 dark:text-slate-400">
                          Sec Engineer
                        </div>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-purple-700 dark:group-hover:text-blue-400 shrink-0 ml-1" />
                    </button>

                    <button
                      type="button"
                      onClick={() => handleFastPersona('it_operations')}
                      className="p-2 bg-slate-50 dark:bg-[#090d24] hover:border-purple-500 dark:hover:border-amber-400 border border-slate-200/90 dark:border-purple-900/40 rounded-lg text-left transition flex items-center justify-between group cursor-pointer shadow-2xs"
                    >
                      <div className="min-w-0">
                        <div className="text-[11px] font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-purple-700 dark:group-hover:text-amber-300">
                          {DEMO_PERSONAS.it_operations.name}
                        </div>
                        <div className="text-[9px] font-mono text-slate-500 dark:text-slate-400">
                          IT Operations
                        </div>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-purple-700 dark:group-hover:text-amber-400 shrink-0 ml-1" />
                    </button>

                    <button
                      type="button"
                      onClick={() => handleFastPersona('super_admin')}
                      className="p-2 bg-slate-50 dark:bg-[#090d24] hover:border-purple-500 border border-slate-200/90 dark:border-purple-900/40 rounded-lg text-left transition flex items-center justify-between group cursor-pointer shadow-2xs"
                    >
                      <div className="min-w-0">
                        <div className="text-[11px] font-bold text-slate-900 dark:text-slate-100 truncate group-hover:text-purple-700 dark:group-hover:text-purple-300">
                          {DEMO_PERSONAS.super_admin.name}
                        </div>
                        <div className="text-[9px] font-mono text-slate-500 dark:text-slate-400">
                          Super Admin
                        </div>
                      </div>
                      <ArrowRight className="w-3 h-3 text-slate-400 group-hover:text-purple-700 dark:group-hover:text-purple-400 shrink-0 ml-1" />
                    </button>
                  </div>
                </div>
              )}

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setMode('register');
                    setErrorMessage(null);
                  }}
                  className="text-xs text-purple-700 dark:text-purple-400 hover:underline font-medium cursor-pointer"
                >
                  Need an operator account? Register for approval &rarr;
                </button>
              </div>
            </form>
          )}

          {/* VIEW B: CREATE ACCOUNT (REGISTRATION) FORM */}
          {mode === 'register' && (
            <form onSubmit={handleRegisterSubmit} className="space-y-4">
              <div className="p-3 bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800/60 rounded-xl space-y-1 text-[11px] text-purple-900 dark:text-purple-300">
                <div className="font-bold flex items-center gap-1.5">
                  <UserPlus className="w-3.5 h-3.5 text-purple-600 dark:text-cyan-400" />
                  Zero-Trust Access Governance Policy
                </div>
                <p className="text-slate-600 dark:text-slate-400 font-sans leading-normal">
                  New accounts are provisioned in a <strong>Pending Approval</strong> state with no operational permissions. A Platform Super Admin must verify your credentials and assign your operational role.
                </p>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Full Legal Name
                </label>
                <div className="relative">
                  <input
                    type="text"
                    placeholder="e.g. Jordan Hayes"
                    value={regFullName}
                    onChange={(e) => setRegFullName(e.target.value)}
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <User className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Enterprise Work Email
                </label>
                <div className="relative">
                  <input
                    type="email"
                    placeholder="jordan.hayes@soc.internal"
                    value={regEmail}
                    onChange={(e) => setRegEmail(e.target.value)}
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <Mail className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Password (Min 8 Characters)
                </label>
                <div className="relative">
                  <input
                    type={showRegPassword ? 'text' : 'password'}
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 pr-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <Lock className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                  <button
                    type="button"
                    onClick={() => setShowRegPassword(!showRegPassword)}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                    aria-label={showRegPassword ? 'Hide password' : 'Show password'}
                  >
                    {showRegPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showRegPassword ? 'text' : 'password'}
                    value={regConfirmPassword}
                    onChange={(e) => setRegConfirmPassword(e.target.value)}
                    className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                    required
                  />
                  <Lock className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                </div>
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition cursor-pointer disabled:opacity-50"
              >
                {isLoading ? 'Creating Account...' : 'Submit Registration Request'}
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setMode('signin');
                    setErrorMessage(null);
                  }}
                  className="text-xs text-purple-700 dark:text-purple-400 hover:underline font-medium cursor-pointer"
                >
                  Already have an approved account? Sign in &rarr;
                </button>
              </div>
            </form>
          )}

          {/* VIEW C: FORGOT PASSWORD FORM */}
          {mode === 'forgot_password' && (
            <form onSubmit={handleForgotPasswordSubmit} className="space-y-4">
              <div className="p-3 bg-purple-50/80 dark:bg-purple-950/40 border border-purple-200/90 dark:border-purple-800/60 rounded-xl space-y-1 text-[11px] text-purple-900 dark:text-purple-300">
                <div className="font-bold flex items-center gap-1.5">
                  <KeyRound className="w-3.5 h-3.5 text-purple-600 dark:text-cyan-400" />
                  Secure Password Recovery
                </div>
                <p className="text-slate-600 dark:text-slate-400 font-sans leading-normal">
                  Enter your registered enterprise work email address. If an account is located, a cryptographically signed recovery dispatch will be issued.
                </p>
              </div>

              {recoveryConfirmation ? (
                <div className="p-4 bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 rounded-xl space-y-3 text-xs">
                  <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300 font-semibold">
                    <CheckCircle2 className="w-4 h-4 shrink-0" />
                    Recovery Request Dispatched
                  </div>
                  <p className="text-emerald-700 dark:text-emerald-300/90 text-xs leading-relaxed">
                    {recoveryConfirmation}
                  </p>
                  <div className="pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        setMode('signin');
                        setRecoveryConfirmation(null);
                        setErrorMessage(null);
                      }}
                      className="w-full py-2.5 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition cursor-pointer"
                    >
                      Return to Sign In
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      Enterprise Work Email
                    </label>
                    <div className="relative">
                      <input
                        type="email"
                        value={recoveryEmail}
                        onChange={(e) => setRecoveryEmail(e.target.value)}
                        placeholder="operator@soc.internal"
                        className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                        required
                      />
                      <Mail className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition cursor-pointer disabled:opacity-50"
                  >
                    {isLoading ? 'Dispatching Recovery Link...' : 'Send Password Recovery Link'}
                  </button>

                  <div className="text-center pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        setMode('signin');
                        setErrorMessage(null);
                      }}
                      className="text-xs text-purple-700 dark:text-purple-400 hover:underline font-medium cursor-pointer"
                    >
                      &larr; Back to Sign In
                    </button>
                  </div>
                </>
              )}
            </form>
          )}

          {/* VIEW D: RESET PASSWORD FORM */}
          {mode === 'reset_password' && (
            <form onSubmit={handleResetPasswordSubmit} className="space-y-4">
              <div className="p-3 bg-purple-50/80 dark:bg-purple-950/40 border border-purple-200/90 dark:border-purple-800/60 rounded-xl space-y-1 text-[11px] text-purple-900 dark:text-purple-300">
                <div className="font-bold flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-purple-600 dark:text-cyan-400" />
                  Set New Secure Password
                </div>
                <p className="text-slate-600 dark:text-slate-400 font-sans leading-normal">
                  Configure a new access password for your Kryptrion account. Passwords must meet enterprise complexity standards (minimum 8 characters).
                </p>
              </div>

              {resetSuccessStatus ? (
                <div className="p-4 bg-slate-50 dark:bg-slate-950/80 rounded-xl border border-purple-200 dark:border-purple-800 space-y-3 text-xs">
                  <div className="flex items-center gap-2 text-purple-800 dark:text-purple-300 font-semibold">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                    Password Reset Completed
                  </div>

                  {resetSuccessStatus === 'approved' ? (
                    <p className="text-slate-600 dark:text-slate-300 text-xs leading-relaxed">
                      Your access credentials have been securely updated. You may now authenticate into your authorized operational session.
                    </p>
                  ) : (
                    <div className="p-2.5 bg-amber-50 dark:bg-amber-950/60 border border-amber-200 dark:border-amber-800 rounded-lg text-amber-900 dark:text-amber-200 text-[11px] space-y-1">
                      <div className="font-bold">Pending Administrative Clearance</div>
                      <p>
                        Your password was updated, but your account is in <strong>{resetSuccessStatus}</strong> status. Operational workspace access remains locked until a Super Admin approves your account.
                      </p>
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={() => {
                      setResetSuccessStatus(null);
                      setMode('signin');
                      setErrorMessage(null);
                    }}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 text-white shadow-sm hover:shadow transition cursor-pointer"
                  >
                    Proceed to Sign In Screen
                  </button>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      New Password (Min 8 Characters)
                    </label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 pr-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                        required
                      />
                      <Lock className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 cursor-pointer"
                        aria-label={showNewPassword ? 'Hide password' : 'Show password'}
                      >
                        {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                      Confirm New Password
                    </label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? 'text' : 'password'}
                        value={confirmNewPassword}
                        onChange={(e) => setConfirmNewPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full bg-[#F8FAFD] dark:bg-[#060814] border border-slate-300 dark:border-purple-900/40 rounded-lg px-3 py-2 pl-9 text-xs text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-purple-500 dark:focus:ring-cyan-500 focus:outline-hidden"
                        required
                      />
                      <Lock className="w-4 h-4 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 hover:from-purple-500 hover:via-purple-600 hover:to-indigo-500 text-white shadow-[0_4px_14px_rgba(124,58,237,0.3)] hover:shadow-[0_6px_20px_rgba(124,58,237,0.45)] transition cursor-pointer disabled:opacity-50"
                  >
                    {isLoading ? 'Updating Password...' : 'Save New Access Password'}
                  </button>

                  <div className="text-center pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        setMode('signin');
                        setErrorMessage(null);
                      }}
                      className="text-xs text-purple-700 dark:text-purple-400 hover:underline font-medium cursor-pointer"
                    >
                      &larr; Cancel and Return to Sign In
                    </button>
                  </div>
                </>
              )}
            </form>
          )}

          {/* VIEW E: REGISTRATION CONFIRMATION SCREEN */}
          {mode === 'confirmation' && (
            <div className="p-5 bg-slate-50 dark:bg-slate-950/80 rounded-2xl border border-purple-200 dark:border-purple-800/60 space-y-4">
              <div className="w-10 h-10 rounded-xl bg-purple-100 dark:bg-purple-950/80 border border-purple-300 dark:border-purple-700/60 flex items-center justify-center text-purple-700 dark:text-cyan-400 mx-auto shadow-sm">
                <Clock className="w-5 h-5 animate-pulse" />
              </div>

              <div className="text-center space-y-1">
                <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border border-amber-300 dark:border-amber-800/80">
                  PENDING SUPER ADMIN APPROVAL
                </div>
                <h4 className="text-base font-bold font-heading text-slate-900 dark:text-slate-100">
                  Registration Request Submitted
                </h4>
                <p className="text-xs text-slate-600 dark:text-slate-300 font-sans">
                  Account profile for <strong>{registeredEmail}</strong> created in pending state.
                </p>
              </div>

              <div className="space-y-2 text-xs text-slate-700 dark:text-slate-300 font-sans bg-white dark:bg-[#0c102a] p-3 rounded-xl border border-slate-200 dark:border-purple-900/40">
                {requiresEmailConfirmation && (
                  <div className="flex items-start gap-2">
                    <Mail className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" />
                    <div>
                      <strong>Email Verification Required:</strong> Please click the confirmation link dispatched to your inbox.
                    </div>
                  </div>
                )}

                <div className="flex items-start gap-2">
                  <Shield className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Administrative Clearance:</strong> A Super Admin must review your credentials and assign an operational role.
                  </div>
                </div>

                <div className="flex items-start gap-2">
                  <Lock className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Zero-Trust Isolation:</strong> Operational dashboards remain locked until database approval.
                  </div>
                </div>
              </div>

              <button
                type="button"
                onClick={() => {
                  setMode('signin');
                  setErrorMessage(null);
                }}
                className="w-full py-2.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-purple-600 via-purple-700 to-indigo-600 text-white shadow-sm hover:shadow transition cursor-pointer"
              >
                Return to Sign In Screen
              </button>
            </div>
          )}
        </div>

        {/* Client-Side Session Honesty Notice */}
        <div className="p-3 bg-[#F8FAFD] dark:bg-[#070a18] border border-slate-200/90 dark:border-purple-900/30 rounded-lg text-[10px] text-slate-500 dark:text-slate-400 font-mono space-y-1 mt-6">
          <div className="flex items-center gap-1.5 text-slate-700 dark:text-slate-300 font-bold">
            <Info className="w-3.5 h-3.5 text-purple-700 dark:text-cyan-400" />
            AUTHENTICATION HONESTY NOTICE
          </div>
          <p className="font-sans leading-normal">
            Demo personas operate within local/session storage. Live Supabase deployments enforce PostgreSQL Row-Level Security with cryptographic server-side JWT verification.
          </p>
        </div>
      </div>
    </div>
  );
};
