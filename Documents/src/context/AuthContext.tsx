import React, { createContext, useContext, useState, useEffect, useRef, ReactNode } from 'react';
import { UserProfile, UserRole, DEMO_PERSONAS } from '../types/auth';
import {
  supabase,
  isSupabaseConfigured,
  getSupabaseConfigurationStatus,
  getStorageMode,
  setStorageMode,
  migrateStorageMode,
  clearAllAuthStorage,
  AUTH_STORAGE_KEY,
  StorageMode,
} from '../lib/supabaseClient';

export interface LoginResult {
  success: boolean;
  error?: string;
}

export interface RegisterResult {
  success: boolean;
  requiresEmailConfirmation?: boolean;
  error?: string;
}

export interface PasswordResetResult {
  success: boolean;
  error?: string;
  accountStatus?: string;
}

export interface AuthContextType {
  currentUser: UserProfile | null;
  isAuthenticated: boolean;
  isAuthReady: boolean;
  loginAs: (role: UserRole, rememberMe?: boolean) => void;
  loginWithCredentials: (email: string, password: string, rememberMe?: boolean) => Promise<LoginResult>;
  register: (email: string, password: string, fullName: string) => Promise<RegisterResult>;
  requestPasswordReset: (email: string) => Promise<{ success: boolean; error?: string }>;
  updatePassword: (newPassword: string) => Promise<PasswordResetResult>;
  isPasswordRecovery: boolean;
  setIsPasswordRecovery: (val: boolean) => void;
  logout: () => Promise<void>;
  switchRoleDemo: (role: UserRole) => void;
  rememberMe: boolean;
  setRememberMe: (val: boolean) => void;
  verifyEmailOtp: (tokenHash: string, type?: 'signup' | 'email') => Promise<{ success: boolean; error?: string }>;
}

const isProd = Boolean(import.meta.env?.PROD);
const configStatus = getSupabaseConfigurationStatus();
const isOfflineDemoMode = !configStatus.configured && !isProd;

/**
 * Resolves a canonical application redirect URL.
 * Prefers VITE_APP_URL if defined, falling back safely to the active window.location.origin.
 */
export function getCanonicalRedirectUrl(route: string): string | undefined {
  if (typeof window === 'undefined') return undefined;
  const explicitAppUrl = (import.meta.env?.VITE_APP_URL as string | undefined)?.trim();
  let baseOrigin = window.location.origin;
  if (explicitAppUrl) {
    try {
      baseOrigin = new URL(explicitAppUrl).origin;
    } catch {
      baseOrigin = window.location.origin;
    }
  }
  const cleanRoute = route.replace(/^[#/]+/, '');
  return `${baseOrigin}/#${cleanRoute}`;
}

function safeStoreDemo(profile: UserProfile | null, rememberMe?: boolean): void {
  if (typeof window === 'undefined') return;
  try {
    if (!profile) {
      window.sessionStorage?.removeItem(AUTH_STORAGE_KEY);
      window.localStorage?.removeItem(AUTH_STORAGE_KEY);
      return;
    }

    const mode = rememberMe !== undefined ? (rememberMe ? 'local' : 'session') : getStorageMode();
    if (mode === 'session') {
      window.sessionStorage?.setItem(AUTH_STORAGE_KEY, JSON.stringify(profile));
      window.localStorage?.removeItem(AUTH_STORAGE_KEY);
    } else {
      window.localStorage?.setItem(AUTH_STORAGE_KEY, JSON.stringify(profile));
      window.sessionStorage?.removeItem(AUTH_STORAGE_KEY);
    }
  } catch {
    // Ignore storage restrictions in private browsing or sandboxed iframes
  }
}

function safeRemoveStoredDemo(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage?.removeItem(AUTH_STORAGE_KEY);
    window.localStorage?.removeItem(AUTH_STORAGE_KEY);
  } catch {
    // Ignore storage restrictions
  }
}

function getInitialUser(): UserProfile | null {
  if (typeof window === 'undefined') return null;

  // In production, never restore unverified demo personas from storage
  if (isProd) {
    safeRemoveStoredDemo();
    return null;
  }

  // In offline demo mode, restore stored persona according to active storage mode
  if (isOfflineDemoMode) {
    try {
      const mode = getStorageMode();
      const stored =
        mode === 'session'
          ? window.sessionStorage?.getItem(AUTH_STORAGE_KEY)
          : window.localStorage?.getItem(AUTH_STORAGE_KEY);

      // Defensively purge localStorage token when in session mode
      if (mode === 'session') {
        window.localStorage?.removeItem(AUTH_STORAGE_KEY);
      }

      if (stored) {
        const parsed = JSON.parse(stored) as UserProfile;
        if (parsed && parsed.id && parsed.role && parsed.accountStatus === 'approved') {
          return parsed;
        }
      }
    } catch {
      // Ignore parse failure
    }
    return DEMO_PERSONAS.soc_analyst;
  }

  return null;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(getInitialUser);
  const [isAuthReady, setIsAuthReady] = useState<boolean>(isOfflineDemoMode);
  const [rememberMe, setRememberMeState] = useState<boolean>(() => getStorageMode() === 'local');
  const [isPasswordRecovery, setIsPasswordRecovery] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    const hash = window.location.hash || '';
    return hash.includes('type=recovery') || hash.includes('reset-password');
  });
  const sessionGenerationRef = useRef(0);

  const setRememberMe = (val: boolean): void => {
    setRememberMeState(val);
    const targetMode: StorageMode = val ? 'local' : 'session';
    if (currentUser) {
      // User is currently authenticated: migrate persisted session tokens between storage tiers
      // so active in-memory session, reload restoration, and subsequent auto-refreshes remain synchronized
      migrateStorageMode(targetMode);
      safeStoreDemo(currentUser, val);
    } else {
      // Not authenticated: update storage mode preference directly
      setStorageMode(targetMode);
    }
  };

  useEffect(() => {
    if (!isSupabaseConfigured() || !supabase) {
      if (isOfflineDemoMode && !currentUser) {
        const initial = getInitialUser();
        if (initial) setCurrentUser(initial);
      }
      setIsAuthReady(true);
      return;
    }

    const client = supabase;
    let isMounted = true;

    const mapProfile = (row: any): UserProfile => ({
      id: row.id,
      name: row.name || row.email,
      email: row.email,
      role: row.role,
      callsign: row.callsign || 'OPERATOR',
      title: row.title || 'Security Operator',
      avatarUrl: row.avatar_url || undefined,
      accountStatus: row.account_status,
      approvedBy: row.approved_by,
      approvedAt: row.approved_at,
      createdAt: row.created_at,
      lastAuditId: row.last_audit_id,
    });

    const syncSessionUser = async (userId: string, generation: number) => {
      try {
        const { data: profile, error } = await client
          .from('user_profiles')
          .select('*')
          .eq('id', userId)
          .single();

        // 1. Invalidation checks: component unmounted or newer session generation started
        if (!isMounted || sessionGenerationRef.current !== generation) {
          return;
        }

        // 2. Double-check session is still active and belongs to the same user
        const { data: activeSessionData } = await client.auth.getSession();
        if (!isMounted || sessionGenerationRef.current !== generation) {
          return;
        }
        if (!activeSessionData.session?.user || activeSessionData.session.user.id !== userId) {
          console.warn('[CyberOps SOC] Stale session profile response discarded: user changed or signed out.');
          return;
        }

        if (error || !profile) {
          console.warn('[CyberOps SOC] Profile not found for authenticated user. Failing closed.');
          sessionGenerationRef.current += 1;
          // Defer signOut outside callback to avoid auth lock contention
          setTimeout(() => {
            client.auth.signOut().catch(() => {});
          }, 0);
          if (!isMounted || sessionGenerationRef.current !== generation + 1) return;
          setCurrentUser(null);
          safeRemoveStoredDemo();
          setIsAuthReady(true);
          return;
        }

        if (profile.account_status !== 'approved' || !profile.role) {
          console.warn(
            `[CyberOps SOC] User ${profile.email} has status "${profile.account_status}" and role "${profile.role}". Workspace access denied.`
          );
          sessionGenerationRef.current += 1;
          setTimeout(() => {
            client.auth.signOut().catch(() => {});
          }, 0);
          if (!isMounted || sessionGenerationRef.current !== generation + 1) return;
          setCurrentUser(null);
          safeRemoveStoredDemo();
          setIsAuthReady(true);
          return;
        }

        const mapped = mapProfile(profile);
        setCurrentUser(mapped);
        setIsAuthReady(true);
      } catch (err) {
        if (!isMounted || sessionGenerationRef.current !== generation) return;
        console.error('[CyberOps SOC] Error syncing session profile:', err);
        setCurrentUser(null);
        safeRemoveStoredDemo();
        setIsAuthReady(true);
      }
    };

    const initialGen = ++sessionGenerationRef.current;
    client.auth.getSession().then(({ data: { session } }) => {
      if (!isMounted || sessionGenerationRef.current !== initialGen) return;
      if (session?.user) {
        syncSessionUser(session.user.id, initialGen);
      } else {
        setCurrentUser(null);
        safeRemoveStoredDemo();
        setIsAuthReady(true);
      }
    }).catch((err) => {
      if (!isMounted || sessionGenerationRef.current !== initialGen) return;
      console.error('[CyberOps SOC] Error checking initial session:', err);
      setCurrentUser(null);
      safeRemoveStoredDemo();
      setIsAuthReady(true);
    });

    const {
      data: { subscription },
    } = client.auth.onAuthStateChange((event, session) => {
      if (!isMounted) return;
      if (event === 'PASSWORD_RECOVERY') {
        setIsPasswordRecovery(true);
        // Do not sync as normal workspace session before explicit password reset
        return;
      }
      const currentGen = ++sessionGenerationRef.current;
      if (event === 'SIGNED_OUT' || !session?.user) {
        setCurrentUser(null);
        safeRemoveStoredDemo();
        setIsAuthReady(true);
      } else if (session?.user) {
        syncSessionUser(session.user.id, currentGen);
      }
    });

    return () => {
      isMounted = false;
      sessionGenerationRef.current += 1;
      subscription.unsubscribe();
    };
  }, []);

  const loginAs = (role: UserRole, isRemember: boolean = rememberMe): void => {
    if (!isOfflineDemoMode) {
      console.warn(
        '[CyberOps SOC Security Warning] Fast persona login is available only in offline development mode.'
      );
      return;
    }
    setStorageMode(isRemember ? 'local' : 'session');
    const profile = DEMO_PERSONAS[role];
    if (!profile) return;
    setCurrentUser(profile);
    safeStoreDemo(profile, isRemember);
  };

  const loginWithCredentials = async (
    email: string,
    pass: string,
    isRemember: boolean = rememberMe
  ): Promise<LoginResult> => {
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail || !pass) {
      return { success: false, error: 'Email and password are required.' };
    }

    // Set storage mode before issuing the login request.
    // If isRemember is false, this immediately purges stale persistent tokens from localStorage.
    setStorageMode(isRemember ? 'local' : 'session');

    if (isSupabaseConfigured() && supabase) {
      const client = supabase;
      sessionGenerationRef.current += 1;
      try {
        // Safely reset any prior in-memory session or refresh timers without revoking external devices
        await client.auth.signOut({ scope: 'local' }).catch(() => {});
        // Re-enforce storage mode after clean local sign out
        setStorageMode(isRemember ? 'local' : 'session');

        const { data, error } = await client.auth.signInWithPassword({
          email: cleanEmail,
          password: pass,
        });

        if (error) {
          return { success: false, error: error.message };
        }

        if (!data?.user) {
          return { success: false, error: 'Authentication failed. Please verify your credentials.' };
        }

        const { data: profile, error: profileErr } = await client
          .from('user_profiles')
          .select('*')
          .eq('id', data.user.id)
          .single();

        if (profileErr || !profile) {
          await client.auth.signOut().catch(() => {});
          setCurrentUser(null);
          safeRemoveStoredDemo();
          return {
            success: false,
            error: 'User profile not found. Please contact a platform administrator.',
          };
        }

        if (profile.account_status !== 'approved') {
          await client.auth.signOut().catch(() => {});
          setCurrentUser(null);
          safeRemoveStoredDemo();

          if (profile.account_status === 'pending') {
            return {
              success: false,
              error: 'Your account registration is pending administrator approval.',
            };
          }
          if (profile.account_status === 'disabled') {
            return {
              success: false,
              error: 'This account has been disabled. Please contact an administrator.',
            };
          }
          if (profile.account_status === 'rejected') {
            return {
              success: false,
              error: 'This account application was rejected. Please contact security operations.',
            };
          }
          return {
            success: false,
            error: 'Account is not approved for operational access.',
          };
        }

        if (!profile.role) {
          await client.auth.signOut().catch(() => {});
          setCurrentUser(null);
          safeRemoveStoredDemo();
          return {
            success: false,
            error: 'Your account does not have an active operational role assigned.',
          };
        }

        const userProfile: UserProfile = {
          id: profile.id,
          name: profile.name || cleanEmail,
          email: profile.email || cleanEmail,
          role: profile.role,
          callsign: profile.callsign || 'OPERATOR',
          title: profile.title || 'Security Operator',
          avatarUrl: profile.avatar_url || undefined,
          accountStatus: profile.account_status,
          approvedBy: profile.approved_by,
          approvedAt: profile.approved_at,
          createdAt: profile.created_at,
          lastAuditId: profile.last_audit_id,
        };

        setCurrentUser(userProfile);
        safeStoreDemo(userProfile);
        return { success: true };
      } catch (err: any) {
        return {
          success: false,
          error: err?.message || 'Authentication failed due to a network or service error.',
        };
      }
    }

    if (isOfflineDemoMode) {
      const persona = Object.values(DEMO_PERSONAS).find(
        (p) => p.email.toLowerCase() === cleanEmail
      );
      if (persona) {
        setCurrentUser(persona);
        safeStoreDemo(persona);
        return { success: true };
      }
      return {
        success: false,
        error: `User not found in demo personas. Try one of: ${Object.values(DEMO_PERSONAS).map((p) => p.email).join(', ')}`,
      };
    }

    return {
      success: false,
      error: 'Authentication service unavailable in unconfigured production mode.',
    };
  };

  const register = async (
    email: string,
    pass: string,
    fullName: string
  ): Promise<RegisterResult> => {
    const cleanEmail = email.trim().toLowerCase();
    const cleanName = fullName.trim();

    if (!cleanEmail || !cleanName || !pass) {
      return { success: false, error: 'All fields are required.' };
    }

    if (pass.length < 8) {
      return { success: false, error: 'Password must be at least 8 characters long.' };
    }

    if (!isSupabaseConfigured() || !supabase) {
      if (isOfflineDemoMode) {
        return { success: true, requiresEmailConfirmation: false };
      }
      return {
        success: false,
        error: 'Registration service is unavailable in unconfigured production mode.',
      };
    }

    const client = supabase;

    try {
      const emailRedirectTo = getCanonicalRedirectUrl('login');

      const { data, error } = await client.auth.signUp({
        email: cleanEmail,
        password: pass,
        options: {
          emailRedirectTo,
          data: {
            full_name: cleanName,
          },
        },
      });

      if (error) {
        if (error.message.toLowerCase().includes('already registered')) {
          return {
            success: false,
            error: 'An account with this email address already exists. Please sign in or reset your password.',
          };
        }

        return { success: false, error: error.message };
      }

      if (!data?.user) {
        return { success: false, error: 'Registration did not return a user. Please try again.' };
      }

      if (Array.isArray(data.user.identities) && data.user.identities.length === 0) {
        return {
          success: false,
          error: 'An account with this email address already exists. Please sign in or reset your password.',
        };
      }

      if (data.session) {
        // A profile trigger may create this row. This insert is best-effort and
        // must never grant a role or approve the account.
        const callsign =
          cleanName.replace(/[^a-zA-Z0-9]/g, '').slice(0, 8).toUpperCase() || 'OPERATOR';

        const { error: insertError } = await client.from('user_profiles').insert({
          id: data.user.id,
          email: cleanEmail,
          name: cleanName,
          role: null,
          account_status: 'pending',
          callsign,
          title: 'Pending Operator',
        });

        // A duplicate row can mean the database trigger already created it.
        // Other insert errors should be surfaced rather than silently ignored.
        if (insertError && insertError.code !== '23505') {
          await client.auth.signOut().catch(() => {});
          setCurrentUser(null);
          safeRemoveStoredDemo();
          return {
            success: false,
            error: 'Your account was created, but its pending profile could not be verified. Please contact an administrator.',
          };
        }

        setCurrentUser(null);
        safeRemoveStoredDemo();
        await client.auth.signOut().catch(() => {});
        return { success: true, requiresEmailConfirmation: false };
      }

      return { success: true, requiresEmailConfirmation: true };
    } catch {
      return {
        success: false,
        error: 'Registration failed due to a network or service error.',
      };
    }
  };

  const requestPasswordReset = async (
    email: string
  ): Promise<{ success: boolean; error?: string }> => {
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes('@')) {
      return { success: false, error: 'Please provide a valid enterprise email address.' };
    }

    if (!isSupabaseConfigured() || !supabase) {
      if (isOfflineDemoMode) {
        // In offline demo mode, simulate successful recovery request
        return { success: true };
      }
      return {
        success: false,
        error: 'Password recovery service unavailable in unconfigured production mode.',
      };
    }

    const client = supabase;
    try {
      const emailRedirectTo = getCanonicalRedirectUrl('reset-password');

      const { error } = await client.auth.resetPasswordForEmail(cleanEmail, {
        redirectTo: emailRedirectTo,
      });

      if (error) {
        const msg = error.message.toLowerCase();
        if (msg.includes('rate limit') || msg.includes('too many requests')) {
          return {
            success: false,
            error: 'Too many recovery requests. Please wait a few moments before trying again.',
          };
        }
        // Neutral response for security: do not disclose account presence or internal errors
        return { success: true };
      }

      return { success: true };
    } catch {
      // Return neutral confirmation to prevent enumeration
      return { success: true };
    }
  };

  const updatePassword = async (
    newPassword: string
  ): Promise<PasswordResetResult> => {
    if (!newPassword || newPassword.length < 8) {
      return { success: false, error: 'Password must be at least 8 characters long.' };
    }

    if (!isSupabaseConfigured() || !supabase) {
      if (isOfflineDemoMode) {
        setIsPasswordRecovery(false);
        return { success: true, accountStatus: 'approved' };
      }
      return {
        success: false,
        error: 'Authentication service unavailable in unconfigured production mode.',
      };
    }

    const client = supabase;
    try {
      const { data, error } = await client.auth.updateUser({
        password: newPassword,
      });

      if (error) {
        return { success: false, error: error.message };
      }

      if (!data?.user) {
        return {
          success: false,
          error: 'Password reset session is invalid or has expired. Please request a new recovery link.',
        };
      }

      // Check profile status to ensure recovery never grants unauthorized workspace access
      const { data: profile } = await client
        .from('user_profiles')
        .select('account_status, role')
        .eq('id', data.user.id)
        .single();

      const accountStatus = profile?.account_status || 'pending';

      // Always clear recovery session and sign out to force clean login with selected Remember Me settings
      sessionGenerationRef.current += 1;
      await client.auth.signOut().catch(() => {});
      setCurrentUser(null);
      safeRemoveStoredDemo();
      clearAllAuthStorage();
      setIsPasswordRecovery(false);

      return { success: true, accountStatus };
    } catch (err: any) {
      return {
        success: false,
        error: err?.message || 'Password update failed. Please try again.',
      };
    }
  };

  const logout = async (): Promise<void> => {
    const logoutGen = ++sessionGenerationRef.current;
    setCurrentUser(null);
    safeRemoveStoredDemo();
    clearAllAuthStorage();
    setIsAuthReady(true);

    if (typeof window !== 'undefined') {
      try {
        sessionStorage.removeItem('cyberops_soc_in_workspace');
        sessionStorage.removeItem('cyberops_soc_workspace_view');
        sessionStorage.removeItem('cyberops_soc_public_route');
      } catch {
        // Ignore storage errors in restricted contexts
      }
    }

    if (isSupabaseConfigured() && supabase) {
      const client = supabase;
      try {
        await client.auth.signOut();
      } catch (err) {
        // Local UI state remains cleared even if remote sign-out fails.
        console.warn('[CyberOps SOC] Remote signOut threw:', err);
      } finally {
        // Defensively ensure storage is cleared even if an in-flight token refresh
        // attempted to write tokens during signOut execution
        clearAllAuthStorage();
        if (sessionGenerationRef.current === logoutGen) {
          setCurrentUser(null);
          safeRemoveStoredDemo();
        }
      }
    }
  };

  const switchRoleDemo = (role: UserRole): void => {
    if (!isOfflineDemoMode) {
      console.warn(
        '[CyberOps SOC Security Warning] Demo role switching is available only in offline development mode.'
      );
      return;
    }

    const profile = DEMO_PERSONAS[role];
    if (!profile) return;

    setCurrentUser(profile);
    safeStoreDemo(profile, rememberMe);
  };

  const verifyEmailOtp = async (
    tokenHash: string,
    type: 'signup' | 'email' = 'signup'
  ): Promise<{ success: boolean; error?: string }> => {
    if (!tokenHash || !tokenHash.trim()) {
      return { success: false, error: 'Verification token is missing or malformed.' };
    }

    if (!isSupabaseConfigured() || !supabase) {
      if (isOfflineDemoMode) {
        return { success: true };
      }
      return {
        success: false,
        error: 'Authentication service unavailable in unconfigured production mode.',
      };
    }

    const client = supabase;
    try {
      const { data, error } = await client.auth.verifyOtp({
        token_hash: tokenHash.trim(),
        type: type === 'email' ? 'email' : 'signup',
      });

      if (error) {
        return { success: false, error: error.message };
      }

      // If user profile is not approved, sign out locally so no unauthorized workspace state remains
      if (data?.session?.user) {
        const { data: profile } = await client
          .from('user_profiles')
          .select('account_status, role')
          .eq('id', data.session.user.id)
          .single();

        if (!profile || profile.account_status !== 'approved' || !profile.role) {
          sessionGenerationRef.current += 1;
          await client.auth.signOut().catch(() => {});
          setCurrentUser(null);
          safeRemoveStoredDemo();
        }
      }

      return { success: true };
    } catch (err: any) {
      return {
        success: false,
        error: err?.message || 'Email verification failed due to a network error.',
      };
    }
  };

  return (
    <AuthContext.Provider
      value={{
        currentUser,
        isAuthenticated: !!currentUser,
        isAuthReady,
        loginAs,
        loginWithCredentials,
        register,
        requestPasswordReset,
        updatePassword,
        isPasswordRecovery,
        setIsPasswordRecovery,
        logout,
        switchRoleDemo,
        rememberMe,
        setRememberMe,
        verifyEmailOtp,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
