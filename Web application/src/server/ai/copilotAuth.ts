/**
 * CyberOps SOC — Server-Side Copilot Authentication Middleware
 *
 * Enforces cryptographic session verification via Supabase.
 * Strictly prevents role-spoofing via headers (x-user-role), query parameters (?role=),
 * or client-supplied request bodies.
 *
 * Security Invariants:
 * 1. Requires "Authorization: Bearer <token>" on all Copilot API calls.
 * 2. In Live Supabase mode:
 *    - Cryptographically verifies JWT with Supabase auth service.
 *    - Retrieves authoritative role and account status from PostgreSQL `user_profiles` table.
 *    - Requires account_status === 'approved'.
 * 3. In Development/Demo mode (when Supabase is unconfigured):
 *    - Rejects requests with HTTP 401 because client localStorage demo personas are not
 *      cryptographically verifiable by the server. This prevents creating an unauthenticated
 *      public AI proxy.
 * 4. Supports dependency-injected token verifier for deterministic testing.
 */

import { Request, Response, NextFunction } from 'express';
import { createClient } from '@supabase/supabase-js';
import { UserProfile, UserRole } from '../../types/auth';
import { isSupabaseConfigured } from '../../lib/supabaseClient';

export interface AuthenticatedRequest extends Request {
  user?: UserProfile;
}

export type TokenVerifier = (token: string) => Promise<UserProfile | null>;

const VALID_ROLES: UserRole[] = [
  'soc_analyst',
  'security_engineer',
  'it_operations',
  'super_admin',
];

export interface SupabaseTokenVerifierDependencies {
  authClient?: {
    getUser: (token: string) => Promise<{ data: { user: { id: string } | null } | null; error: unknown }>;
  };
  profileQueryRunner?: (
    userId: string,
    token: string,
    hasServiceRoleKey: boolean
  ) => Promise<{ data: any; error: unknown }>;
}

/**
 * Evaluates whether Supabase authentication is properly configured in the server environment.
 * Accepts either:
 * - Privileged service role key (SUPABASE_SERVICE_ROLE_KEY)
 * - Legacy anon JWT key (VITE_SUPABASE_ANON_KEY)
 * - Modern publishable key (VITE_SUPABASE_PUBLISHABLE_KEY)
 * along with a valid, non-placeholder HTTP/HTTPS Supabase URL (VITE_SUPABASE_URL or SUPABASE_URL).
 */
export function isSupabaseAuthConfigured(): boolean {
  const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const clientKey = process.env.VITE_SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const supabaseKey = (serviceRoleKey && serviceRoleKey.trim() !== '') ? serviceRoleKey : clientKey;

  return Boolean(supabaseUrl && supabaseKey && isSupabaseConfigured(supabaseUrl, supabaseKey));
}

/**
 * Creates a Supabase token verifier using server environment variables.
 * Under live Supabase deployment:
 * 1. Cryptographically verifies caller's JWT token via authClient.getUser(token).
 * 2. If SUPABASE_SERVICE_ROLE_KEY is present, queries user_profiles via authorized server identity.
 *    If only public client key (VITE_SUPABASE_ANON_KEY or VITE_SUPABASE_PUBLISHABLE_KEY) is present, scopes the query client with the caller's verified
 *    JWT in "Authorization: Bearer <token>" so PostgreSQL evaluates `auth.uid() = id` under profiles_select_policy.
 * 3. Enforces account_status === 'approved' and authoritative role assignment.
 */
export function createSupabaseTokenVerifier(deps?: SupabaseTokenVerifierDependencies): TokenVerifier {
  const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const anonKey = process.env.VITE_SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const supabaseKey = serviceRoleKey || anonKey;
  const hasServiceRoleKey = Boolean(serviceRoleKey && serviceRoleKey.trim() !== '');

  if (!deps && !isSupabaseAuthConfigured()) {
    return async () => null;
  }

  const defaultAuthClient = (supabaseUrl && supabaseKey)
    ? createClient(supabaseUrl, supabaseKey, {
        auth: {
          autoRefreshToken: false,
          persistSession: false,
        },
      }).auth
    : undefined;

  const authClient = deps?.authClient || defaultAuthClient;

  const defaultProfileQueryRunner = async (
    userId: string,
    token: string,
    isServiceRole: boolean
  ): Promise<{ data: any; error: unknown }> => {
    // If server has service role key, query with privileged server client.
    // Otherwise, execute query with caller's verified JWT so PostgreSQL RLS
    // profiles_select_policy permits the select based on `auth.uid() = id`.
    const queryClient = isServiceRole
      ? createClient(supabaseUrl!, serviceRoleKey!, {
          auth: { autoRefreshToken: false, persistSession: false },
        })
      : createClient(supabaseUrl!, anonKey || supabaseKey!, {
          global: {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          },
          auth: { autoRefreshToken: false, persistSession: false },
        });

    return queryClient
      .from('user_profiles')
      .select('*')
      .eq('id', userId)
      .single();
  };

  const profileQueryRunner = deps?.profileQueryRunner || defaultProfileQueryRunner;

  return async (token: string): Promise<UserProfile | null> => {
    try {
      if (!authClient) return null;

      // 1. Cryptographically verify bearer token
      const { data: authData, error: authError } = await authClient.getUser(token);
      if (authError || !authData?.user) {
        return null;
      }

      const userId = authData.user.id;

      // 2. Query authoritative user profile from database under caller JWT context (or service role)
      const { data: profileRow, error: profileError } = await profileQueryRunner(
        userId,
        token,
        hasServiceRoleKey
      );

      if (profileError || !profileRow) {
        return null;
      }

      // 3. Verify account is approved
      if (profileRow.account_status !== 'approved') {
        return {
          id: profileRow.id,
          name: profileRow.name || profileRow.email,
          email: profileRow.email,
          role: profileRow.role,
          callsign: profileRow.callsign || 'OPERATOR',
          title: profileRow.title || 'Security Operator',
          accountStatus: profileRow.account_status,
        };
      }

      // 4. Return profile even if role is not recognized so middleware can explicitly reject with HTTP 403 INVALID_ROLE
      return {
        id: profileRow.id,
        name: profileRow.name || profileRow.email,
        email: profileRow.email,
        role: profileRow.role,
        callsign: profileRow.callsign || 'OPERATOR',
        title: profileRow.title || 'Security Operator',
        accountStatus: 'approved',
      };
    } catch {
      return null;
    }
  };
}

/**
 * Express middleware to authenticate Copilot requests.
 */
export function authenticateCopilotRequest(customVerifier?: TokenVerifier) {
  const verifier = customVerifier || createSupabaseTokenVerifier();

  return async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    // 1. Extract Bearer token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || (!authHeader.startsWith('Bearer ') && authHeader.trim() !== 'Bearer')) {
      res.status(401).json({
        error: 'Authentication required: Missing or malformed Authorization header. Expected Bearer token.',
        code: 'UNAUTHENTICATED',
      });
      return;
    }

    const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7).trim() : '';
    if (!token) {
      res.status(401).json({
        error: 'Authentication required: Empty Bearer token.',
        code: 'EMPTY_TOKEN',
      });
      return;
    }

    // 2. Explicitly guard against client attempting role spoofing via headers, queries, or body
    // Even if client passes x-user-role, ?role=, or body.role, we completely ignore it.

    // 3. Check if server has Supabase configured (or custom verifier provided)
    const isConfigured = Boolean(customVerifier || isSupabaseAuthConfigured());

    if (!isConfigured) {
      res.status(401).json({
        error:
          'Copilot authentication unavailable: Offline development demo mode does not have a server-verifiable session mechanism. Live Supabase authentication with an approved account is required for AI Copilot access.',
        code: 'DEMO_MODE_AUTHENTICATION_UNAVAILABLE',
      });
      return;
    }

    // 4. Verify token
    try {
      const user = await verifier(token);

      if (!user) {
        res.status(401).json({
          error: 'Authentication failed: Invalid, expired, or unverified session token.',
          code: 'INVALID_TOKEN',
        });
        return;
      }

      if (user.accountStatus !== 'approved') {
        res.status(403).json({
          error: `Access denied: Operator account is not approved (status: "${user.accountStatus || 'unknown'}").`,
          code: 'ACCOUNT_NOT_APPROVED',
        });
        return;
      }

      if (!VALID_ROLES.includes(user.role)) {
        res.status(403).json({
          error: `Access denied: Role "${user.role}" is not recognized or authorized for Copilot access.`,
          code: 'INVALID_ROLE',
        });
        return;
      }

      // Attach verified profile to request
      req.user = user;
      next();
    } catch {
      res.status(500).json({
        error: 'Authentication verification error.',
        code: 'AUTH_VERIFICATION_ERROR',
      });
    }
  };
}
