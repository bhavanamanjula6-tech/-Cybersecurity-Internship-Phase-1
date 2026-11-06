/**
 * CyberOps SOC — Super Admin Reference Datasets Aggregate Service
 *
 * Provides typed, authenticated execution of the `public.get_reference_datasets_summary()` RPC.
 *
 * Security & Boundary Invariants:
 * 1. Invokes strictly the `get_reference_datasets_summary` RPC via the Supabase client.
 * 2. Enforces defense-in-depth: Caller must be an approved 'super_admin' user evaluated strictly
 *    before client resolution or initiating any RPC request.
 * 3. Never executes direct SELECT, INSERT, UPDATE, or DELETE on the underlying knowledge tables.
 * 4. Never touches private operational alerts, incident tasks, or analyst notes.
 * 5. Validates payload integrity through strict runtime contract verification before returning data.
 * 6. Supports properly typed client injection (`clientOverride?: AggregateRpcClient`) for offline testing.
 * 7. Comprehensive Error Sanitization:
 *    - Intercepts all failure paths: client initialization errors, synchronous exceptions, rejected promises
 *      (e.g. network/connection drops, CORS, fetch errors), and Supabase PostgREST error responses.
 *    - Consistently throws strictly the safe user-facing error message with zero raw database details,
 *      SQL queries, schema names, error codes, hints, stack traces, or Error.cause attachments.
 *    - Runs client-side in the browser: suppresses raw diagnostics to ensure no untrusted browser callbacks
 *      or DevTools console logs receive raw database internals.
 */

import { getSupabaseClient } from '../lib/supabaseClient';
import { UserProfile, AccessDeniedError } from '../types/auth';
import {
  ReferenceDatasetsSummaryResponse,
  validateReferenceDatasetsSummary,
} from '../types/superAdminAggregate';

export const SAFE_RPC_ERROR_MESSAGE =
  'Failed to retrieve reference datasets summary. An unexpected error occurred while processing the request.';

export interface AggregateRpcResponse {
  data: unknown;
  error: { message: string; code?: string; details?: string; hint?: string } | null;
}

export interface AggregateRpcClient {
  rpc: (
    fnName: string,
    args?: Record<string, unknown>
  ) => PromiseLike<AggregateRpcResponse> | Promise<AggregateRpcResponse>;
}

export interface AggregateServiceResult {
  data: ReferenceDatasetsSummaryResponse | null;
  error: string | null;
  isLoading: boolean;
}

/**
 * Narrow adapter converting the production SupabaseClient into the AggregateRpcClient interface.
 * Avoids unsafe casts while preserving exact production RPC behavior.
 */
function createProductionAggregateRpcClient(): AggregateRpcClient {
  const supabase = getSupabaseClient();
  return {
    rpc: async (fnName: string, args?: Record<string, unknown>): Promise<AggregateRpcResponse> => {
      const response = await supabase.rpc(fnName, args);
      return {
        data: response.data,
        error: response.error
          ? {
              message: response.error.message,
              code: response.error.code,
              details: (response.error as { details?: string }).details,
              hint: (response.error as { hint?: string }).hint,
            }
          : null,
      };
    },
  };
}

/**
 * Executes the `get_reference_datasets_summary` RPC for authorized Super Admin users.
 *
 * @param user The authenticated user profile invoking the RPC.
 * @param clientOverride Optional client override conforming to AggregateRpcClient for testing.
 * @returns Typed summary response containing scalar metrics and Top 5 distributions.
 * @throws AccessDeniedError if the user is unapproved or lacks the super_admin role (evaluated prior to client resolution).
 * @throws Error with exactly SAFE_RPC_ERROR_MESSAGE if client creation fails, network fails, database rejects execution, or RPC throws.
 * @throws Error if the RPC returns an empty/null payload or payload fails schema validation invariants.
 */
export async function fetchReferenceDatasetsSummary(
  user: UserProfile,
  clientOverride?: AggregateRpcClient
): Promise<ReferenceDatasetsSummaryResponse> {
  // 1. Defense-in-depth authorization gate (evaluated strictly BEFORE resolving client or calling RPC)
  if (!user || user.accountStatus !== 'approved') {
    throw new AccessDeniedError(
      'Account must be approved by an administrator to query platform reference datasets.',
      'platform:health_read',
      user?.role || 'super_admin'
    );
  }

  if (user.role !== 'super_admin') {
    throw new AccessDeniedError(
      `Role "${user.role}" is not authorized to query Super Admin aggregate reference datasets.`,
      'platform:health_read',
      user.role
    );
  }

  // 2. Resolve client and execute RPC wrapped in comprehensive error sanitization
  let rpcResponse: AggregateRpcResponse;
  try {
    const client: AggregateRpcClient = clientOverride ?? createProductionAggregateRpcClient();
    rpcResponse = await client.rpc('get_reference_datasets_summary');
  } catch (_rawExecutionError: unknown) {
    // Intercepts client initialization exceptions, synchronous throws, and rejected promises (network/connection failures).
    // Absolutely NO internal details, stacks, error.cause, or raw messages escape to the caller.
    throw new Error(SAFE_RPC_ERROR_MESSAGE);
  }

  // 3. Inspect RPC error response
  if (rpcResponse.error) {
    // Suppress raw database error, SQL details, hints, and error codes.
    throw new Error(SAFE_RPC_ERROR_MESSAGE);
  }

  const { data } = rpcResponse;
  if (!data) {
    throw new Error(
      '[SuperAdminAggregateService] RPC returned an empty or null payload.'
    );
  }

  // 4. Validate response structure against the approved typed contract and invariants
  return validateReferenceDatasetsSummary(data);
}
