/**
 * CyberOps SOC — Client-Side AI Security Copilot Service
 *
 * Communicates exclusively with the authoritative server-side endpoint:
 *   POST /api/copilot/chat
 *   GET /api/copilot/status
 *
 * Security Invariants:
 * 1. Never imports @google/genai or references GEMINI_API_KEY on the client.
 * 2. Extracts JWT bearer tokens strictly from verified Supabase session state.
 * 3. Never sends client-asserted roles or permissions; backend role derivation is authoritative.
 * 4. Fails safely on 401, 403, 429, 503, 504 and network errors without fabricating fake AI text.
 */

import { supabase, isSupabaseConfigured } from '../lib/supabaseClient';
import {
  CopilotChatRequest,
  CopilotChatResponse,
  CopilotStatusResponse,
  CopilotContextType,
} from '../server/ai/types';

export interface CopilotApiError {
  status: number;
  code: string;
  message: string;
  retryAfterSeconds?: number;
  requiredPermission?: string;
}

export class CopilotClientError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly retryAfterSeconds?: number;
  public readonly requiredPermission?: string;

  constructor(error: CopilotApiError) {
    super(error.message);
    this.name = 'CopilotClientError';
    this.status = error.status;
    this.code = error.code;
    this.retryAfterSeconds = error.retryAfterSeconds;
    this.requiredPermission = error.requiredPermission;
  }
}

/**
 * Retrieves the current caller's access token from the active session.
 */
export async function getClientAccessToken(): Promise<string | null> {
  if (!isSupabaseConfigured() || !supabase) {
    return null;
  }
  try {
    const { data } = await supabase.auth.getSession();
    return data.session?.access_token || null;
  } catch {
    return null;
  }
}

/**
 * Checks Copilot operational status from GET /api/copilot/status.
 */
export async function fetchCopilotStatus(tokenOverride?: string): Promise<CopilotStatusResponse> {
  const token = tokenOverride !== undefined ? tokenOverride : await getClientAccessToken();
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch('/api/copilot/status', {
    method: 'GET',
    headers,
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new CopilotClientError({
      status: response.status,
      code: payload.code || 'STATUS_ERROR',
      message: payload.error || `Status request failed with HTTP ${response.status}`,
    });
  }

  return payload as CopilotStatusResponse;
}

/**
 * Dispatches an advisory chat prompt to POST /api/copilot/chat.
 */
export async function sendCopilotMessage(
  request: CopilotChatRequest,
  tokenOverride?: string
): Promise<CopilotChatResponse> {
  const token = tokenOverride !== undefined ? tokenOverride : await getClientAccessToken();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    response = await fetch('/api/copilot/chat', {
      method: 'POST',
      headers,
      body: JSON.stringify(request),
    });
  } catch (netErr: any) {
    throw new CopilotClientError({
      status: 0,
      code: 'NETWORK_FAILURE',
      message: 'Network error: Unable to reach CyberOps SOC Copilot service.',
    });
  }

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const retryAfterHeader = response.headers.get('Retry-After');
    const retryAfterSeconds = retryAfterHeader ? parseInt(retryAfterHeader, 10) : undefined;

    throw new CopilotClientError({
      status: response.status,
      code: payload.code || 'API_ERROR',
      message: payload.error || `Copilot request failed with HTTP ${response.status}`,
      retryAfterSeconds,
      requiredPermission: payload.requiredPermission,
    });
  }

  return payload as CopilotChatResponse;
}
