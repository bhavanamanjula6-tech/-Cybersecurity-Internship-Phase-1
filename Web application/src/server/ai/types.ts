/**
 * CyberOps SOC — Server-Side AI Copilot Types & Interfaces
 *
 * Defines request/response contracts, context types, and safety envelopes.
 */

import { UserRole } from '../../types/auth';

export type CopilotContextType =
  | 'alert_triage'
  | 'mitre_analysis'
  | 'remediation_task'
  | 'platform_health'
  | 'general_soc';

export interface CopilotChatRequest {
  prompt: string;
  contextType: CopilotContextType;
  entityId?: string;
}

export interface CopilotChatResponse {
  response: string;
  text?: string;
  role: UserRole;
  contextType: CopilotContextType;
  entityId?: string;
  isAdvisory: true;
  disclaimer: string;
  timestamp: string;
}

export interface AssembledContext {
  systemInstruction: string;
  assembledContent: string;
  redactedFields: string[];
}

export interface CopilotBaseStatusResponse {
  status: 'online';
  modelConfigured: boolean;
  role: UserRole;
}

export interface CopilotAdminStatusResponse extends CopilotBaseStatusResponse {
  metrics: {
    activeRequests: number;
    maxConcurrency: number;
    trackedUsers: number;
  };
}

export type CopilotStatusResponse = CopilotBaseStatusResponse | CopilotAdminStatusResponse;
