/**
 * CyberOps SOC — useCopilot Hook
 *
 * Manages conversational state, active threat context, loading states,
 * and error transitions for the AI Security Copilot drawer.
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import {
  CopilotContextType,
  CopilotChatRequest,
  CopilotChatResponse,
  CopilotStatusResponse,
} from '../server/ai/types';
import {
  sendCopilotMessage,
  fetchCopilotStatus,
  CopilotClientError,
  CopilotApiError,
} from '../services/copilotClientService';

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  contextType?: CopilotContextType;
  entityId?: string;
  isAdvisory?: boolean;
  disclaimer?: string;
  error?: CopilotApiError;
}

export interface UseCopilotProps {
  initialContextType?: CopilotContextType;
  initialEntityId?: string;
}

export function useCopilot({
  initialContextType = 'general_soc',
  initialEntityId,
}: UseCopilotProps = {}) {
  const { currentUser } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<CopilotMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [status, setStatus] = useState<CopilotStatusResponse | null>(null);
  const [isCheckingStatus, setIsCheckingStatus] = useState(false);
  const [statusError, setStatusError] = useState<CopilotApiError | null>(null);

  // Active context state
  const [contextType, setContextType] = useState<CopilotContextType>(initialContextType);
  const [entityId, setEntityId] = useState<string | undefined>(initialEntityId);

  // Sync context when props change
  useEffect(() => {
    if (initialContextType) {
      setContextType(initialContextType);
    }
  }, [initialContextType]);

  useEffect(() => {
    setEntityId(initialEntityId);
  }, [initialEntityId]);

  // Load status when drawer opens or on mount
  const checkStatus = useCallback(async () => {
    try {
      setIsCheckingStatus(true);
      setStatusError(null);
      const res = await fetchCopilotStatus();
      setStatus(res);
    } catch (err: unknown) {
      if (err instanceof CopilotClientError) {
        setStatusError({
          status: err.status,
          code: err.code,
          message: err.message,
          retryAfterSeconds: err.retryAfterSeconds,
          requiredPermission: err.requiredPermission,
        });
      } else {
        setStatusError({
          status: 0,
          code: 'STATUS_UNKNOWN_ERROR',
          message: 'Unable to retrieve Copilot service status.',
        });
      }
    } finally {
      setIsCheckingStatus(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      checkStatus();
    }
  }, [isOpen, checkStatus]);

  const openDrawer = useCallback(() => setIsOpen(true), []);
  const closeDrawer = useCallback(() => setIsOpen(false), []);
  const toggleDrawer = useCallback(() => setIsOpen((prev) => !prev), []);

  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  const sendMessage = useCallback(
    async (
      promptText: string,
      contextOverride?: { contextType: CopilotContextType; entityId?: string }
    ) => {
      const cleanPrompt = promptText.trim();
      if (!cleanPrompt || isLoading) return;

      const activeType = contextOverride?.contextType || contextType;
      const activeEntity = contextOverride?.entityId !== undefined ? contextOverride.entityId : entityId;

      const userMessageId = `msg-usr-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const userMessage: CopilotMessage = {
        id: userMessageId,
        sender: 'user',
        text: cleanPrompt,
        timestamp: new Date().toISOString(),
        contextType: activeType,
        entityId: activeEntity,
      };

      setMessages((prev) => [...prev, userMessage]);
      setIsLoading(true);

      const requestPayload: CopilotChatRequest = {
        prompt: cleanPrompt,
        contextType: activeType,
        entityId: activeEntity || undefined,
      };

      try {
        const responseData: CopilotChatResponse = await sendCopilotMessage(requestPayload);

        const rawText = (responseData.response || responseData.text || '').trim();

        if (!rawText) {
          const errorMessage: CopilotMessage = {
            id: `msg-err-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            sender: 'assistant',
            text: '',
            timestamp: new Date().toISOString(),
            contextType: activeType,
            entityId: activeEntity,
            error: {
              status: 502,
              code: 'EMPTY_RESPONSE',
              message: 'The AI Copilot returned an empty advisory response. Please retry your query.',
            },
          };

          setMessages((prev) => [...prev, errorMessage]);
          return;
        }

        const assistantMessage: CopilotMessage = {
          id: `msg-ast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          sender: 'assistant',
          text: rawText,
          timestamp: responseData.timestamp || new Date().toISOString(),
          contextType: responseData.contextType,
          entityId: responseData.entityId,
          isAdvisory: responseData.isAdvisory,
          disclaimer: responseData.disclaimer,
        };

        setMessages((prev) => [...prev, assistantMessage]);
      } catch (err: unknown) {
        let errorPayload: CopilotApiError;
        if (err instanceof CopilotClientError) {
          errorPayload = {
            status: err.status,
            code: err.code,
            message: err.message,
            retryAfterSeconds: err.retryAfterSeconds,
            requiredPermission: err.requiredPermission,
          };
        } else {
          errorPayload = {
            status: 500,
            code: 'CLIENT_UNKNOWN_ERROR',
            message: err instanceof Error ? err.message : 'Unexpected client error during model dispatch.',
          };
        }

        const errorMessage: CopilotMessage = {
          id: `msg-err-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          sender: 'assistant',
          text: '',
          timestamp: new Date().toISOString(),
          contextType: activeType,
          entityId: activeEntity,
          error: errorPayload,
        };

        setMessages((prev) => [...prev, errorMessage]);
      } finally {
        setIsLoading(false);
      }
    },
    [isLoading, contextType, entityId]
  );

  return {
    isOpen,
    openDrawer,
    closeDrawer,
    toggleDrawer,
    messages,
    isLoading,
    status,
    isCheckingStatus,
    statusError,
    contextType,
    setContextType,
    entityId,
    setEntityId,
    sendMessage,
    clearMessages,
    refreshStatus: checkStatus,
  };
}
