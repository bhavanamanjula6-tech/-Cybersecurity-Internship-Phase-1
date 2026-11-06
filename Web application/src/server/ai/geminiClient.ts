/**
 * CyberOps SOC — Server-Side Gemini AI Client Service
 *
 * Exclusively executes Gemini API calls server-side using @google/genai.
 * Adheres strictly to the Google GenAI SDK guidelines:
 * - Reads GEMINI_API_KEY strictly from process.env.
 * - Sets 'User-Agent': 'aistudio-build' in httpOptions.
 * - Uses 'gemini-3.8-flash' with configurable override.
 * - Applies timeout, secret redaction, and bounded output tokens.
 * - Fails safely with typed errors; NEVER fabricates fake responses when key is missing.
 */

import { GoogleGenAI } from '@google/genai';

export class GeminiUnavailableError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(
    message = 'AI Copilot service is temporarily unavailable: The upstream model is experiencing high demand. Please retry shortly.',
    status = 503,
    code = 'COPILOT_UNAVAILABLE'
  ) {
    super(message);
    this.name = 'GeminiUnavailableError';
    this.status = status;
    this.code = code;
  }
}

export class GeminiRateLimitError extends Error {
  public readonly status: number;
  public readonly code: string;
  public readonly retryAfterSeconds?: number;

  constructor(
    message = 'AI Copilot service rate limit or quota exceeded. Please wait a moment before retrying.',
    retryAfterSeconds?: number
  ) {
    super(message);
    this.name = 'GeminiRateLimitError';
    this.status = 429;
    this.code = 'RATE_LIMIT_EXCEEDED';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class GeminiTimeoutError extends Error {
  public readonly status: number;
  public readonly code: string;

  constructor(message = 'Gemini model request timed out after 30 seconds.') {
    super(message);
    this.name = 'GeminiTimeoutError';
    this.status = 504;
    this.code = 'MODEL_TIMEOUT';
  }
}

/**
 * Safely extracts non-empty text from a @google/genai GenerateContentResponse.
 * Handles both the .text getter and direct inspection of candidate content parts,
 * gracefully ignoring thought/reasoning blocks while recovering substantive text.
 */
export function extractGeneratedText(response: any): string {
  if (!response) return '';

  // 1. Primary getter from @google/genai GenerateContentResponse
  if (typeof response.text === 'string' && response.text.trim().length > 0) {
    return response.text.trim();
  }

  // 2. Candidate inspection: iterate parts in candidates
  if (response.candidates && Array.isArray(response.candidates) && response.candidates.length > 0) {
    for (const candidate of response.candidates) {
      if (candidate.content && Array.isArray(candidate.content.parts)) {
        // Collect non-thought text parts
        const nonThought = candidate.content.parts.filter(
          (p: any) => typeof p.text === 'string' && !p.thought
        );
        const partsToUse = nonThought.length > 0 ? nonThought : candidate.content.parts;
        const joined = partsToUse
          .map((p: any) => (typeof p.text === 'string' ? p.text : ''))
          .join('')
          .trim();
        if (joined.length > 0) {
          return joined;
        }
      }
    }
  }

  return '';
}

export interface GeminiClientOptions {
  apiKey?: string;
  modelName?: string;
  timeoutMs?: number;
  maxOutputTokens?: number;
}

export interface CopilotGenerationResult {
  text: string;
  model: string;
  disclaimer: string;
}

export type ModelGenerator = (
  systemInstruction: string,
  userContent: string
) => Promise<string>;

export class GeminiCopilotService {
  private client: GoogleGenAI | null = null;
  private readonly apiKey?: string;
  private readonly modelName: string;
  private readonly timeoutMs: number;
  private readonly maxOutputTokens: number;
  private customGenerator?: ModelGenerator;

  constructor(options: GeminiClientOptions = {}, customGenerator?: ModelGenerator) {
    this.modelName = options.modelName || process.env.COPILOT_MODEL || 'gemini-3.8-flash';
    this.timeoutMs = options.timeoutMs || 30000;
    this.maxOutputTokens = options.maxOutputTokens || 2048;
    this.customGenerator = customGenerator;

    const resolvedApiKey = options.apiKey || process.env.GEMINI_API_KEY || process.env.GOOGLE_GENAI_API_KEY;
    this.apiKey = resolvedApiKey?.trim();

    if (this.apiKey && this.apiKey.length > 0) {
      this.client = new GoogleGenAI({
        apiKey: this.apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    }
  }

  /**
   * Checks if the Gemini service has a configured API key or test generator.
   */
  public isConfigured(): boolean {
    const hasKey = Boolean(this.apiKey && this.apiKey.length > 0);
    return Boolean(this.customGenerator || (this.client && hasKey));
  }

  /**
   * Generates advisory response from Gemini model.
   */
  public async generateAdvisory(
    systemInstruction: string,
    assembledContent: string
  ): Promise<CopilotGenerationResult> {
    // 1. Fail safely if neither custom generator nor client is configured
    if (!this.customGenerator && (!this.client || !this.apiKey || this.apiKey === '')) {
      throw new GeminiUnavailableError(
        'AI Copilot service is unavailable: Server GEMINI_API_KEY is not configured in process.env.'
      );
    }

    const abortController = new AbortController();
    let timeoutId: NodeJS.Timeout | null = null;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        abortController.abort();
        reject(new GeminiTimeoutError());
      }, this.timeoutMs);
    });

    const callPromise = (async (): Promise<string> => {
      try {
        if (this.customGenerator) {
          return await this.customGenerator(systemInstruction, assembledContent);
        }

        const response = await this.client!.models.generateContent({
          model: this.modelName,
          contents: assembledContent,
          config: {
            systemInstruction,
            maxOutputTokens: this.maxOutputTokens,
            temperature: 0.2, // Low temperature for high-precision analytical answers
            abortSignal: abortController.signal,
          },
        });

        // Detect safety filter blocks
        const firstCandidate = response.candidates?.[0];
        if (firstCandidate?.finishReason === 'SAFETY') {
          throw new GeminiUnavailableError(
            'Model output was filtered by safety policies for the requested security telemetry. Please rephrase your query.',
            422,
            'CONTENT_FILTERED'
          );
        }

        const extracted = extractGeneratedText(response);
        if (!extracted || extracted.trim().length === 0) {
          throw new GeminiUnavailableError(
            'The AI model completed the request but returned an empty response. Please retry your query.',
            502,
            'EMPTY_MODEL_RESPONSE'
          );
        }

        return extracted;
      } catch (err: unknown) {
        if (abortController.signal.aborted) {
          throw new GeminiTimeoutError();
        }
        throw err;
      }
    })();

    try {
      const rawText = await Promise.race([callPromise, timeoutPromise]);
      const sanitizedText = this.redactSensitiveData(rawText);

      if (!sanitizedText || sanitizedText.trim().length === 0) {
        throw new GeminiUnavailableError(
          'The AI model completed the request but returned an empty response. Please retry your query.',
          502,
          'EMPTY_MODEL_RESPONSE'
        );
      }

      return {
        text: sanitizedText,
        model: this.modelName,
        disclaimer:
          'AI Copilot analysis is strictly advisory and requires human verification before operational action.',
      };
    } catch (err: unknown) {
      if (
        err instanceof GeminiTimeoutError ||
        err instanceof GeminiUnavailableError ||
        err instanceof GeminiRateLimitError
      ) {
        throw err;
      }

      const message = err instanceof Error ? err.message : String(err);
      const status = (err as any)?.status || (err as any)?.statusCode;

      // Classify 503 / Service Unavailable / High Demand
      if (
        status === 503 ||
        message.includes('503') ||
        message.includes('UNAVAILABLE') ||
        message.includes('high demand') ||
        message.includes('overloaded') ||
        message.includes('Service Unavailable')
      ) {
        throw new GeminiUnavailableError(
          'AI Copilot service is temporarily unavailable: The upstream model is experiencing high demand. Please retry shortly.'
        );
      }

      // Classify 429 / RESOURCE_EXHAUSTED / Rate Limit
      if (
        status === 429 ||
        message.includes('429') ||
        message.includes('RESOURCE_EXHAUSTED') ||
        message.includes('rate limit') ||
        message.includes('Too Many Requests')
      ) {
        throw new GeminiRateLimitError(
          'AI Copilot service rate limit or quota reached. Please wait a moment before sending another query.'
        );
      }

      // Classify 504 / Gateway Timeout / Deadline Exceeded
      if (
        status === 504 ||
        message.includes('504') ||
        message.includes('DEADLINE_EXCEEDED')
      ) {
        throw new GeminiTimeoutError('Gemini model request timed out after 30 seconds.');
      }

      const sanitized = this.redactSensitiveData(
        message.replace(/key=[A-Za-z0-9_-]+/g, 'key=[REDACTED]')
      );
      throw new Error(`Gemini generation failed: ${sanitized}`);
    } finally {
      // Clean up timer resources immediately when callPromise completes or errors
      if (timeoutId !== null) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      // Attach no-op error handler to callPromise to suppress unhandled rejections if provider errors after timeout
      callPromise.catch(() => {});
    }
  }

  /**
   * Redacts accidental reflections of secrets, tokens, or credentials from output.
   */
  private redactSensitiveData(text: string): string {
    if (!text) return '';

    return text
      // Redact JWT tokens (header.payload.signature)
      .replace(/eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, '[REDACTED_JWT_TOKEN]')
      // Redact Supabase publishable keys
      .replace(/sb_publishable_[a-zA-Z0-9_-]{20,}/g, '[REDACTED_SUPABASE_KEY]')
      // Redact Google / Gemini API keys (AIza...)
      .replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_API_KEY]')
      // Redact connection strings with passwords
      .replace(/postgres(?:ql)?:\/\/[^:]+:[^@]+@/g, 'postgresql://[REDACTED_CREDENTIALS]@');
  }
}
