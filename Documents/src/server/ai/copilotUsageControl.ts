/**
 * CyberOps SOC — Server-Side Copilot Concurrency & Usage Controls
 *
 * Architecture for request concurrency bounding, rate limiting, and token accounting.
 *
 * DESIGN & AUDIT DISCLOSURES:
 * - Concurrency bounding and sliding-window rate tracking are implemented in-process (in-memory).
 * - Full multi-instance atomic rate-limiting, daily quotas, and persistent token accounting require
 *   an external transactional datastore (such as Redis or PostgreSQL usage tables).
 * - Token estimations are calculated server-side; client-reported token counts are NEVER trusted.
 */

export interface UsageEvaluation {
  allowed: boolean;
  reason?: string;
  retryAfterSeconds?: number;
}

export interface IUsageController {
  acquireConcurrency(): boolean;
  releaseConcurrency(): void;
  evaluateUserLimits(userId: string): UsageEvaluation;
  recordTokens(userId: string, estimatedPromptTokens: number, estimatedResponseTokens: number): void;
  getMetrics(): {
    activeRequests: number;
    maxConcurrency: number;
    trackedUsers: number;
  };
}

export interface UsageControllerConfig {
  maxConcurrentRequests: number;
  maxRequestsPerMinutePerUser: number;
  requestTimeoutMs: number;
}

const DEFAULT_CONFIG: UsageControllerConfig = {
  maxConcurrentRequests: 5,
  maxRequestsPerMinutePerUser: 20,
  requestTimeoutMs: 30000,
};

export class InMemoryUsageController implements IUsageController {
  private activeRequests = 0;
  private readonly config: UsageControllerConfig;
  private userRequestTimestamps: Map<string, number[]> = new Map();
  private userTokenUsage: Map<string, { promptTokens: number; responseTokens: number }> = new Map();

  constructor(config: Partial<UsageControllerConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Attempts to acquire a concurrency slot for an in-flight model request.
   */
  public acquireConcurrency(): boolean {
    if (this.activeRequests >= this.config.maxConcurrentRequests) {
      return false;
    }
    this.activeRequests++;
    return true;
  }

  /**
   * Releases an acquired concurrency slot upon request completion or error.
   */
  public releaseConcurrency(): void {
    if (this.activeRequests > 0) {
      this.activeRequests--;
    }
  }

  /**
   * Evaluates user sliding-window rate limits.
   */
  public evaluateUserLimits(userId: string): UsageEvaluation {
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute sliding window
    const cutoff = now - windowMs;

    const timestamps = this.userRequestTimestamps.get(userId) || [];
    const validTimestamps = timestamps.filter((t) => t > cutoff);

    if (validTimestamps.length >= this.config.maxRequestsPerMinutePerUser) {
      const oldestInWindow = validTimestamps[0];
      const retryAfter = Math.ceil((oldestInWindow + windowMs - now) / 1000);
      return {
        allowed: false,
        reason: `Rate limit exceeded. Maximum ${this.config.maxRequestsPerMinutePerUser} requests per minute allowed.`,
        retryAfterSeconds: Math.max(1, retryAfter),
      };
    }

    validTimestamps.push(now);
    this.userRequestTimestamps.set(userId, validTimestamps);

    return { allowed: true };
  }

  /**
   * Records server-estimated token consumption.
   * Client-reported values are never accepted.
   */
  public recordTokens(
    userId: string,
    estimatedPromptTokens: number,
    estimatedResponseTokens: number
  ): void {
    const current = this.userTokenUsage.get(userId) || { promptTokens: 0, responseTokens: 0 };
    this.userTokenUsage.set(userId, {
      promptTokens: current.promptTokens + Math.max(0, estimatedPromptTokens),
      responseTokens: current.responseTokens + Math.max(0, estimatedResponseTokens),
    });
  }

  /**
   * Estimates token count based on standard English/code heuristic (approx 4 characters per token).
   */
  public static estimateTokens(text: string): number {
    if (!text) return 0;
    return Math.ceil(text.length / 4);
  }

  public getMetrics() {
    return {
      activeRequests: this.activeRequests,
      maxConcurrency: this.config.maxConcurrentRequests,
      trackedUsers: this.userRequestTimestamps.size,
    };
  }
}

export const defaultUsageController = new InMemoryUsageController();
