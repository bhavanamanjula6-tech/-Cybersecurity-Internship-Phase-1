/**
 * Alert Velocity & Telemetry Metrics Service
 *
 * Implements:
 * 1. 24-Hour alert intake trend interval bucketing with timestamp validation.
 * 2. Defensible MTTA (Mean Time to Acknowledge) and MTTR (Mean Time to Resolve)
 *    evaluations that strictly respect schema limitations and refuse to fabricate metrics.
 * 3. Alert lifecycle transition rules for batch operations.
 */

import { SecurityAlert, AlertStatus, AlertSeverity } from '../types/alert';

export interface IntakeIntervalBucket {
  index: number;
  label: string;
  startIso: string;
  endIso: string;
  count: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  alertIds: string[];
}

export interface IntakeTrendResult {
  buckets: IntakeIntervalBucket[];
  totalWithinWindow: number;
  outsideWindowCount: number;
  invalidTimestampCount: number;
  windowStartIso: string;
  windowEndIso: string;
  isAnchoredToTelemetry: boolean;
  isSynthetic: boolean;
  hasUsableData: boolean;
}

export interface MetricCalculation {
  metricName: string;
  valueMinutes: number | null;
  formattedValue: string;
  contributingRecords: number;
  totalRecords: number;
  status: 'computed' | 'unavailable';
  reason: string;
  measurementWindow: string;
  unit: string;
}

export class AlertMetricsService {
  /**
   * Group alerts into time intervals across a 24-hour window.
   * Handles invalid or missing timestamps gracefully without crashing.
   *
   * Window Anchoring Strategy:
   * - If alerts have valid timestamps but they are older than 24 hours from current wall clock
   *   (e.g., synthetic demonstration scenarios from 2026-10-12), the window anchors to the
   *   most recent telemetry event timestamp to ensure demonstration events can be analyzed.
   * - If real-time alerts fall within the current wall-clock window, the window anchors to now.
   */
  public static calculate24hIntakeTrend(
    alerts: SecurityAlert[],
    options?: {
      referenceTime?: number;
      bucketCount?: number;
    }
  ): IntakeTrendResult {
    const bucketCount = options?.bucketCount || 6; // 6 intervals of 4 hours
    const intervalMs = (24 * 60 * 60 * 1000) / bucketCount;

    let invalidTimestampCount = 0;
    const validAlertTimestamps: Array<{ alert: SecurityAlert; time: number }> = [];

    for (const alert of alerts) {
      if (!alert.detectedAt) {
        invalidTimestampCount++;
        continue;
      }
      const t = new Date(alert.detectedAt).getTime();
      if (isNaN(t) || t <= 0) {
        invalidTimestampCount++;
        continue;
      }
      validAlertTimestamps.push({ alert, time: t });
    }

    if (validAlertTimestamps.length === 0) {
      const now = options?.referenceTime || Date.now();
      const emptyBuckets: IntakeIntervalBucket[] = [];
      for (let i = 0; i < bucketCount; i++) {
        const bucketStart = now - (bucketCount - i) * intervalMs;
        const bucketEnd = bucketStart + intervalMs;
        const startH = new Date(bucketStart).getUTCHours().toString().padStart(2, '0');
        const endH = new Date(bucketEnd).getUTCHours().toString().padStart(2, '0');
        emptyBuckets.push({
          index: i,
          label: `${startH}:00 - ${endH}:00`,
          startIso: new Date(bucketStart).toISOString(),
          endIso: new Date(bucketEnd).toISOString(),
          count: 0,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          infoCount: 0,
          alertIds: [],
        });
      }

      return {
        buckets: emptyBuckets,
        totalWithinWindow: 0,
        outsideWindowCount: 0,
        invalidTimestampCount,
        windowStartIso: new Date(now - 24 * 60 * 60 * 1000).toISOString(),
        windowEndIso: new Date(now).toISOString(),
        isAnchoredToTelemetry: false,
        isSynthetic: alerts.some((a) => a.isSynthetic),
        hasUsableData: false,
      };
    }

    // Determine window anchor
    const now = Date.now();
    const latestEventTime = Math.max(...validAlertTimestamps.map((v) => v.time));
    const isHistorical = now - latestEventTime > 24 * 60 * 60 * 1000;

    const windowEnd = options?.referenceTime
      ? options.referenceTime
      : isHistorical
      ? latestEventTime
      : now;
    const windowStart = windowEnd - 24 * 60 * 60 * 1000;

    // Initialize buckets
    const buckets: IntakeIntervalBucket[] = [];
    for (let i = 0; i < bucketCount; i++) {
      const bucketStart = windowStart + i * intervalMs;
      const bucketEnd = bucketStart + intervalMs;
      const startH = new Date(bucketStart).getUTCHours().toString().padStart(2, '0');
      const startM = new Date(bucketStart).getUTCMinutes().toString().padStart(2, '0');
      const endH = new Date(bucketEnd).getUTCHours().toString().padStart(2, '0');
      const endM = new Date(bucketEnd).getUTCMinutes().toString().padStart(2, '0');
      buckets.push({
        index: i,
        label: `${startH}:${startM}-${endH}:${endM}`,
        startIso: new Date(bucketStart).toISOString(),
        endIso: new Date(bucketEnd).toISOString(),
        count: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        alertIds: [],
      });
    }

    let outsideWindowCount = 0;
    let totalWithinWindow = 0;

    for (const item of validAlertTimestamps) {
      if (item.time < windowStart || item.time > windowEnd) {
        outsideWindowCount++;
        continue;
      }

      // Find appropriate bucket
      const bucketIdx = Math.min(
        Math.floor((item.time - windowStart) / intervalMs),
        bucketCount - 1
      );

      const bucket = buckets[bucketIdx];
      bucket.count++;
      totalWithinWindow++;
      bucket.alertIds.push(item.alert.id);

      switch (item.alert.severity) {
        case 'critical':
          bucket.criticalCount++;
          break;
        case 'high':
          bucket.highCount++;
          break;
        case 'medium':
          bucket.mediumCount++;
          break;
        case 'low':
          bucket.lowCount++;
          break;
        case 'informational':
          bucket.infoCount++;
          break;
      }
    }

    return {
      buckets,
      totalWithinWindow,
      outsideWindowCount,
      invalidTimestampCount,
      windowStartIso: new Date(windowStart).toISOString(),
      windowEndIso: new Date(windowEnd).toISOString(),
      isAnchoredToTelemetry: isHistorical,
      isSynthetic: alerts.some((a) => a.isSynthetic),
      hasUsableData: totalWithinWindow > 0,
    };
  }

  /**
   * Calculates Mean Time to Acknowledge (MTTA).
   *
   * Architectural Constraint & Defensibility Rules:
   * - Must use a valid alert-created timestamp (detectedAt) and a valid acknowledgement/triage timestamp.
   * - Excludes invalid, missing, or negative time intervals.
   * - Handles zero-duration intervals safely.
   * - Reports contributing records and measurement window.
   * - If data lacks required acknowledgement timestamps, it MUST NOT fabricate the metric or
   *   substitute elapsed time. It reports status: 'unavailable' with full diagnostic reasons.
   */
  public static calculateMTTA(alerts: SecurityAlert[]): MetricCalculation {
    const totalRecords = alerts.length;
    let sumMinutes = 0;
    let contributingRecords = 0;

    for (const alert of alerts) {
      if (!alert.detectedAt) continue;

      const createdTime = new Date(alert.detectedAt).getTime();
      if (isNaN(createdTime) || createdTime <= 0) continue;

      // Inspect record for an explicit acknowledgment timestamp
      const ackTimestamp =
        (alert as any).acknowledgedAt ||
        (alert as any).triagedAt ||
        (alert as any).acknowledged_at ||
        (alert as any).triaged_at;

      if (!ackTimestamp) {
        // Timestamp is missing from schema/record: cannot contribute to defensible MTTA
        continue;
      }

      const ackTime = new Date(ackTimestamp).getTime();
      if (isNaN(ackTime) || ackTime <= 0) continue;

      const diffMs = ackTime - createdTime;
      // Exclude negative time intervals
      if (diffMs < 0) continue;

      // Handle zero-duration safely (0 ms = 0 minutes)
      const diffMinutes = diffMs / (60 * 1000);
      sumMinutes += diffMinutes;
      contributingRecords++;
    }

    if (contributingRecords === 0) {
      return {
        metricName: 'Mean Time to Acknowledge (MTTA)',
        valueMinutes: null,
        formattedValue: 'N/A',
        contributingRecords: 0,
        totalRecords,
        status: 'unavailable',
        reason:
          'Alert schema currently tracks detectedAt only; discrete triage acknowledgement timestamp (acknowledged_at) is unpopulated in current fixtures.',
        measurementWindow: '24-Hour Queue Scope',
        unit: 'Minutes',
      };
    }

    const meanMinutes = Math.round((sumMinutes / contributingRecords) * 10) / 10;
    const formattedValue =
      meanMinutes < 60
        ? `${meanMinutes}m`
        : `${Math.round((meanMinutes / 60) * 10) / 10}h`;

    return {
      metricName: 'Mean Time to Acknowledge (MTTA)',
      valueMinutes: meanMinutes,
      formattedValue,
      contributingRecords,
      totalRecords,
      status: 'computed',
      reason: `Evaluated across ${contributingRecords} verified acknowledged alert records.`,
      measurementWindow: '24-Hour Queue Scope',
      unit: 'Minutes',
    };
  }

  /**
   * Calculates Mean Time to Resolve (MTTR).
   *
   * Architectural Constraint & Defensibility Rules:
   * - Must use a valid alert-created timestamp (detectedAt) and a verified resolution timestamp.
   * - Never labels a simple elapsed-time calculation as MTTR if available timestamps do not
   *   establish the actual resolution event.
   * - Excludes invalid, missing, or negative time intervals.
   * - Handles zero-duration intervals safely.
   */
  public static calculateMTTR(alerts: SecurityAlert[]): MetricCalculation {
    const totalRecords = alerts.length;
    let sumMinutes = 0;
    let contributingRecords = 0;

    for (const alert of alerts) {
      if (!alert.detectedAt) continue;

      const createdTime = new Date(alert.detectedAt).getTime();
      if (isNaN(createdTime) || createdTime <= 0) continue;

      // Inspect record for an explicit resolution timestamp
      const resTimestamp =
        (alert as any).resolvedAt ||
        (alert as any).closedAt ||
        (alert as any).resolved_at ||
        (alert as any).closed_at;

      if (!resTimestamp) {
        // Record has no resolution timestamp; cannot fabricate resolution duration
        continue;
      }

      const resTime = new Date(resTimestamp).getTime();
      if (isNaN(resTime) || resTime <= 0) continue;

      const diffMs = resTime - createdTime;
      // Exclude negative time intervals
      if (diffMs < 0) continue;

      const diffMinutes = diffMs / (60 * 1000);
      sumMinutes += diffMinutes;
      contributingRecords++;
    }

    if (contributingRecords === 0) {
      return {
        metricName: 'Mean Time to Resolve (MTTR)',
        valueMinutes: null,
        formattedValue: 'N/A',
        contributingRecords: 0,
        totalRecords,
        status: 'unavailable',
        reason:
          'Alert schema currently tracks detectedAt only; discrete incident resolution timestamp (resolved_at) is unpopulated in current fixtures. Elapsed time is not substituted.',
        measurementWindow: '24-Hour Queue Scope',
        unit: 'Minutes',
      };
    }

    const meanMinutes = Math.round((sumMinutes / contributingRecords) * 10) / 10;
    const formattedValue =
      meanMinutes < 60
        ? `${meanMinutes}m`
        : `${Math.round((meanMinutes / 60) * 10) / 10}h`;

    return {
      metricName: 'Mean Time to Resolve (MTTR)',
      valueMinutes: meanMinutes,
      formattedValue,
      contributingRecords,
      totalRecords,
      status: 'computed',
      reason: `Evaluated across ${contributingRecords} verified resolved alert records.`,
      measurementWindow: '24-Hour Queue Scope',
      unit: 'Minutes',
    };
  }

  /**
   * Evaluates if a proposed status transition is permitted by lifecycle rules.
   */
  public static isStatusTransitionValid(currentStatus: AlertStatus, targetStatus: AlertStatus): boolean {
    if (currentStatus === targetStatus) return false;

    switch (targetStatus) {
      case 'in_triage':
        // Can move to in_triage from new, escalated, or reopened from resolved/false_positive
        return ['new', 'escalated', 'resolved', 'false_positive'].includes(currentStatus);
      case 'escalated':
        // Can escalate from new or in_triage
        return ['new', 'in_triage'].includes(currentStatus);
      case 'resolved':
        // Can resolve from new, in_triage, or escalated
        return ['new', 'in_triage', 'escalated'].includes(currentStatus);
      case 'false_positive':
        // Can mark false positive from new or in_triage
        return ['new', 'in_triage'].includes(currentStatus);
      case 'new':
        // Generally alerts cannot revert to 'new' once touched
        return false;
      default:
        return false;
    }
  }

  /**
   * Filters an array of alerts down to only those eligible for a target status transition.
   */
  public static getEligibleAlertsForTransition(alerts: SecurityAlert[], targetStatus: AlertStatus): SecurityAlert[] {
    return alerts.filter((a) => this.isStatusTransitionValid(a.status, targetStatus));
  }
}
