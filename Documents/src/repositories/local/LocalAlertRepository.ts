/**
 * Local Browser Storage Adapter for Alerts with Role & Record-Level Enforcement
 *
 * PROTOTYPE ARCHITECTURE NOTICE & LIMITATION DISCLAIMER:
 * This repository implements client-side role and record-level isolation for Phase 1 prototyping.
 * Architectural Limitations:
 * - Isolation is enforced in client repository code; it does NOT constitute backend or database-level RLS.
 * - In a production system, these rules must be enforced in backend API routes and parameterized database queries.
 * - Single-device scope: State is stored in client browser localStorage and is not shared across machines.
 * - No secrets or real production telemetry are stored.
 */

import { IAlertRepository } from '../IAlertRepository';
import { SecurityAlert, AlertFilterOptions, AlertStatus } from '../../types/alert';
import { IncidentTask } from '../../types/audit';
import { UserProfile, AccessDeniedError } from '../../types/auth';
import { AuthorizationService } from '../../services/authorizationService';
import { INITIAL_SYNTHETIC_ALERTS } from '../../data/syntheticAlerts';
import { normalizeAttackId } from '../../utils/mitreUtils';
import { checkAlertClosureEligibility } from '../../utils/remediationReview';

const STORAGE_KEY = 'ai_soc_alerts_v1';

export class LocalAlertRepository implements IAlertRepository {
  private memoryStore: SecurityAlert[] | null = null;

  private getStorageData(): SecurityAlert[] {
    let rawAlerts: SecurityAlert[] | null = null;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        const stored = window.localStorage.getItem(STORAGE_KEY);
        if (stored) {
          rawAlerts = JSON.parse(stored);
        }
      } catch {
        // Fallback
      }
    }
    if (!rawAlerts) {
      if (this.memoryStore) return this.memoryStore;
      rawAlerts = [...INITIAL_SYNTHETIC_ALERTS];
    }
    const normalized = rawAlerts.map((a) => ({
      ...a,
      attack_id: a.attack_id || normalizeAttackId(a.mitreTechniqueId) || undefined,
    }));
    this.memoryStore = normalized;
    return this.memoryStore;
  }

  private saveStorageData(alerts: SecurityAlert[]): void {
    this.memoryStore = alerts;
    if (typeof window !== 'undefined' && window.localStorage) {
      try {
        window.localStorage.setItem(STORAGE_KEY, JSON.stringify(alerts));
      } catch {
        // Fallback
      }
    }
  }

  /**
   * Retrieves alerts strictly scoped to the requesting user's role and assigned records.
   */
  async getAlertsForUser(
    user: UserProfile,
    filter?: Partial<AlertFilterOptions>,
    assignedAlertIds: string[] = ['ALT-2026-1046', 'ALT-2026-1047'] // Task-linked alerts for IT Operations
  ): Promise<SecurityAlert[]> {
    let list = this.getStorageData();

    // 1. Role-based record scoping
    if (user.role === 'super_admin') {
      throw new AccessDeniedError(
        'Platform Administrator is architecturally isolated from private SOC operational alerts.',
        'alert:read',
        user.role
      );
    } else if (user.role === 'it_operations') {
      // IT Operations cannot browse general unassigned queue; only alerts tied to assigned remediation tasks
      list = list.filter((a) => assignedAlertIds.includes(a.id));
    } else if (user.role === 'security_engineer') {
      // Security Engineers can audit alerts for detection analysis, but operational notes are read-only
      list = [...list];
    } else if (user.role === 'soc_analyst') {
      // SOC Analysts have full queue access
      list = [...list];
    } else {
      throw new AccessDeniedError(`Unknown role "${user.role}" cannot access alerts`, 'alert:read', user.role);
    }

    // 2. Query filters
    if (filter?.searchQuery) {
      const q = filter.searchQuery.toLowerCase();
      list = list.filter(
        (a) =>
          a.id.toLowerCase().includes(q) ||
          a.title.toLowerCase().includes(q) ||
          a.hostName.toLowerCase().includes(q) ||
          (a.mitreTechniqueId && a.mitreTechniqueId.toLowerCase().includes(q)) ||
          a.sourceIp.includes(q)
      );
    }

    if (filter?.severities && filter.severities.length > 0) {
      list = list.filter((a) => filter.severities!.includes(a.severity));
    }

    if (filter?.statuses && filter.statuses.length > 0) {
      list = list.filter((a) => filter.statuses!.includes(a.status));
    }

    if (filter?.tacticId) {
      list = list.filter((a) => a.mitreTacticId === filter.tacticId);
    }

    if (filter?.sortBy) {
      list.sort((a, b) => {
        const order = filter.sortOrder === 'asc' ? 1 : -1;
        if (filter.sortBy === 'detectedAt') {
          return (new Date(a.detectedAt).getTime() - new Date(b.detectedAt).getTime()) * order;
        }
        if (filter.sortBy === 'confidenceScore') {
          return (a.confidenceScore - b.confidenceScore) * order;
        }
        return 0;
      });
    }

    return list;
  }

  /**
   * Retrieves single alert with record-level permission verification.
   */
  async getAlertByIdForUser(
    user: UserProfile,
    id: string,
    assignedAlertIds: string[] = ['ALT-2026-1046', 'ALT-2026-1047']
  ): Promise<SecurityAlert | null> {
    const list = this.getStorageData();
    const alert = list.find((a) => a.id === id);
    if (!alert) return null;

    if (!AuthorizationService.canReadAlertRecord(user, alert, assignedAlertIds)) {
      throw new AccessDeniedError(
        `Access Denied: User in role "${user.role}" is not authorized to read alert record ${id}.`,
        'alert:read',
        user.role
      );
    }

    return alert;
  }

  /**
   * Updates alert triage status. Throws AccessDeniedError if user lacks 'alert:triage'.
   * Enforces Incident Closure Guard: blocks transition to 'resolved' if any linked remediation tasks are unapproved.
   */
  async updateAlertStatus(
    user: UserProfile,
    id: string,
    status: AlertStatus,
    tasks?: IncidentTask[]
  ): Promise<SecurityAlert> {
    // Assert authorization
    AuthorizationService.assertPermission(user, 'alert:triage');

    const list = this.getStorageData();
    const index = list.findIndex((a) => a.id === id);
    if (index === -1) {
      throw new Error(`Alert ${id} not found`);
    }

    // Incident Closure Guard: prevent resolution if associated remediation tasks are not all approved
    if (status === 'resolved') {
      let taskList: IncidentTask[] = tasks || [];
      if (!tasks && typeof window !== 'undefined' && window.localStorage) {
        try {
          const stored = window.localStorage.getItem('ai_soc_tasks_v1');
          if (stored) {
            taskList = JSON.parse(stored);
          }
        } catch {}
      }
      const eligibility = checkAlertClosureEligibility(id, taskList);
      if (!eligibility.eligible) {
        throw new Error(
          eligibility.reason ||
            `Cannot resolve alert ${id}: all associated remediation tasks must have explicit SOC Analyst approval before closure.`
        );
      }
    }

    const updated: SecurityAlert = {
      ...list[index],
      status,
      assignedAnalyst: user.name,
    };
    list[index] = updated;
    this.saveStorageData(list);
    return updated;
  }

  /**
   * Appends analyst investigation note. Throws AccessDeniedError if user lacks 'alert:add_note'.
   */
  async addAnalystNote(user: UserProfile, id: string, note: string): Promise<SecurityAlert> {
    // Assert authorization
    AuthorizationService.assertPermission(user, 'alert:add_note');

    const list = this.getStorageData();
    const index = list.findIndex((a) => a.id === id);
    if (index === -1) {
      throw new Error(`Alert ${id} not found`);
    }

    const formattedNote = `[${user.callsign} (${user.role.toUpperCase()})]: ${note.trim()}`;
    const updated: SecurityAlert = {
      ...list[index],
      analystNotes: [...(list[index].analystNotes || []), formattedNote],
    };
    list[index] = updated;
    this.saveStorageData(list);
    return updated;
  }

  /**
   * Appends or updates a controlled simulated alert with duplicate prevention.
   */
  async addSimulatedAlert(alert: SecurityAlert): Promise<SecurityAlert> {
    const list = this.getStorageData();
    const existingIndex = list.findIndex((a) => a.id === alert.id);

    if (existingIndex >= 0) {
      // Update existing alert timestamp and preserve triage status if updated
      const updated = {
        ...list[existingIndex],
        detectedAt: alert.detectedAt,
        evidence: alert.evidence,
      };
      list[existingIndex] = updated;
      this.saveStorageData(list);
      return updated;
    }

    const updatedList = [alert, ...list];
    this.saveStorageData(updatedList);
    return alert;
  }

  async resetToDefault(): Promise<void> {
    this.saveStorageData(INITIAL_SYNTHETIC_ALERTS);
  }
}
