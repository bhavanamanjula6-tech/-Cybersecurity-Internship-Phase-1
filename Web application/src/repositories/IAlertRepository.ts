/**
 * Alert Repository Interface
 * Defines role-aware, record-isolated operations for alerts.
 */

import { SecurityAlert, AlertFilterOptions, AlertStatus } from '../types/alert';
import { UserProfile } from '../types/auth';

export interface IAlertRepository {
  /**
   * Retrieves alerts scoped to the requesting user's role and authorizations.
   */
  getAlertsForUser(
    user: UserProfile,
    filter?: Partial<AlertFilterOptions>,
    assignedAlertIds?: string[]
  ): Promise<SecurityAlert[]>;

  /**
   * Retrieves a single alert with record-level access evaluation.
   */
  getAlertByIdForUser(
    user: UserProfile,
    id: string,
    assignedAlertIds?: string[]
  ): Promise<SecurityAlert | null>;

  /**
   * Updates an alert's status. Requires 'alert:triage' permission.
   * Enforces Incident Closure Guard if status is 'resolved'.
   */
  updateAlertStatus(
    user: UserProfile,
    id: string,
    status: AlertStatus,
    tasks?: import('../types/audit').IncidentTask[]
  ): Promise<SecurityAlert>;

  /**
   * Appends an analyst investigation note. Requires 'alert:add_note' permission.
   */
  addAnalystNote(user: UserProfile, id: string, note: string): Promise<SecurityAlert>;

  /**
   * Resets local prototype records to clean baseline.
   */
  resetToDefault(): Promise<void>;

  /**
   * Inserts or updates a controlled simulated alert into the operational queue.
   */
  addSimulatedAlert?(alert: SecurityAlert): Promise<SecurityAlert>;
}
