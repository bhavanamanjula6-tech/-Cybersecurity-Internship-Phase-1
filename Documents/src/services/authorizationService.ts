/**
 * Authorization Service
 * Enforces role-based capabilities, record-level scoping, and strict access denial.
 *
 * PROTOTYPE ARCHITECTURE LIMITATION NOTICE:
 * In this client-side prototype, this enforcement runs in memory and client repositories.
 * In a production architecture, this identical evaluation logic MUST be mirrored and enforced
 * authoritatively on the server API (via JWT claims/middleware) and database row-level security.
 */

import { UserRole, UserProfile, Permission, ROLE_PERMISSIONS, AccessDeniedError } from '../types/auth';
import { SecurityAlert } from '../types/alert';

export class AuthorizationService {
  /**
   * Evaluates if a given role possesses a requested permission.
   */
  public static hasPermission(role: UserRole, permission: Permission): boolean {
    const permissions = ROLE_PERMISSIONS[role] || [];
    return permissions.includes(permission);
  }

  /**
   * Asserts that a user has a required permission, throwing an AccessDeniedError if not.
   */
  public static assertPermission(user: UserProfile, permission: Permission): void {
    if (!this.hasPermission(user.role, permission)) {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" does not have permission "${permission}".`,
        permission,
        user.role
      );
    }
  }

  public static canTriageAlerts(role: UserRole): boolean {
    return this.hasPermission(role, 'alert:triage');
  }

  public static canAddNote(role: UserRole): boolean {
    return this.hasPermission(role, 'alert:add_note');
  }

  public static canProposeActions(role: UserRole): boolean {
    return this.hasPermission(role, 'action:propose');
  }

  public static canAuthorizeSimulatedActions(role: UserRole): boolean {
    return this.hasPermission(role, 'action:authorize_simulated');
  }

  public static canAnalyzeMitreCoverage(role: UserRole): boolean {
    return this.hasPermission(role, 'mitre:analyze_coverage');
  }

  public static isPlatformAdmin(role: UserRole): boolean {
    return this.hasPermission(role, 'platform:admin');
  }

  public static canExportAuditLogs(role: UserRole): boolean {
    return this.hasPermission(role, 'audit:export');
  }

  public static canCreateRecommendation(role: UserRole): boolean {
    return this.hasPermission(role, 'recommendation:create');
  }

  public static canReviewRecommendation(role: UserRole): boolean {
    return this.hasPermission(role, 'recommendation:review');
  }

  public static canUpdateRecommendation(role: UserRole): boolean {
    return this.hasPermission(role, 'recommendation:update');
  }

  public static canValidateRecommendation(role: UserRole): boolean {
    return this.hasPermission(role, 'recommendation:validate');
  }

  public static assertCanExportAuditLogs(user: UserProfile): void {
    if (!this.canExportAuditLogs(user.role)) {
      throw new AccessDeniedError(
        `Access Denied: Role "${user.role}" is not authorized to export audit logs. Only Super Admin can export audit logs.`,
        'audit:export',
        user.role
      );
    }
  }

  /**
   * Record-level access check for an alert:
   * - SOC Analyst: full access to all alerts.
   * - Security Engineer: read-only access to all alerts.
   * - IT Operations: ONLY access alerts that correspond to assigned remediation tasks.
   * - Super Admin: STRICTLY DENIED (Super Admin cannot access private SOC alerts).
   */
  public static canReadAlertRecord(user: UserProfile, alert: SecurityAlert, assignedAlertIds: string[]): boolean {
    if (user.role === 'super_admin') {
      return false; // Platform Admin cannot view private operational alerts
    }
    if (user.role === 'soc_analyst' || user.role === 'security_engineer') {
      return true;
    }
    if (user.role === 'it_operations') {
      return assignedAlertIds.includes(alert.id);
    }
    return false;
  }

  /**
   * Role-to-view authorization matrix.
   * Defines strictly permitted UI workspace views for each role.
   */
  public static readonly ROLE_AUTHORIZED_VIEWS: Record<UserRole, string[]> = {
    soc_analyst: [
      'overview',
      'strategies',
      'analytics',
      'log_sources',
      'data_components',
      'mitre_explorer',
      'alerts',
      'investigations',
      'playbooks',
      'audit',
      'profile',
    ],
    security_engineer: ['seceng_overview', 'mitre', 'alerts', 'audit', 'profile'],
    it_operations: [
      'itops_overview',
      'itops_techniques',
      'itops_mitigations',
      'tasks',
      'alerts',
      'audit',
      'profile',
    ],
    super_admin: ['admin', 'audit', 'profile'],
  };

  /**
   * Default primary landing view for each role.
   */
  public static readonly ROLE_DEFAULT_VIEW: Record<UserRole, string> = {
    soc_analyst: 'overview',
    security_engineer: 'seceng_overview',
    it_operations: 'itops_overview',
    super_admin: 'admin',
  };

  /**
   * Evaluates if a role is authorized to render a given workspace view.
   */
  public static isViewAuthorized(role: UserRole, view: string): boolean {
    const allowed = this.ROLE_AUTHORIZED_VIEWS[role] || [];
    return allowed.includes(view);
  }

  /**
   * Retrieves the authorized default landing view for a role.
   */
  public static getDefaultViewForRole(role: UserRole): string {
    return this.ROLE_DEFAULT_VIEW[role] || 'alerts';
  }

  /**
   * Asserts view authorization, throwing AccessDeniedError if unauthorized.
   */
  public static assertViewAccess(role: UserRole, view: string): void {
    if (!this.isViewAuthorized(role, view)) {
      throw new AccessDeniedError(
        `Access Denied: Role "${role}" is not authorized to access workspace view "${view}".`,
        role === 'super_admin' ? 'platform:admin' : 'alert:read',
        role
      );
    }
  }
}

