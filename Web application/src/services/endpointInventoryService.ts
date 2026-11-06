/**
 * CyberOps SOC — IT Operations Endpoint & Host Inventory Service
 *
 * Provides authoritative aggregation of endpoint and host inventory records
 * strictly derived from authorized IT Operations remediation tasks and scoped incident alerts.
 *
 * SECURITY & SCOPING INVARIANTS:
 * 1. Zero External/Fake Endpoints: Does NOT invent standalone endpoint records or fake CMDB entries.
 *    Every endpoint is strictly anchored to an assigned task or authorized scoped alert.
 * 2. Record-Level Scoping: IT Operations only sees endpoints from tasks assigned to it_operations
 *    and alerts explicitly linked to those tasks.
 * 3. Super Admin Operational Isolation: Super Admin receives strictly empty inventory (isolated from private host assets).
 * 4. Non-Fabrication: If IP, FQDN, or OS details are absent, explicitly displays "Not available" or "Not recorded in telemetry".
 * 5. Honest Containment Status: Containment state reflects actual stored audit records or task lifecycle states.
 * 6. Read-Only: Zero endpoint mutation or containment execution controls in inventory view.
 */

import { IncidentTask, ResponseActionType, AuditLogEntry } from '../types/audit';
import { SecurityAlert } from '../types/alert';
import { UserProfile } from '../types/auth';

export interface EndpointTaskSummary {
  taskId: string;
  title: string;
  status: IncidentTask['status'];
  priority: IncidentTask['priority'];
  suggestedActionType?: ResponseActionType;
  createdAt: string;
}

export interface EndpointAlertSummary {
  alertId: string;
  title: string;
  severity: string;
  mitreTechniqueId?: string;
  detectedAt: string;
}

export type ContainmentState =
  | 'Simulated Isolated'
  | 'Quarantine Pending'
  | 'Verified Recovered'
  | 'Active / Standard Network'
  | 'Unknown';

export interface EndpointRecord {
  id: string; // Normalized asset identifier, e.g. "EP-FILESERVER-01"
  hostname: string;
  fqdn: string;
  ipAddress: string;
  osDetails: string;
  osIsInferred: boolean; // True if OS was inferred from logSource/process rather than native CMDB
  containmentStatus: ContainmentState;
  containmentRationale: string;
  associatedTasks: EndpointTaskSummary[];
  associatedAlerts: EndpointAlertSummary[];
  dataSources: string[];
  provenance: string;
  isObservedData: boolean;
}

/**
 * Normalizes host or asset names into a consistent uppercase endpoint key.
 */
function normalizeAssetIdentifier(asset: string): string {
  // Strip domain prefix e.g. "DOMAIN\hostname" or IP parentheses
  const cleaned = asset.replace(/^[A-Za-z0-9_-]+\\/, '').split(' ')[0].trim().toUpperCase();
  return cleaned;
}

/**
 * Aggregates authorized endpoints from IT Operations tasks and scoped alerts.
 */
export function buildEndpointInventory(params: {
  tasks: IncidentTask[];
  scopedAlerts: SecurityAlert[];
  auditLogs?: AuditLogEntry[];
  currentUser?: UserProfile;
}): EndpointRecord[] {
  const { tasks, scopedAlerts, auditLogs = [], currentUser } = params;

  // 1. Strict Super Admin Operational Isolation Guard
  if (currentUser?.role === 'super_admin') {
    return [];
  }

  // 2. Strict Role Scoping for IT Operations
  // Filter tasks assigned to it_operations (or all tasks if not specified)
  const itTasks = currentUser?.role === 'it_operations'
    ? tasks.filter((t) => t.assignedRole === 'it_operations')
    : tasks;

  // Derive allowed alert IDs strictly from assigned tasks
  const allowedAlertIds = new Set<string>();
  for (const t of itTasks) {
    if (t.associatedAlertId) {
      allowedAlertIds.add(t.associatedAlertId);
    }
  }

  // Filter alerts strictly to those allowed for IT Operations
  const authorizedAlerts = currentUser?.role === 'it_operations'
    ? scopedAlerts.filter((a) => allowedAlertIds.has(a.id))
    : scopedAlerts;

  const endpointMap = new Map<string, EndpointRecord>();

  // Index authorized alerts by normalized hostname and by alert ID
  const alertsById = new Map<string, SecurityAlert>();
  const alertsByHost = new Map<string, SecurityAlert[]>();

  for (const alert of authorizedAlerts) {
    alertsById.set(alert.id, alert);
    const norm = normalizeAssetIdentifier(alert.hostName);
    const list = alertsByHost.get(norm) || [];
    list.push(alert);
    alertsByHost.set(norm, list);
  }

  // Helper to extract OS details from evidence log sources honestly
  function determineOsDetails(alert?: SecurityAlert): { os: string; isInferred: boolean } {
    if (!alert) {
      return { os: 'Not recorded in telemetry', isInferred: false };
    }

    const logSource = alert.evidence?.logSource || '';
    const proc = alert.evidence?.processName || '';

    if (logSource.includes('Sysmon') || logSource.includes('Security Event Log') || logSource.includes('WMI') || proc.endsWith('.exe')) {
      return {
        os: 'Windows Server / Workstation (Inferred from Windows Event Log)',
        isInferred: true,
      };
    }
    if (logSource.toLowerCase().includes('linux') || proc.includes('nginx') || proc.includes('sshd')) {
      return {
        os: 'Linux Enterprise (Inferred from service daemon)',
        isInferred: true,
      };
    }

    return { os: 'Not recorded in telemetry', isInferred: false };
  }

  // Helper to evaluate containment status from audit trail and tasks
  function evaluateContainment(
    hostname: string,
    hostTasks: IncidentTask[],
    hostAuditLogs: AuditLogEntry[]
  ): { status: ContainmentState; rationale: string } {
    const norm = hostname.toUpperCase();

    // Check if an isolate_host action succeeded in audit logs for this target
    const isolationLog = hostAuditLogs.find(
      (log) =>
        (log.actionType === 'isolate_host' || log.actionType === 'unisolate_host') &&
        log.targetResource.toUpperCase().includes(norm) &&
        (log.status === 'SIMULATED_SUCCESS' || log.status === 'SUCCESS')
    );

    if (isolationLog) {
      if (isolationLog.actionType === 'unisolate_host') {
        return {
          status: 'Active / Standard Network',
          rationale: `Network unisolation confirmed per audit log ${isolationLog.id}.`,
        };
      }
      return {
        status: 'Simulated Isolated',
        rationale: `Simulated host quarantine executed per audit record ${isolationLog.id} (${isolationLog.justification || 'Containment Playbook'}).`,
      };
    }

    // Check task status
    const isolationTask = hostTasks.find((t) => t.suggestedActionType === 'isolate_host');
    if (isolationTask) {
      if (isolationTask.status === 'completed') {
        return {
          status: 'Verified Recovered',
          rationale: `Remediation Task ${isolationTask.id} verified and closed by operator.`,
        };
      }
      if (isolationTask.status === 'in_progress' || isolationTask.status === 'pending') {
        return {
          status: 'Quarantine Pending',
          rationale: `Task ${isolationTask.id} (${isolationTask.status}) requires host containment verification.`,
        };
      }
    }

    return {
      status: 'Active / Standard Network',
      rationale: 'No containment isolation action recorded for this host.',
    };
  }

  // 3. Populate endpoints from assigned IT Operations Tasks
  for (const task of itTasks) {
    const rawAsset = task.targetAsset || 'UNKNOWN-ASSET';
    const normKey = normalizeAssetIdentifier(rawAsset);

    // Look for matching scoped alert
    let matchingAlert: SecurityAlert | undefined;
    if (task.associatedAlertId) {
      matchingAlert = alertsById.get(task.associatedAlertId);
    }
    if (!matchingAlert) {
      const candidates = alertsByHost.get(normKey);
      if (candidates && candidates.length > 0) {
        matchingAlert = candidates[0];
      }
    }

    let record = endpointMap.get(normKey);
    if (!record) {
      const { os, isInferred } = determineOsDetails(matchingAlert);
      const containment = evaluateContainment(rawAsset, [task], auditLogs);

      const ipAddress = matchingAlert?.evidence?.hostIp || matchingAlert?.sourceIp || 'Not available';
      const fqdn = matchingAlert?.evidence?.hostFqdn || 'Not available';

      const dataSources: string[] = ['IT Operations Task Registry'];
      if (matchingAlert?.evidence?.logSource) {
        dataSources.push(matchingAlert.evidence.logSource);
      }

      record = {
        id: `EP-${normKey}`,
        hostname: matchingAlert?.hostName || rawAsset,
        fqdn,
        ipAddress,
        osDetails: os,
        osIsInferred: isInferred,
        containmentStatus: containment.status,
        containmentRationale: containment.rationale,
        associatedTasks: [],
        associatedAlerts: [],
        dataSources,
        provenance: 'Derived from Assigned IT Tasks & Scoped Alert Telemetry (Synthetic Demonstration Data)',
        isObservedData: Boolean(matchingAlert),
      };
      endpointMap.set(normKey, record);
    }

    // Append task summary
    if (!record.associatedTasks.some((t) => t.taskId === task.id)) {
      record.associatedTasks.push({
        taskId: task.id,
        title: task.title,
        status: task.status,
        priority: task.priority,
        suggestedActionType: task.suggestedActionType,
        createdAt: task.createdAt,
      });
    }

    // Append alert summary if present
    if (matchingAlert && !record.associatedAlerts.some((a) => a.alertId === matchingAlert!.id)) {
      record.associatedAlerts.push({
        alertId: matchingAlert.id,
        title: matchingAlert.title,
        severity: matchingAlert.severity,
        mitreTechniqueId: matchingAlert.mitreTechniqueId,
        detectedAt: matchingAlert.detectedAt,
      });
    }
  }

  // 4. Also capture any authorized alerts that might not have an existing task yet
  for (const alert of authorizedAlerts) {
    const normKey = normalizeAssetIdentifier(alert.hostName);
    let record = endpointMap.get(normKey);

    if (!record) {
      const { os, isInferred } = determineOsDetails(alert);
      const containment = evaluateContainment(alert.hostName, [], auditLogs);
      const ipAddress = alert.evidence?.hostIp || alert.sourceIp || 'Not available';
      const fqdn = alert.evidence?.hostFqdn || 'Not available';

      record = {
        id: `EP-${normKey}`,
        hostname: alert.hostName,
        fqdn,
        ipAddress,
        osDetails: os,
        osIsInferred: isInferred,
        containmentStatus: containment.status,
        containmentRationale: containment.rationale,
        associatedTasks: [],
        associatedAlerts: [],
        dataSources: ['Scoped Incident Alert Telemetry', alert.evidence?.logSource || 'Telemetry Log'],
        provenance: 'Derived from Scoped Alert Telemetry (Synthetic Demonstration Data)',
        isObservedData: true,
      };
      endpointMap.set(normKey, record);
    }

    if (!record.associatedAlerts.some((a) => a.alertId === alert.id)) {
      record.associatedAlerts.push({
        alertId: alert.id,
        title: alert.title,
        severity: alert.severity,
        mitreTechniqueId: alert.mitreTechniqueId,
        detectedAt: alert.detectedAt,
      });
    }
  }

  return Array.from(endpointMap.values());
}
