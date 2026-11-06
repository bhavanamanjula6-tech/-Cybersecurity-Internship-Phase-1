/**
 * Controlled Simulated Windows Event Detection Pipeline (Phase 1)
 *
 * Implements:
 * 1. Controlled Windows Process Creation telemetry for T1486 (Inhibit System Recovery).
 * 2. Event normalization into Image, CommandLine, host, timestamp, and event ID fields.
 * 3. Dynamic evaluation against Sigma rule draft conditions (not a hardcoded true).
 * 4. Structured simulated alert generation with explicit provenance and evidence.
 * 5. Strict safety: non-destructive, client-evaluated, clearly disclosed as simulated.
 */

import { DetectionRuleDraft } from './detectionRuleService';
import { SecurityAlert } from '../types/alert';

export interface SimulatedWindowsEvent {
  image: string;
  commandLine: string;
  host: string;
  timestamp: string;
  eventId: number;
  source: string;
  userAccount?: string;
  parentProcess?: string;
}

export interface SimulationEvaluationResult {
  matched: boolean;
  ruleId: string;
  techniqueId: string;
  evaluatedAt: string;
  matchedConditions: string[];
  unmatchedConditions: string[];
  rationale: string;
  simulatedAlert?: SecurityAlert;
}

/**
 * Controlled synthetic Windows Process Creation event for T1486 (Inhibit System Recovery).
 * Preserved intact for backwards compatibility and baseline testing.
 */
export const T1486_SIMULATED_EVENT: SimulatedWindowsEvent = {
  image: 'C:\\Windows\\System32\\vssadmin.exe',
  commandLine: 'vssadmin.exe delete shadows /all /quiet',
  host: 'SIM-WIN-001',
  timestamp: new Date().toISOString(),
  eventId: 1, // Sysmon Process Creation / Windows Security 4688
  source: 'Controlled Simulation',
  userAccount: 'NT AUTHORITY\\SYSTEM',
  parentProcess: 'C:\\Windows\\System32\\cmd.exe',
};

/**
 * Controlled synthetic Windows Process Creation event for T1047 (Windows Management Instrumentation).
 * Non-destructive simulation creating a harmless echo command via WMIC.
 */
export const T1047_SIMULATED_EVENT: SimulatedWindowsEvent = {
  image: 'C:\\Windows\\System32\\wbem\\WMIC.exe',
  commandLine: 'wmic.exe /node:SIM-WIN-001 process call create "cmd.exe /c echo simulation_test"',
  host: 'SIM-WIN-001',
  timestamp: new Date().toISOString(),
  eventId: 1, // Sysmon Process Creation / Windows Security 4688
  source: 'Controlled Simulation',
  userAccount: 'NT AUTHORITY\\SYSTEM',
  parentProcess: 'C:\\Windows\\System32\\cmd.exe',
};

/**
 * Controlled synthetic Windows Process Creation event for T1053.005 (Scheduled Task).
 * Non-destructive simulation creating a harmless scheduled task entry via schtasks.exe.
 */
export const T1053_005_SIMULATED_EVENT: SimulatedWindowsEvent = {
  image: 'C:\\Windows\\System32\\schtasks.exe',
  commandLine: 'schtasks.exe /create /tn "SecurityHealthCheck_Sim" /tr "cmd.exe /c echo simulated_task" /sc daily /st 09:00',
  host: 'SIM-WIN-001',
  timestamp: new Date().toISOString(),
  eventId: 1, // Sysmon Process Creation / Windows Security 4688
  source: 'Controlled Simulation',
  userAccount: 'NT AUTHORITY\\SYSTEM',
  parentProcess: 'C:\\Windows\\System32\\cmd.exe',
};

export class SimulatedDetectionEngine {
  /**
   * Normalizes technique IDs across formatting variants (e.g. T1053_005 vs T1053.005).
   */
  public static normalizeTechniqueId(id: string): string {
    return (id || '').trim().toUpperCase().replace(/_/g, '.');
  }

  /**
   * Resolves the controlled simulated event for a specific ATT&CK technique ID.
   * Returns null if no controlled event scenario exists for the technique.
   */
  public static getSimulatedEventForTechnique(techniqueId: string): SimulatedWindowsEvent | null {
    const norm = this.normalizeTechniqueId(techniqueId);
    if (norm === 'T1486') return T1486_SIMULATED_EVENT;
    if (norm === 'T1047') return T1047_SIMULATED_EVENT;
    if (norm === 'T1053.005' || norm === 'T1053') return T1053_005_SIMULATED_EVENT;
    return null;
  }

  /**
   * Normalizes incoming raw telemetry event into standard attributes.
   */
  public static normalizeEvent(event: SimulatedWindowsEvent): {
    Image: string;
    CommandLine: string;
    host: string;
    timestamp: string;
    eventId: number;
    image: string;
    commandLine: string;
    source: string;
    userAccount?: string;
    parentProcess?: string;
  } {
    const img = (event.image || '').trim();
    const cmd = (event.commandLine || '').trim();
    const hst = (event.host || '').trim();
    const ts = event.timestamp || new Date().toISOString();
    const eid = Number(event.eventId || 1);
    const src = (event.source || 'Controlled Simulation').trim();

    return {
      Image: img,
      CommandLine: cmd,
      host: hst,
      timestamp: ts,
      eventId: eid,
      image: img,
      commandLine: cmd,
      source: src,
      userAccount: event.userAccount,
      parentProcess: event.parentProcess,
    };
  }

  /**
   * Evaluates an event against the conditions defined in a Sigma rule draft.
   * Selects the controlled event based on the draft's technique ID when not explicitly passed.
   * Dynamically inspects logsource, image, and command line criteria from the draft's actual model.
   */
  public static evaluateAgainstDraft(
    draft: DetectionRuleDraft,
    event?: SimulatedWindowsEvent
  ): SimulationEvaluationResult {
    const evaluatedAt = new Date().toISOString();
    const matchedConditions: string[] = [];
    const unmatchedConditions: string[] = [];

    // Select controlled event based on draft technique ID if not provided
    const targetEvent = event || this.getSimulatedEventForTechnique(draft.techniqueId);

    if (!targetEvent) {
      const rationale = `Evaluation halted: No controlled simulation telemetry available for technique "${draft.techniqueId}". Supported techniques: T1047, T1053.005, T1486.`;
      return {
        matched: false,
        ruleId: draft.id,
        techniqueId: draft.techniqueId,
        evaluatedAt,
        matchedConditions: [],
        unmatchedConditions: [
          `Draft technique (${draft.techniqueId}) does not have a mapped controlled simulation event.`,
        ],
        rationale,
      };
    }

    const normalized = this.normalizeEvent(targetEvent);

    // Check 1: Log Source Compatibility (Product and Category)
    let logsourceMatches = true;
    if (draft.logSource) {
      if (draft.logSource.product && draft.logSource.product.toLowerCase() !== 'windows') {
        logsourceMatches = false;
        unmatchedConditions.push(
          `Log source product mismatch: rule requires "${draft.logSource.product}", simulated event is Windows telemetry`
        );
      } else {
        matchedConditions.push(`Log source product satisfied: "windows"`);
      }

      if (draft.logSource.category && draft.logSource.category.toLowerCase() !== 'process_creation') {
        logsourceMatches = false;
        unmatchedConditions.push(
          `Log source category mismatch: rule targets "${draft.logSource.category}", simulated event is process creation (Event ID ${normalized.eventId})`
        );
      } else {
        matchedConditions.push(`Log source category satisfied: "process_creation"`);
      }
    }

    // Parse selection criteria dynamically from draft model and fallback to rawYaml
    const selection = draft.detectionSelection || {};
    const rawYaml = draft.rawYaml || '';

    // Check 2: Image / Process Name condition
    const imagePattern =
      (selection['Image|endswith'] as string) ||
      (selection['Image'] as string) ||
      (selection['Image|contains'] as string) ||
      (selection['processName'] as string) ||
      this.extractYamlValue(rawYaml, /Image(\|endswith|\|contains)?:\s*['"]?([^'"\n]+)['"]?/i);

    const normalizedLowerImage = normalized.image.toLowerCase();
    let imageMatches = false;

    if (imagePattern) {
      const cleanPattern = imagePattern.toLowerCase().replace(/^\\+/, '').trim();
      if (normalizedLowerImage.endsWith(cleanPattern) || normalizedLowerImage.includes(cleanPattern)) {
        imageMatches = true;
        matchedConditions.push(`Image condition matched: "${cleanPattern}" satisfied by "${normalized.image}"`);
      } else {
        unmatchedConditions.push(`Image mismatch: expected "${cleanPattern}", observed "${normalized.image}"`);
      }
    } else {
      unmatchedConditions.push('Draft rule does not specify an executable image selector.');
    }

    // Check 3: CommandLine condition
    let cmdMatches = true;
    let cmdTokens: string[] = [];

    if (Array.isArray(selection['CommandLine|contains'])) {
      cmdTokens = selection['CommandLine|contains'];
    } else if (typeof selection['CommandLine|contains'] === 'string') {
      cmdTokens = [selection['CommandLine|contains']];
    } else if (Array.isArray(selection['CommandLine'])) {
      cmdTokens = selection['CommandLine'];
    } else if (typeof selection['CommandLine'] === 'string') {
      cmdTokens = [selection['CommandLine']];
    } else {
      // Extract command line tokens from raw YAML if detectionSelection is not structured
      cmdTokens = this.extractYamlTokens(rawYaml, /CommandLine(\|contains)?:\s*\n((?:\s*-\s*['"][^'"]+['"]\s*\n?)+)/i);
    }

    const normalizedLowerCmd = normalized.commandLine.toLowerCase();

    if (cmdTokens.length > 0) {
      for (const token of cmdTokens) {
        const cleanToken = token.toLowerCase().trim();
        if (cleanToken && normalizedLowerCmd.includes(cleanToken)) {
          matchedConditions.push(`CommandLine token matched: "${cleanToken}"`);
        } else if (cleanToken) {
          cmdMatches = false;
          unmatchedConditions.push(`CommandLine token missing: "${cleanToken}"`);
        }
      }
    } else {
      unmatchedConditions.push('Draft rule does not define CommandLine selection tokens.');
      cmdMatches = false;
    }

    // Check 4: EventID if specified in draft selection or raw YAML
    let eventIdMatches = true;
    let expectedEventIds: string[] = [];

    const rawEventId = selection['EventID'] ?? selection['event_id'] ?? selection['eventId'];
    if (Array.isArray(rawEventId)) {
      expectedEventIds = rawEventId.map((id) => String(id).trim());
    } else if (rawEventId !== undefined && rawEventId !== null && String(rawEventId).trim() !== '') {
      expectedEventIds = [String(rawEventId).trim()];
    } else {
      // Check YAML fallback
      const yamlEidMatch = rawYaml.match(/EventID:\s*['"]?(\d+)['"]?/i);
      if (yamlEidMatch && yamlEidMatch[1]) {
        expectedEventIds = [yamlEidMatch[1].trim()];
      }
    }

    if (expectedEventIds.length > 0) {
      const currentEidStr = String(normalized.eventId);
      if (expectedEventIds.includes(currentEidStr)) {
        matchedConditions.push(`EventID matched: "${currentEidStr}" satisfies [${expectedEventIds.join(', ')}]`);
      } else {
        eventIdMatches = false;
        unmatchedConditions.push(
          `EventID mismatch: expected [${expectedEventIds.join(', ')}], observed "${currentEidStr}"`
        );
      }
    }

    // Overall match verdict
    const matched = logsourceMatches && imageMatches && cmdMatches && eventIdMatches;

    let rationale = '';
    if (matched) {
      rationale = `Telemetry verified: Process creation of "${normalized.image}" with arguments "${normalized.commandLine}" on host "${normalized.host}" matched rule criteria for draft "${draft.id}" (${draft.techniqueId}). (Evaluated against Sigma draft criteria: logsource category/product, process image, command line tokens, and event ID.)`;
    } else {
      rationale = `Rule evaluation failed: ${unmatchedConditions.join('; ')}.`;
    }

    let simulatedAlert: SecurityAlert | undefined;
    if (matched) {
      simulatedAlert = this.generateSimulatedAlert(draft, normalized, targetEvent);
    }

    return {
      matched,
      ruleId: draft.id,
      techniqueId: draft.techniqueId,
      evaluatedAt,
      matchedConditions,
      unmatchedConditions,
      rationale,
      simulatedAlert,
    };
  }

  /**
   * Generates a fully populated SecurityAlert record dynamically derived from the matched draft and event.
   * Generates a unique alert ID for each execution so repeated simulations never overwrite earlier alerts.
   */
  public static generateSimulatedAlert(
    draft: DetectionRuleDraft,
    normalized: ReturnType<typeof SimulatedDetectionEngine.normalizeEvent>,
    rawEvent?: SimulatedWindowsEvent
  ): SecurityAlert {
    // Generate unique alert ID: ALT-SIM-<TECH>-<TIMESTAMP_BASE36>-<RANDOM>
    const cleanTech = (draft.techniqueId || 'TECH').replace(/[^a-zA-Z0-9]/g, '-').toUpperCase();
    const timestampSegment = Date.now().toString(36).toUpperCase();
    const randomSuffix = Math.random().toString(36).substring(2, 6).toUpperCase();
    const alertId = `ALT-SIM-${cleanTech}-${timestampSegment}-${randomSuffix}`;

    const processBaseName = normalized.image.split('\\').pop() || 'process.exe';
    const parentBaseName = (rawEvent?.parentProcess || normalized.parentProcess || 'cmd.exe').split('\\').pop() || 'cmd.exe';
    const user = rawEvent?.userAccount || normalized.userAccount || 'NT AUTHORITY\\SYSTEM';

    const techTitle = draft.techniqueName || draft.title.replace(/Detection Strategy$/i, '').trim();

    return {
      id: alertId,
      title: `Controlled Simulation: ${techTitle} (${processBaseName})`,
      description: `Controlled test event detected: Execution of ${processBaseName} on ${normalized.host}. Matched Sigma rule draft ${draft.id} for technique ${draft.techniqueId} (${draft.techniqueName || draft.tacticName}).`,
      severity: draft.severity || 'high',
      status: 'new',
      detectedAt: normalized.timestamp,
      sourceIp: '192.168.10.25',
      destinationIp: undefined,
      hostName: normalized.host,
      userName: user,
      mitreTechniqueId: draft.techniqueId,
      attack_id: draft.techniqueId,
      mitreTacticId: draft.tacticId || 'TA0002',
      confidenceScore: draft.severity === 'critical' ? 95 : draft.severity === 'high' ? 90 : 80,
      evidence: {
        processName: processBaseName,
        processCommandLine: normalized.commandLine,
        parentProcess: parentBaseName,
        userAccount: user,
        hostFqdn: `${normalized.host.toLowerCase()}.corp.internal`,
        hostIp: '192.168.10.25',
        logSource: `Controlled Simulation (Windows Event ID ${normalized.eventId}: Process Creation)`,
        rawEventLog: JSON.stringify(
          {
            EventID: normalized.eventId,
            Source: normalized.source,
            Computer: normalized.host,
            TimeCreated: normalized.timestamp,
            Image: normalized.image,
            CommandLine: normalized.commandLine,
            User: user,
            MatchedRuleDraft: draft.id,
            MatchedTechnique: draft.techniqueId,
            SimulationNotice: 'NON-DESTRUCTIVE CONTROLLED TEST TELEMETRY',
          },
          null,
          2
        ),
      },
      analystNotes: [
        `[CONTROLLED SIMULATION PIPELINE]: Event ID ${normalized.eventId} matched draft ${draft.id} (${draft.techniqueId}). Injected for SOC detection verification.`,
      ],
      isSynthetic: true,
      provenance: `Controlled Simulation: Windows Event Detection Pipeline (${draft.techniqueId})`,
    };
  }

  private static extractYamlValue(yaml: string, regex: RegExp): string {
    const match = yaml.match(regex);
    return match && match[2] ? match[2].trim() : '';
  }

  private static extractYamlTokens(yaml: string, regex: RegExp): string[] {
    const match = yaml.match(regex);
    if (!match || !match[2]) return [];
    return match[2]
      .split('\n')
      .map((line) => {
        const itemMatch = line.match(/^\s*-\s*['"]?([^'"]+)['"]?/);
        return itemMatch ? itemMatch[1].trim() : '';
      })
      .filter(Boolean);
  }
}
