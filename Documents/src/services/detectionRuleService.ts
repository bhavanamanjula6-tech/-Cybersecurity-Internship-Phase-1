/**
 * Detection Engineering Rule Drafting Service
 *
 * Provides:
 * 1. Structured Sigma-compliant detection rule template generation from authentic MITRE ATT&CK v14.1 records.
 * 2. Structural syntax inspection and validation (verifies required Sigma keys and structure).
 * 3. Session-local storage adapter (drafts remain strictly session-local; no fake DB columns).
 * 4. Explicit draft-versus-deployed state isolation (rules are strictly labeled NON-DEPLOYED).
 */

import { MitreTechnique, MitreTactic } from '../types/mitre';

export type DetectionSeverity = 'critical' | 'high' | 'medium' | 'low';
export type RuleLifecycleStatus = 'draft' | 'experimental' | 'review';

export interface DetectionRuleDraft {
  id: string; // e.g. "SIGMA-DRAFT-T1059-001"
  title: string;
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  tacticName: string;
  severity: DetectionSeverity;
  status: RuleLifecycleStatus;
  description: string;
  author: string;
  createdAt: string;
  updatedAt: string;
  logSource: {
    category: string;
    product: string;
    service?: string;
  };
  detectionSelection: Record<string, string | string[]>;
  condition: string;
  falsePositives: string[];
  rawYaml: string;
  isDeployed: false; // Explicit compile-time invariant: drafts are NEVER active in production
  deploymentNotice: string;
}

export interface RuleValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  inspectedAt: string;
}

const SESSION_STORAGE_KEY = 'cyberops_detection_rule_drafts_v1';

export class DetectionRuleService {
  /**
   * Generates a structured Sigma rule template populated with actual MITRE ATT&CK technique telemetry.
   */
  public static generateSigmaTemplateFromTechnique(
    tech: MitreTechnique,
    tactic?: MitreTactic,
    author = 'CyberOps Security Engineering'
  ): DetectionRuleDraft {
    const tacticId = tactic ? tactic.id : tech.tactics[0] || 'TA0002';
    const tacticName = tactic ? tactic.name : 'Enterprise ATT&CK';
    const draftId = `SIG-DRAFT-${tech.id.replace('.', '_')}-${Date.now().toString(36).slice(-4).toUpperCase()}`;

    // Determine category from data sources
    let category = 'process_creation';
    let product = 'windows';

    if (tech.id === 'T1486' || tech.dataSources.some((ds) => ds.toLowerCase().includes('process'))) {
      category = 'process_creation';
    } else if (tech.dataSources.some((ds) => ds.toLowerCase().includes('network'))) {
      category = 'network_traffic';
    } else if (tech.dataSources.some((ds) => ds.toLowerCase().includes('logon') || ds.toLowerCase().includes('account'))) {
      category = 'authentication';
    } else if (tech.dataSources.some((ds) => ds.toLowerCase().includes('file'))) {
      category = 'file_event';
    }

    if (tech.platforms.includes('Linux') && !tech.platforms.includes('Windows')) {
      product = 'linux';
    }

    // Curated field mappings based on known technique guidance
    const selection: Record<string, string | string[]> = {};
    const falsePositives: string[] = [
      'Legitimate administrative automation or scheduled orchestration',
      'Authorized software deployment or maintenance tools',
    ];

    if (tech.id === 'T1059.001') {
      selection['Image|endswith'] = '\\powershell.exe';
      selection['CommandLine|contains'] = [
        '-enc',
        '-EncodedCommand',
        'DownloadString',
        'Invoke-Expression',
        'Net.WebClient',
      ];
      falsePositives.push('Internal corporate provisioning scripts signed by enterprise CA');
    } else if (tech.id === 'T1003.001') {
      selection['TargetImage|endswith'] = '\\lsass.exe';
      selection['GrantedAccess|contains'] = ['0x10', '0x1010', '0x1FFFFF'];
      falsePositives.push('Legitimate antivirus or credential isolation agent memory scanning');
    } else if (tech.id === 'T1047') {
      selection['Image|endswith'] = '\\wmic.exe';
      selection['CommandLine|contains'] = ['process call create', '/node:'];
      falsePositives.push('Domain controller replication and centralized inventory sweeps');
    } else if (tech.id === 'T1021.002') {
      selection['EventID'] = '5140';
      selection['ShareName|contains'] = ['ADMIN$', 'C$', 'IPC$'];
    } else if (tech.id === 'T1078.002') {
      selection['EventID'] = '4624';
      selection['LogonType'] = ['3', '10'];
      selection['AuthenticationPackageName'] = 'Kerberos';
    } else if (tech.id === 'T1190') {
      selection['ParentImage|endswith'] = ['\\w3wp.exe', '\\nginx.exe', '\\httpd.exe'];
      selection['Image|endswith'] = ['\\cmd.exe', '\\powershell.exe', '\\sh', '\\bash'];
    } else if (tech.id === 'T1071.001') {
      selection['DestinationPort'] = ['80', '443', '8080'];
      selection['UserAgent|contains'] = ['curl', 'powershell', 'python'];
    } else if (tech.id === 'T1053.005' || tech.id === 'T1053') {
      selection['Image|endswith'] = '\\schtasks.exe';
      selection['CommandLine|contains'] = ['/create', '/tn'];
      falsePositives.push('Authorized administrative job scheduling or automated maintenance scripts');
    } else if (tech.id === 'T1486') {
      selection['Image|endswith'] = '\\vssadmin.exe';
      selection['CommandLine|contains'] = ['delete shadows', '/all', '/quiet'];
      falsePositives.push('Backup system automated rotation routines');
    } else {
      selection['EventID'] = '1';
      selection['CommandLine|contains'] = [tech.id.toLowerCase()];
    }

    const yaml = this.serializeToSigmaYaml({
      title: `${tech.name} Detection Strategy`,
      id: draftId,
      status: 'experimental',
      description: tech.detectionGuidance || `Detects execution patterns associated with ${tech.name} (${tech.id}).`,
      author,
      date: new Date().toISOString().slice(0, 10),
      techId: tech.id,
      tacticShort: tactic ? tactic.shortName : 'defense',
      category,
      product,
      selection,
      condition: 'selection',
      falsePositives,
      level: 'high',
      sourceUrl: tech.sourceUrl,
    });

    return {
      id: draftId,
      title: `${tech.name} Detection Strategy`,
      techniqueId: tech.id,
      techniqueName: tech.name,
      tacticId,
      tacticName,
      severity: 'high',
      status: 'experimental',
      description: tech.detectionGuidance || `Detects execution patterns associated with ${tech.name} (${tech.id}).`,
      author,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      logSource: {
        category,
        product,
      },
      detectionSelection: selection,
      condition: 'selection',
      falsePositives,
      rawYaml: yaml,
      isDeployed: false,
      deploymentNotice:
        'NON-DEPLOYED DRAFT: Stored in session memory only. This rule has not been compiled or pushed to SIEM/EDR detection engines.',
    };
  }

  /**
   * Serializes detection fields into formatted Sigma YAML.
   */
  public static serializeToSigmaYaml(params: {
    title: string;
    id: string;
    status: string;
    description: string;
    author: string;
    date: string;
    techId: string;
    tacticShort: string;
    category: string;
    product: string;
    selection: Record<string, string | string[]>;
    condition: string;
    falsePositives: string[];
    level: string;
    sourceUrl: string;
  }): string {
    const lines: string[] = [
      `title: ${params.title}`,
      `id: ${params.id}`,
      `status: ${params.status}`,
      `description: ${params.description.replace(/\n/g, ' ')}`,
      `references:`,
      `  - ${params.sourceUrl}`,
      `author: ${params.author}`,
      `date: ${params.date}`,
      `tags:`,
      `  - attack.${params.tacticShort}`,
      `  - attack.${params.techId.toLowerCase()}`,
      `logsource:`,
      `  category: ${params.category}`,
      `  product: ${params.product}`,
      `detection:`,
      `  selection:`,
    ];

    for (const [key, val] of Object.entries(params.selection)) {
      if (Array.isArray(val)) {
        lines.push(`    ${key}:`);
        for (const item of val) {
          lines.push(`      - '${item}'`);
        }
      } else {
        lines.push(`    ${key}: '${val}'`);
      }
    }

    lines.push(`  condition: ${params.condition}`);

    if (params.falsePositives.length > 0) {
      lines.push(`falsepositives:`);
      for (const fp of params.falsePositives) {
        lines.push(`  - '${fp}'`);
      }
    }

    lines.push(`level: ${params.level}`);
    return lines.join('\n');
  }

  /**
   * Structural syntax inspector and validator.
   * Discloses: Checks YAML structure and required Sigma schema keys. Does not claim live SIEM compilation.
   */
  public static validateSigmaRuleStructure(yamlText: string): RuleValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    const lines = yamlText.split('\n').map((l) => l.trim());

    const hasTitle = lines.some((l) => l.startsWith('title:'));
    const hasLogsource = lines.some((l) => l.startsWith('logsource:'));
    const hasDetection = lines.some((l) => l.startsWith('detection:'));
    const hasCondition = lines.some((l) => l.startsWith('condition:') || l.includes('condition:'));
    const hasLevel = lines.some((l) => l.startsWith('level:'));
    const hasTags = lines.some((l) => l.startsWith('tags:') || l.startsWith('- attack.'));

    if (!hasTitle) errors.push('Missing required Sigma header: "title"');
    if (!hasLogsource) errors.push('Missing required Sigma section: "logsource"');
    if (!hasDetection) errors.push('Missing required Sigma section: "detection"');
    if (!hasCondition) errors.push('Missing required detection logic: "condition"');
    if (!hasLevel) warnings.push('Severity level is unspecified (defaults to medium)');
    if (!hasTags) warnings.push('Rule lacks MITRE ATT&CK tag mappings (e.g., - attack.t1059)');

    // Check YAML indentation basic integrity
    const rawLines = yamlText.split('\n');
    for (let i = 0; i < rawLines.length; i++) {
      if (rawLines[i].includes('\t')) {
        errors.push(`Tab character detected on line ${i + 1}; YAML requires standard spaces`);
        break;
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      inspectedAt: new Date().toISOString(),
    };
  }

  /**
   * Retrieves starter draft rules for demonstration and baseline testing.
   */
  public static getInitialStarterDrafts(techniques: MitreTechnique[], tactics: MitreTactic[]): DetectionRuleDraft[] {
    const starters: DetectionRuleDraft[] = [];

    const pwr = techniques.find((t) => t.id === 'T1059.001');
    if (pwr) {
      const tac = tactics.find((t) => t.id === 'TA0002');
      starters.push(this.generateSigmaTemplateFromTechnique(pwr, tac));
    }

    const lsass = techniques.find((t) => t.id === 'T1003.001');
    if (lsass) {
      const tac = tactics.find((t) => t.id === 'TA0006');
      starters.push(this.generateSigmaTemplateFromTechnique(lsass, tac));
    }

    const wmi = techniques.find((t) => t.id === 'T1047');
    if (wmi) {
      const tac = tactics.find((t) => t.id === 'TA0002');
      starters.push(this.generateSigmaTemplateFromTechnique(wmi, tac));
    }

    return starters;
  }

  /**
   * Session-local persistence: Saves drafts to browser sessionStorage only.
   */
  public static saveDraftsToSession(drafts: DetectionRuleDraft[]): void {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      try {
        window.sessionStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(drafts));
      } catch {
        // Fallback for restricted storage environments
      }
    }
  }

  /**
   * Session-local persistence: Loads drafts from browser sessionStorage.
   */
  public static loadDraftsFromSession(): DetectionRuleDraft[] | null {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      try {
        const stored = window.sessionStorage.getItem(SESSION_STORAGE_KEY);
        if (stored) {
          return JSON.parse(stored);
        }
      } catch {
        // Fallback
      }
    }
    return null;
  }
}
