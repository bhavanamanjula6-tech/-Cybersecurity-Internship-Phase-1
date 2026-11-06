/**
 * MITRE ATT&CK Enterprise Reference Types
 * Provenance: Based on MITRE ATT&CK Enterprise v14.1
 */

export interface MitreTactic {
  id: string; // e.g. "TA0001"
  name: string; // e.g. "Initial Access"
  shortName: string; // e.g. "initial-access"
  description: string;
}

export interface MitreTechnique {
  id: string; // e.g. "T1059.001" or "T1059"
  name: string; // e.g. "Command and Scripting Interpreter: PowerShell"
  tactics: string[]; // Tactic IDs, e.g. ["TA0002"]
  description: string;
  platforms: string[]; // e.g. ["Windows", "Linux", "macOS"]
  dataSources: string[]; // e.g. ["Process: Process Creation", "Script: Script Execution"]
  mitigationIds: string[]; // Mitigation IDs mapped to this technique
  detectionGuidance: string;
  sourceUrl: string; // Official MITRE reference URL
}

export interface MitreMitigation {
  id: string; // e.g. "M1038"
  name: string; // e.g. "Execution Prevention"
  description: string;
  sourceUrl: string;
}

export interface MitreDefenseCoverage {
  techniqueId: string;
  techniqueName: string;
  tacticId: string;
  coveredByDetections: boolean;
  detectionRuleCount: number;
  mitigationAvailable: boolean;
  notes: string;
}
