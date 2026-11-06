/**
 * MITRE ATT&CK Repository Interface
 * Accesses authentic MITRE Enterprise tactics, techniques, and mitigations.
 */

import { MitreTactic, MitreTechnique, MitreMitigation, MitreDefenseCoverage } from '../types/mitre';

export interface IMITRERepository {
  getTactics(): Promise<MitreTactic[]>;
  getTechniques(tacticId?: string): Promise<MitreTechnique[]>;
  getTechniqueById(id: string): Promise<MitreTechnique | null>;
  getMitigationById(id: string): Promise<MitreMitigation | null>;
  getDefenseCoverage(): Promise<MitreDefenseCoverage[]>;
}
