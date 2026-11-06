/**
 * Authentic MITRE ATT&CK Repository Implementation
 * Sources data strictly from authentic MITRE ATT&CK Enterprise v14.1 records.
 */

import { IMITRERepository } from '../IMITRERepository';
import { MitreTactic, MitreTechnique, MitreMitigation, MitreDefenseCoverage } from '../../types/mitre';
import {
  AUTHENTIC_MITRE_TACTICS,
  AUTHENTIC_MITRE_TECHNIQUES,
  AUTHENTIC_MITRE_MITIGATIONS,
} from '../../data/mitreData';

export class LocalMITRERepository implements IMITRERepository {
  async getTactics(): Promise<MitreTactic[]> {
    return AUTHENTIC_MITRE_TACTICS;
  }

  async getTechniques(tacticId?: string): Promise<MitreTechnique[]> {
    if (!tacticId) {
      return AUTHENTIC_MITRE_TECHNIQUES;
    }
    return AUTHENTIC_MITRE_TECHNIQUES.filter((t) => t.tactics.includes(tacticId));
  }

  async getTechniqueById(id: string): Promise<MitreTechnique | null> {
    const tech = AUTHENTIC_MITRE_TECHNIQUES.find((t) => t.id === id);
    return tech || null;
  }

  async getMitigationById(id: string): Promise<MitreMitigation | null> {
    const mit = AUTHENTIC_MITRE_MITIGATIONS.find((m) => m.id === id);
    return mit || null;
  }

  async getDefenseCoverage(): Promise<MitreDefenseCoverage[]> {
    // Computes defense coverage based on verified techniques and their documented mitigations & detection sources
    return AUTHENTIC_MITRE_TECHNIQUES.map((tech) => {
      const hasMitigation = tech.mitigationIds.length > 0;
      const hasDetection = tech.detectionGuidance.length > 0;
      return {
        techniqueId: tech.id,
        techniqueName: tech.name,
        tacticId: tech.tactics[0] || 'TA0002',
        coveredByDetections: hasDetection,
        detectionRuleCount: tech.dataSources.length,
        mitigationAvailable: hasMitigation,
        notes: `Data sources: ${tech.dataSources.join(', ')}`,
      };
    });
  }
}
