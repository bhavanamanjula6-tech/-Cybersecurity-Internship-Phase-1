import React, { useState, useMemo } from 'react';
import { Modal } from '../common/Modal';
import { Button } from '../common/Button';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { SecurityAlert } from '../../types/alert';
import { UserProfile } from '../../types/auth';
import { MitreTechnique, MitreTactic } from '../../types/mitre';
import {
  SimulatedDetectionEngine,
  SimulatedWindowsEvent,
} from '../../services/simulatedDetectionEngine';
import { DetectionRuleService } from '../../services/detectionRuleService';
import { AUTHENTIC_MITRE_TECHNIQUES, AUTHENTIC_MITRE_TACTICS } from '../../data/mitreData';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  Server,
  FileCode2,
  Terminal,
  ShieldCheck,
  Cpu,
} from 'lucide-react';

interface SimulateControlledAlertModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSimulateAlert: (alert: SecurityAlert) => Promise<void>;
  currentUser: UserProfile;
  techniques?: MitreTechnique[];
  tactics?: MitreTactic[];
}

type SupportedSimTechnique = 'T1486' | 'T1047' | 'T1053.005';

interface ScenarioOption {
  id: SupportedSimTechnique;
  name: string;
  category: string;
  process: string;
  commandSnippet: string;
}

const SUPPORTED_SCENARIOS: ScenarioOption[] = [
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact (Shadow Copy Deletion)',
    category: 'Impact (TA0040)',
    process: 'vssadmin.exe',
    commandSnippet: 'vssadmin.exe delete shadows /all /quiet',
  },
  {
    id: 'T1047',
    name: 'Windows Management Instrumentation (WMI Execution)',
    category: 'Execution (TA0002)',
    process: 'WMIC.exe',
    commandSnippet: 'wmic.exe /node:SIM-WIN-001 process call create ...',
  },
  {
    id: 'T1053.005',
    name: 'Scheduled Task/Job (Scheduled Task Creation)',
    category: 'Persistence / Execution (TA0002)',
    process: 'schtasks.exe',
    commandSnippet: 'schtasks.exe /create /tn "SecurityHealthCheck_Sim" ...',
  },
];

export const SimulateControlledAlertModal: React.FC<SimulateControlledAlertModalProps> = ({
  isOpen,
  onClose,
  onSimulateAlert,
  currentUser,
  techniques = AUTHENTIC_MITRE_TECHNIQUES,
  tactics = AUTHENTIC_MITRE_TACTICS,
}) => {
  const [selectedTechId, setSelectedTechId] = useState<SupportedSimTechnique>('T1486');
  const [isPersisting, setIsPersisting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // 1. Resolve controlled simulated telemetry event for the selected technique
  const simulatedEvent = useMemo<SimulatedWindowsEvent | null>(() => {
    return SimulatedDetectionEngine.getSimulatedEventForTechnique(selectedTechId);
  }, [selectedTechId]);

  // 2. Generate or find authentic Sigma rule draft for evaluation
  const evaluationResult = useMemo(() => {
    if (!simulatedEvent) return null;

    const allTechs = techniques.length > 0 ? techniques : AUTHENTIC_MITRE_TECHNIQUES;
    const allTactics = tactics.length > 0 ? tactics : AUTHENTIC_MITRE_TACTICS;

    const tech = allTechs.find((t) => t.id === selectedTechId) || {
      id: selectedTechId,
      name: SUPPORTED_SCENARIOS.find((s) => s.id === selectedTechId)?.name || selectedTechId,
      tactics: ['TA0002'],
      dataSources: ['Process: Process Creation'],
      platforms: ['Windows'],
      mitigationIds: [],
      description: 'Controlled simulation technique target.',
      detectionGuidance: 'Monitor process creation telemetry.',
      sourceUrl: `https://attack.mitre.org/techniques/${selectedTechId.replace('.', '/')}/`,
    };

    const tactic = allTactics.find((t) => t.id === tech.tactics[0]);
    const draft = DetectionRuleService.generateSigmaTemplateFromTechnique(tech, tactic);

    // Dynamic evaluation against draft selection criteria
    return SimulatedDetectionEngine.evaluateAgainstDraft(draft, simulatedEvent);
  }, [selectedTechId, simulatedEvent, techniques, tactics]);

  if (!isOpen) return null;

  const handlePersistAlert = async () => {
    if (isPersisting) return;

    // Strict role authorization verification
    if (currentUser.role !== 'soc_analyst') {
      setErrorMessage(
        `Access Denied: Role "${currentUser.role}" is not authorized to persist operational alerts. Only approved SOC Analysts have INSERT privileges under alerts_insert_policy.`
      );
      return;
    }

    if (!evaluationResult?.matched || !evaluationResult.simulatedAlert) {
      setErrorMessage('Rule evaluation did not match. Cannot persist an unverified alert.');
      return;
    }

    setIsPersisting(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      // Invoke parent dispatcher which delegates to alertRepo.addSimulatedAlert()
      await onSimulateAlert(evaluationResult.simulatedAlert);

      setSuccessMessage(
        `Alert "${evaluationResult.simulatedAlert.id}" successfully persisted to operational database and dispatched to Alert Triage Queue.`
      );

      // Auto-close after brief confirmation window
      setTimeout(() => {
        onClose();
      }, 1400);
    } catch (err: any) {
      setErrorMessage(
        err?.message || 'Database persistence failed. Check Supabase connection and role authorization.'
      );
    } finally {
      setIsPersisting(false);
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Controlled Simulated Event Detection Pipeline"
      subtitle="Phase 1: Generate & evaluate synthetic Windows telemetry against Sigma rules"
      maxWidth="xl"
      footer={
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-500 dark:text-slate-400">
            <ProvenanceBadge type="controlled_simulation" label="CONTROLLED SIMULATION" />
            <span>Role: <strong className="text-slate-800 dark:text-slate-200 uppercase">{currentUser.role}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onClose}
              disabled={isPersisting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={handlePersistAlert}
              disabled={isPersisting || !evaluationResult?.matched || currentUser.role !== 'soc_analyst'}
              className="bg-amber-600 hover:bg-amber-700 text-white font-mono text-xs flex items-center gap-1.5"
            >
              <Play className={`w-3.5 h-3.5 ${isPersisting ? 'animate-spin' : ''}`} />
              {isPersisting ? 'Persisting Alert...' : 'Dispatch & Persist to Queue'}
            </Button>
          </div>
        </div>
      }
    >
      <div className="p-4 space-y-4 text-xs">
        {/* Feedback Banners */}
        {successMessage && (
          <div className="p-3 bg-emerald-950/60 border border-emerald-800 text-emerald-200 rounded text-xs flex items-center gap-2 font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMessage}</span>
          </div>
        )}

        {errorMessage && (
          <div className="p-3 bg-rose-950/60 border border-rose-800 text-rose-200 rounded text-xs flex items-center gap-2 font-mono">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Scenario Selection */}
        <div className="space-y-1.5">
          <label className="font-mono text-[11px] font-bold text-slate-700 dark:text-slate-300 uppercase block">
            Select Controlled Simulation Scenario:
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {SUPPORTED_SCENARIOS.map((scenario) => {
              const isSelected = selectedTechId === scenario.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => {
                    setSelectedTechId(scenario.id);
                    setErrorMessage(null);
                    setSuccessMessage(null);
                  }}
                  className={`p-2.5 rounded border text-left transition cursor-pointer space-y-1 ${
                    isSelected
                      ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-500 text-amber-900 dark:text-amber-200 ring-1 ring-amber-500/50'
                      : 'bg-slate-50 dark:bg-slate-900/60 border-slate-200 dark:border-slate-800 hover:border-slate-400 text-slate-700 dark:text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono font-bold text-xs">
                    <span className="text-amber-600 dark:text-amber-400">{scenario.id}</span>
                    <span className="text-[10px] opacity-75">{scenario.process}</span>
                  </div>
                  <div className="font-semibold text-[11px] line-clamp-1">{scenario.name}</div>
                  <div className="text-[10px] font-mono text-slate-500 truncate">{scenario.commandSnippet}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Telemetry Event Details */}
        {simulatedEvent && (
          <div className="bg-slate-950 border border-slate-800 rounded p-3 space-y-2 text-slate-300">
            <div className="flex items-center justify-between font-mono text-[11px]">
              <span className="font-bold text-slate-200 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                Simulated Windows Process Creation (Sysmon Event ID {simulatedEvent.eventId})
              </span>
              <span className="text-slate-400">Host: <strong className="text-cyan-400">{simulatedEvent.host}</strong></span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono bg-slate-900 p-2 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] block">IMAGE (Process)</span>
                <span className="text-emerald-400 break-all">{simulatedEvent.image}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block">COMMAND LINE</span>
                <span className="text-amber-300 break-all">{simulatedEvent.commandLine}</span>
              </div>
            </div>
          </div>
        )}

        {/* Rule Evaluation Verdict */}
        {evaluationResult && (
          <div
            className={`p-3 rounded border text-xs font-mono space-y-1.5 ${
              evaluationResult.matched
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                : 'bg-rose-950/40 border-rose-800 text-rose-200'
            }`}
          >
            <div className="flex items-center justify-between font-bold">
              <span className="flex items-center gap-1.5">
                {evaluationResult.matched ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <span>Sigma Detection Criteria Satisfied</span>
                  </>
                ) : (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    <span>Detection Evaluation Failed</span>
                  </>
                )}
              </span>
              <span className="text-[10px] opacity-75">{evaluationResult.ruleId}</span>
            </div>

            <p className="text-[11px] text-slate-300">{evaluationResult.rationale}</p>

            {evaluationResult.matchedConditions.length > 0 && (
              <div className="pt-1 border-t border-slate-800/60">
                <span className="text-[10px] text-emerald-400 uppercase font-bold block">Matched Conditions:</span>
                <ul className="list-disc list-inside text-[10px] text-slate-300 space-y-0.5">
                  {evaluationResult.matchedConditions.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* Generated Operational Alert Preview */}
        {evaluationResult?.simulatedAlert && (
          <div className="bg-slate-900 border border-slate-800 rounded p-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[11px] font-bold text-slate-300 uppercase">
                Generated Alert Payload (Ready for Persistence)
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                PERSISTENCE AUTHORIZED
              </span>
            </div>

            <div className="space-y-1 font-mono text-[11px]">
              <div className="flex items-center gap-2">
                <span className="text-slate-500">ID:</span>
                <strong className="text-amber-400">{evaluationResult.simulatedAlert.id}</strong>
                <span className="text-slate-500">•</span>
                <span className="text-slate-500">Technique:</span>
                <strong className="text-cyan-400">{evaluationResult.simulatedAlert.mitreTechniqueId}</strong>
                <span className="text-slate-500">•</span>
                <span className="text-slate-500">Severity:</span>
                <span className="text-rose-400 uppercase font-bold">{evaluationResult.simulatedAlert.severity}</span>
              </div>
              <div className="text-slate-200 font-semibold">{evaluationResult.simulatedAlert.title}</div>
              <p className="text-[11px] text-slate-400 line-clamp-2">{evaluationResult.simulatedAlert.description}</p>
            </div>

            <div className="text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80 flex items-center justify-between">
              <span>Provenance: {evaluationResult.simulatedAlert.provenance}</span>
              <span>Target: {evaluationResult.simulatedAlert.hostName}</span>
            </div>
          </div>
        )}

        {/* Safety & Isolation Notice */}
        <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded text-[10px] font-mono text-slate-400 leading-relaxed">
          <strong>Safe Simulation Protocol:</strong> Telemetry is strictly synthetic and client-evaluated. Dispatched alerts are tagged as <code className="text-cyan-400">is_synthetic: true</code> and ingested into the operational alert queue for detection triage, investigation playbooks, and incident response drill exercises.
        </div>
      </div>
    </Modal>
  );
};
