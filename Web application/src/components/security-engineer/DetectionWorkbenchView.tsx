import React, { useState, useEffect } from 'react';
import { MitreTechnique, MitreTactic } from '../../types/mitre';
import {
  DetectionRuleService,
  DetectionRuleDraft,
  RuleValidationResult,
  DetectionSeverity,
} from '../../services/detectionRuleService';
import { Button } from '../common/Button';
import {
  FileCode2,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  CheckCircle2,
  Info,
  ShieldAlert,
  Layers,
  Terminal,
  RefreshCw,
  ExternalLink,
  Code,
  Tag,
  Play,
  Activity,
} from 'lucide-react';
import {
  SimulatedDetectionEngine,
  SimulationEvaluationResult,
} from '../../services/simulatedDetectionEngine';
import { SecurityAlert } from '../../types/alert';
import { ProvenanceBadge } from '../common/ProvenanceBadge';

interface DetectionWorkbenchViewProps {
  techniques: MitreTechnique[];
  tactics: MitreTactic[];
  initialSelectedTechnique?: MitreTechnique | null;
  onDispatchSimulatedAlert?: (alert: SecurityAlert) => Promise<void>;
  userRole?: string;
}

export const DetectionWorkbenchView: React.FC<DetectionWorkbenchViewProps> = ({
  techniques,
  tactics,
  initialSelectedTechnique,
  onDispatchSimulatedAlert,
  userRole = 'security_engineer',
}) => {
  // Load session drafts or generate initial baseline
  const [drafts, setDrafts] = useState<DetectionRuleDraft[]>(() => {
    const loaded = DetectionRuleService.loadDraftsFromSession();
    if (loaded && loaded.length > 0) return loaded;
    return DetectionRuleService.getInitialStarterDrafts(techniques, tactics);
  });

  const [simulationResult, setSimulationResult] = useState<SimulationEvaluationResult | null>(null);
  const [simulationStatus, setSimulationStatus] = useState<'idle' | 'local_preview' | 'persisted' | 'failed'>('idle');
  const [simulationError, setSimulationError] = useState<string | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);

  const [selectedDraftId, setSelectedDraftId] = useState<string>(() => {
    return drafts.length > 0 ? drafts[0].id : '';
  });

  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<{ type: 'success' | 'warning' | 'info'; message: string } | null>(null);

  // Reset simulation result when draft selection changes
  useEffect(() => {
    setSimulationResult(null);
    setSimulationStatus('idle');
    setSimulationError(null);
  }, [selectedDraftId]);

  // Save to session storage whenever drafts mutate
  useEffect(() => {
    DetectionRuleService.saveDraftsToSession(drafts);
  }, [drafts]);

  // Pre-select or create draft from initialSelectedTechnique if specified
  useEffect(() => {
    if (initialSelectedTechnique) {
      const existing = drafts.find((d) => d.techniqueId === initialSelectedTechnique.id);
      if (existing) {
        setSelectedDraftId(existing.id);
      } else {
        const tac = tactics.find((t) => t.id === initialSelectedTechnique.tactics[0]);
        const newDraft = DetectionRuleService.generateSigmaTemplateFromTechnique(
          initialSelectedTechnique,
          tac
        );
        setDrafts((prev) => [newDraft, ...prev]);
        setSelectedDraftId(newDraft.id);
        setFeedback({
          type: 'success',
          message: `Generated new Sigma template for ${initialSelectedTechnique.id} (${initialSelectedTechnique.name}).`,
        });
      }
    }
  }, [initialSelectedTechnique]);

  const activeDraft = drafts.find((d) => d.id === selectedDraftId) || (drafts.length > 0 ? drafts[0] : null);
  const activeSimEvent = activeDraft ? SimulatedDetectionEngine.getSimulatedEventForTechnique(activeDraft.techniqueId) : null;

  // Structural syntax validation result
  const validation: RuleValidationResult = activeDraft
    ? DetectionRuleService.validateSigmaRuleStructure(activeDraft.rawYaml)
    : { isValid: false, errors: [], warnings: [], inspectedAt: '' };

  const handleCreateDraftFromTechnique = (techId: string) => {
    const tech = techniques.find((t) => t.id === techId);
    if (!tech) return;

    const tac = tactics.find((t) => t.id === tech.tactics[0]);
    const newDraft = DetectionRuleService.generateSigmaTemplateFromTechnique(tech, tac);
    setDrafts((prev) => [newDraft, ...prev]);
    setSelectedDraftId(newDraft.id);
    setFeedback({
      type: 'success',
      message: `Generated draft ${newDraft.id} from ${tech.id}.`,
    });
  };

  const handleUpdateActiveDraftYaml = (newYaml: string) => {
    if (!activeDraft) return;

    setDrafts((prev) =>
      prev.map((d) => (d.id === activeDraft.id ? { ...d, rawYaml: newYaml, updatedAt: new Date().toISOString() } : d))
    );
  };

  const handleUpdateSeverity = (sev: DetectionSeverity) => {
    if (!activeDraft) return;
    const updatedYaml = activeDraft.rawYaml.replace(/^level:\s*.*$/m, `level: ${sev}`);
    setDrafts((prev) =>
      prev.map((d) =>
        d.id === activeDraft.id
          ? { ...d, severity: sev, rawYaml: updatedYaml, updatedAt: new Date().toISOString() }
          : d
      )
    );
  };

  const handleDeleteDraft = (id: string) => {
    const remaining = drafts.filter((d) => d.id !== id);
    setDrafts(remaining);
    if (selectedDraftId === id && remaining.length > 0) {
      setSelectedDraftId(remaining[0].id);
    }
    setFeedback({
      type: 'warning',
      message: `Draft ${id} removed from session workspace.`,
    });
  };

  const handleResetToBaseline = () => {
    const baseline = DetectionRuleService.getInitialStarterDrafts(techniques, tactics);
    setDrafts(baseline);
    if (baseline.length > 0) {
      setSelectedDraftId(baseline[0].id);
    }
    setFeedback({
      type: 'success',
      message: 'Workspace restored to authentic curated Sigma baseline templates.',
    });
  };

  const handleCopyToClipboard = async () => {
    if (!activeDraft) return;
    try {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        await navigator.clipboard.writeText(activeDraft.rawYaml);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      }
    } catch {
      // Fallback
    }
  };

  const handleRunSimulation = async () => {
    if (!activeDraft) return;

    // Role boundary assertion
    if (userRole !== 'security_engineer' && userRole !== 'soc_analyst') {
      setFeedback({
        type: 'warning',
        message: `Role "${userRole}" is not authorized to run controlled event detection simulations.`,
      });
      return;
    }

    setIsSimulating(true);
    setSimulationError(null);

    try {
      // 1. Resolve controlled simulated event matching the active draft's technique
      const targetEvent = SimulatedDetectionEngine.getSimulatedEventForTechnique(activeDraft.techniqueId);

      if (!targetEvent) {
        setSimulationResult({
          matched: false,
          ruleId: activeDraft.id,
          techniqueId: activeDraft.techniqueId,
          evaluatedAt: new Date().toISOString(),
          matchedConditions: [],
          unmatchedConditions: [
            `No controlled simulation telemetry available for technique "${activeDraft.techniqueId}". The controlled pipeline currently supports T1047 (WMI), T1053.005 (Scheduled Task), and T1486 (Data Encrypted for Impact).`,
          ],
          rationale: `Simulation halted: Controlled telemetry scenario is not defined for technique ${activeDraft.techniqueId}. Select or draft a rule for T1047, T1053.005, or T1486 to simulate.`,
        });
        setSimulationStatus('idle');
        setFeedback({
          type: 'info',
          message: `Controlled simulation is available for T1047, T1053.005, and T1486. Select or draft a rule for one of these techniques to test.`,
        });
        return;
      }

      // 2. Execute dynamic rule evaluation against the technique-specific event
      const result = SimulatedDetectionEngine.evaluateAgainstDraft(activeDraft, targetEvent);
      setSimulationResult(result);

      if (result.matched && result.simulatedAlert) {
        if (userRole === 'security_engineer') {
          // Security Engineer: Generate local preview without attempting unauthorized database insert
          setSimulationStatus('local_preview');
          setSimulationError(null);
          setFeedback({
            type: 'info',
            message: `Controlled Simulation: Rule matched! Generated local simulation preview for "${result.simulatedAlert.id}". Security Engineers cannot directly create operational alerts.`,
          });
        } else if (userRole === 'soc_analyst') {
          // SOC Analyst: Require dispatch handler to exist and await successful persistence
          if (!onDispatchSimulatedAlert) {
            const errorMsg = 'Dispatch handler unavailable: cannot persist alert to database.';
            setSimulationStatus('failed');
            setSimulationError(errorMsg);
            setFeedback({
              type: 'warning',
              message: `Alert persistence failed: ${errorMsg}`,
            });
            return;
          }

          await onDispatchSimulatedAlert(result.simulatedAlert);
          setSimulationStatus('persisted');
          setSimulationError(null);
          setFeedback({
            type: 'success',
            message: `Controlled Simulation: Rule matched! Alert "${result.simulatedAlert.id}" successfully persisted to database and dispatched to Alert Triage Queue.`,
          });
        }
      } else {
        setSimulationStatus('idle');
        setFeedback({
          type: 'warning',
          message: `Controlled Simulation: No match. The draft rule conditions do not match the simulated Windows telemetry for ${activeDraft.techniqueId}.`,
        });
      }
    } catch (err: any) {
      const errorMsg = err?.message || 'Database insert failed.';
      setSimulationStatus('failed');
      setSimulationError(errorMsg);
      setFeedback({
        type: 'warning',
        message: `Alert persistence failed: ${errorMsg}`,
      });
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Workbench Header & Security Policy Notice */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <FileCode2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">
              Detection Engineering Workbench (Sigma Rules)
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
              NON-DEPLOYED DRAFT
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Author and inspect standardized detection rule templates mapped to MITRE ATT&CK enterprise techniques.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Quick Add from Curated Technique */}
          <select
            onChange={(e) => {
              if (e.target.value) {
                handleCreateDraftFromTechnique(e.target.value);
                e.target.value = '';
              }
            }}
            defaultValue=""
            className="bg-slate-950 text-slate-200 border border-slate-700 rounded px-2.5 py-1.5 text-xs focus:ring-1 focus:ring-cyan-400 focus:outline-none"
            aria-label="Generate Sigma rule from technique"
          >
            <option value="" disabled>
              + Generate from Technique...
            </option>
            {techniques.map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}: {t.name}
              </option>
            ))}
          </select>

          <Button size="xs" variant="outline" onClick={handleResetToBaseline}>
            <RefreshCw className="w-3 h-3 mr-1" />
            Reset Baseline
          </Button>
        </div>
      </div>

      {/* Persistence & Telemetry Disclosure Banner */}
      <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs space-y-1.5">
        <div className="flex items-start gap-2 text-slate-300">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <p className="font-semibold text-slate-200 text-[11px]">
              Session-Local Workspace & Validation Disclosure:
            </p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Detection rule drafts are stored strictly in <strong>browser session memory</strong> (
              <code className="text-cyan-400 font-mono">sessionStorage</code>). They are <strong>never deployed</strong> to active SIEM or EDR agents in this prototype environment. Structural validation inspects Sigma YAML schema compliance and does not execute queries against live sensors.
            </p>
          </div>
        </div>
      </div>

      {/* Feedback Toast */}
      {feedback && (
        <div
          className={`p-2.5 rounded border text-xs flex items-center justify-between gap-2 ${
            feedback.type === 'success'
              ? 'bg-emerald-950/60 border-emerald-800 text-emerald-200'
              : feedback.type === 'info'
              ? 'bg-cyan-950/60 border-cyan-800 text-cyan-200'
              : 'bg-amber-950/60 border-amber-800 text-amber-200'
          }`}
        >
          <span>{feedback.message}</span>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-200 cursor-pointer">
            ✕
          </button>
        </div>
      )}

      {/* Workbench Main Layout */}
      {drafts.length === 0 ? (
        <div className="p-12 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg text-center space-y-3">
          <FileCode2 className="w-8 h-8 text-slate-400 mx-auto" />
          <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
            No Detection Drafts in Session
          </h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Generate a rule template from any curated MITRE ATT&CK technique to start authoring.
          </p>
          <Button size="xs" variant="primary" onClick={handleResetToBaseline}>
            Restore Starter Baseline Templates
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
          {/* Left: Drafts Selector List */}
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden shadow-xs">
            <div className="p-3 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-slate-800 dark:text-slate-300 uppercase">
                Draft Rules ({drafts.length})
              </span>
              <span className="text-[10px] text-slate-500">Session Scope</span>
            </div>

            <div className="divide-y divide-slate-200 dark:divide-slate-800 max-h-[620px] overflow-y-auto">
              {drafts.map((d) => {
                const isSelected = selectedDraftId === d.id;
                const v = DetectionRuleService.validateSigmaRuleStructure(d.rawYaml);

                return (
                  <div
                    key={d.id}
                    onClick={() => setSelectedDraftId(d.id)}
                    className={`p-3 transition cursor-pointer text-xs space-y-1.5 ${
                      isSelected
                        ? 'bg-blue-50/90 dark:bg-slate-800 ring-1 ring-inset ring-cyan-500/50'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-800/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-blue-700 dark:text-cyan-400">
                        {d.techniqueId}
                      </span>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`text-[9px] font-mono px-1.5 py-0.2 rounded uppercase font-bold border ${
                            d.severity === 'critical'
                              ? 'bg-rose-950 text-rose-300 border-rose-800'
                              : d.severity === 'high'
                              ? 'bg-amber-950 text-amber-300 border-amber-800'
                              : 'bg-yellow-950 text-yellow-300 border-yellow-800'
                          }`}
                        >
                          {d.severity}
                        </span>
                        {v.isValid ? (
                          <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                            Valid
                          </span>
                        ) : (
                          <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800">
                            Syntax Issue
                          </span>
                        )}
                      </div>
                    </div>

                    <h4 className="font-semibold text-slate-900 dark:text-slate-200 text-xs truncate">
                      {d.title}
                    </h4>

                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                      <span>Log: {d.logSource.category}</span>
                      <span className="text-amber-500 dark:text-amber-400 font-bold">NON-DEPLOYED</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right: Active Rule YAML Editor & Structural Linter */}
          {activeDraft && (
            <div className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-4 shadow-xs">
              {/* Draft Header & Controls */}
              <div className="border-b border-slate-200 dark:border-slate-800 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                      {activeDraft.title}
                    </h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
                      STATUS: DRAFT
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500 mt-1">
                    <span>Target Technique: <strong className="text-blue-600 dark:text-cyan-400">{activeDraft.techniqueId} ({activeDraft.techniqueName})</strong></span>
                    <span>•</span>
                    <span>Tactic: {activeDraft.tacticId}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {/* Severity selector */}
                  <select
                    value={activeDraft.severity}
                    onChange={(e) => handleUpdateSeverity(e.target.value as DetectionSeverity)}
                    className="bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700 rounded px-2 py-1 text-xs focus:ring-1 focus:ring-cyan-400 focus:outline-none"
                    aria-label="Detection severity level"
                  >
                    <option value="critical">Severity: Critical</option>
                    <option value="high">Severity: High</option>
                    <option value="medium">Severity: Medium</option>
                    <option value="low">Severity: Low</option>
                  </select>

                  {/* Controlled Event Pipeline Simulation Trigger */}
                  <Button
                    size="xs"
                    variant={activeSimEvent ? 'primary' : 'outline'}
                    onClick={handleRunSimulation}
                    disabled={isSimulating}
                    className="font-mono text-xs flex items-center gap-1.5"
                    title={`Simulate controlled Windows process-creation event for ${activeDraft.techniqueId} against this rule`}
                  >
                    <Play className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : 'text-amber-400'}`} />
                    {isSimulating ? 'Evaluating...' : 'Simulate Windows Event'}
                  </Button>

                  <Button
                    size="xs"
                    variant="outline"
                    onClick={handleCopyToClipboard}
                    className="font-mono text-xs"
                    title="Copy Sigma rule YAML to clipboard"
                  >
                    {copied ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400 mr-1" />
                        Copied!
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 mr-1" />
                        Copy YAML
                      </>
                    )}
                  </Button>

                  <Button
                    size="xs"
                    variant="outline"
                    onClick={() => handleDeleteDraft(activeDraft.id)}
                    className="text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 dark:text-rose-400"
                    title="Delete draft from session"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </Button>
                </div>
              </div>

              {/* Structural Linter & Validation Inspector */}
              <div
                className={`p-3 rounded-lg border text-xs space-y-1.5 ${
                  validation.isValid
                    ? 'bg-emerald-950/30 border-emerald-900/60 text-emerald-300'
                    : 'bg-rose-950/40 border-rose-900/80 text-rose-300'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 font-bold font-mono">
                    {validation.isValid ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span>Sigma Schema Structural Syntax: VALID</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                        <span>Sigma Schema Structural Issues Detected</span>
                      </>
                    )}
                  </div>
                  <span className="text-[10px] font-mono opacity-80">
                    Client Schema Linter
                  </span>
                </div>

                {validation.errors.length > 0 && (
                  <ul className="text-[11px] font-mono list-disc list-inside space-y-0.5 text-rose-400 pt-1">
                    {validation.errors.map((err, i) => (
                      <li key={i}>{err}</li>
                    ))}
                  </ul>
                )}

                {validation.warnings.length > 0 && (
                  <ul className="text-[11px] font-mono list-disc list-inside space-y-0.5 text-amber-300 pt-1">
                    {validation.warnings.map((warn, i) => (
                      <li key={i}>{warn}</li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Controlled Event Pipeline Simulation Panel */}
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-2.5 text-xs">
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <ProvenanceBadge type="controlled_simulation" label="CONTROLLED SIMULATION PIPELINE" />
                    <span className="font-mono text-xs font-semibold text-slate-200">
                      {activeDraft.techniqueId}: {activeDraft.techniqueName}
                    </span>
                  </div>
                  {activeSimEvent ? (
                    <span className="text-[10px] font-mono text-slate-400">
                      Host: <strong className="text-cyan-400">{activeSimEvent.host}</strong> | Event ID: <strong className="text-cyan-400">{activeSimEvent.eventId}</strong>
                    </span>
                  ) : (
                    <span className="text-[10px] font-mono text-amber-400">
                      Scenarios available: T1047, T1053.005, T1486
                    </span>
                  )}
                </div>

                {/* Event Telemetry Summary */}
                {activeSimEvent ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono bg-slate-900/80 p-2.5 rounded border border-slate-800/80">
                    <div>
                      <span className="text-slate-400 text-[10px] block">IMAGE (Process)</span>
                      <span className="text-emerald-400 break-all">{activeSimEvent.image}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 text-[10px] block">COMMAND LINE</span>
                      <span className="text-amber-300 break-all">{activeSimEvent.commandLine}</span>
                    </div>
                  </div>
                ) : (
                  <div className="p-2.5 bg-slate-900/80 border border-slate-800/80 rounded text-[11px] text-slate-400 font-mono">
                    No controlled telemetry scenario mapped for {activeDraft.techniqueId}. Select or generate a draft for <strong>T1047 (WMI)</strong>, <strong>T1053.005 (Scheduled Task)</strong>, or <strong>T1486 (Data Encrypted for Impact)</strong> to simulate.
                  </div>
                )}

                {/* Evaluation State Display */}
                {simulationResult ? (
                  <div
                    className={`p-2.5 rounded border text-xs space-y-1.5 font-mono ${
                      simulationResult.matched
                        ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
                        : 'bg-rose-950/40 border-rose-800 text-rose-200'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold">
                      <span className="flex items-center gap-1.5">
                        {simulationResult.matched ? (
                          <>
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                            <span>RULE EVALUATION MATCHED (High-Severity Alert Generated)</span>
                          </>
                        ) : (
                          <>
                            <AlertTriangle className="w-4 h-4 text-rose-400" />
                            <span>RULE EVALUATION MISMATCH (No Alert Generated)</span>
                          </>
                        )}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {new Date(simulationResult.evaluatedAt).toLocaleTimeString()}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-300">{simulationResult.rationale}</p>

                    {simulationResult.matchedConditions.length > 0 && (
                      <div className="pt-1 border-t border-slate-800/60">
                        <span className="text-[10px] text-emerald-400 uppercase font-bold block">Matched Conditions:</span>
                        <ul className="list-disc list-inside text-[10px] text-slate-300 space-y-0.5">
                          {simulationResult.matchedConditions.map((c, idx) => (
                            <li key={idx}>{c}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {simulationResult.unmatchedConditions.length > 0 && (
                      <div className="pt-1 border-t border-slate-800/60">
                        <span className="text-[10px] text-rose-400 uppercase font-bold block">Unmatched Conditions:</span>
                        <ul className="list-disc list-inside text-[10px] text-slate-300 space-y-0.5">
                          {simulationResult.unmatchedConditions.map((c, idx) => (
                            <li key={idx}>{c}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {simulationResult.simulatedAlert && (
                      <div className="mt-2 p-2.5 bg-slate-900 border border-slate-700/80 rounded space-y-2 text-xs">
                        <div className="flex items-center justify-between flex-wrap gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-bold text-amber-400 font-mono">{simulationResult.simulatedAlert.id}</span>
                            <span className="text-slate-300 text-[11px] truncate max-w-xs">{simulationResult.simulatedAlert.title}</span>
                          </div>
                          {simulationStatus === 'local_preview' && (
                            <span className="text-[10px] font-bold text-amber-400 px-2 py-0.5 rounded bg-amber-950/80 border border-amber-800">
                              SIMULATED — LOCAL PREVIEW
                            </span>
                          )}
                          {simulationStatus === 'persisted' && (
                            <span className="text-[10px] font-bold text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-800">
                              PERSISTED TO QUEUE
                            </span>
                          )}
                          {simulationStatus === 'failed' && (
                            <span className="text-[10px] font-bold text-rose-400 px-2 py-0.5 rounded bg-rose-950/80 border border-rose-800">
                              PERSISTENCE FAILED
                            </span>
                          )}
                        </div>

                        {simulationStatus === 'local_preview' && (
                          <div className="text-[10px] text-amber-200/90 bg-amber-950/40 p-2 rounded border border-amber-900/50 leading-relaxed">
                            <strong>Security Engineer Notice:</strong> Rule matched successfully in local preview. Under SOC security architecture, Security Engineers have read-only access to operational alerts and cannot directly create operational alerts. Submit this draft as an <strong>Improvement Recommendation</strong> for SOC Analyst review.
                          </div>
                        )}

                        {simulationStatus === 'failed' && simulationError && (
                          <div className="text-[10px] text-rose-300 bg-rose-950/40 p-2 rounded border border-rose-900/50 leading-relaxed">
                            <strong>Alert Persistence Failed:</strong> {simulationError}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                    <span>Click <strong>"Simulate Windows Event"</strong> to evaluate the current Sigma draft rule conditions against this controlled telemetry event.</span>
                  </div>
                )}
              </div>

              {/* YAML Editor Textarea */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label htmlFor="sigma-editor" className="font-mono text-xs uppercase font-bold text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                    <Code className="w-4 h-4 text-cyan-400" />
                    Sigma Rule Specification (YAML)
                  </label>
                  <span className="text-[10px] text-slate-400 font-mono">
                    ID: {activeDraft.id}
                  </span>
                </div>
                <textarea
                  id="sigma-editor"
                  value={activeDraft.rawYaml}
                  onChange={(e) => handleUpdateActiveDraftYaml(e.target.value)}
                  rows={18}
                  spellCheck={false}
                  className="w-full font-mono text-xs bg-slate-950 text-slate-200 border border-slate-800 rounded-lg p-3.5 focus:ring-1 focus:ring-cyan-400 focus:outline-none leading-relaxed"
                />
              </div>

              {/* Attribution and Reference Footer */}
              <div className="pt-2 border-t border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between text-[11px] text-slate-500 font-mono gap-2">
                <span>Author: {activeDraft.author}</span>
                <span>Last Modified: {new Date(activeDraft.updatedAt).toUTCString().slice(5, 22)} UTC</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
