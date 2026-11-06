import React, { useState } from 'react';
import { SecurityAlert } from '../../types/alert';
import { ResponseActionType } from '../../types/audit';
import { UserRole } from '../../types/auth';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';
import {
  BookOpen,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  Server,
  Lock,
  Terminal,
  Activity,
  FileText,
  Info,
} from 'lucide-react';

interface PlaybookDef {
  id: string;
  name: string;
  techniqueId: string;
  threatType: string;
  recommendedAction: ResponseActionType;
  description: string;
  prerequisites: string[];
  steps: string[];
  verificationGuidance: string;
}

const STANDARD_PLAYBOOKS: PlaybookDef[] = [
  {
    id: 'IR-SOP-01',
    name: 'Credential Access / LSASS Memory Extraction',
    techniqueId: 'T1003.001',
    threatType: 'Credential Dumping',
    recommendedAction: 'isolate_host',
    description: 'Procedure for responding to unauthorized process injection or memory dump targeting lsass.exe.',
    prerequisites: [
      'Confirm process parentage and command line (e.g. procdump or mimikatz indicators)',
      'Verify target asset hostname and IP from alert telemetry',
      'Ensure SOC triage ticket is assigned',
    ],
    steps: [
      '1. Isolate endpoint from enterprise subnet via simulated host isolation.',
      '2. Collect forensic memory artifact and terminate extraction processes.',
      '3. Initiate domain credential reset for all accounts logged into host within past 2 hours.',
      '4. Generate IT Operations recovery task to collect forensic memory artifact.',
    ],
    verificationGuidance: 'Review endpoint telemetry to verify process termination and lack of subsequent egress connections.',
  },
  {
    id: 'IR-SOP-02',
    name: 'Ransomware Precursor / Shadow Copy Deletion',
    techniqueId: 'T1486',
    threatType: 'Data Encrypted for Impact',
    recommendedAction: 'isolate_host',
    description: 'Emergency containment protocol upon detection of vssadmin or shadow copy deletion commands.',
    prerequisites: [
      'Verify command line: "vssadmin delete shadows /all /quiet"',
      'Identify critical storage volumes mounted on affected server',
      'Alert IT Operations lead of potential active ransomware campaign',
    ],
    steps: [
      '1. Immediately isolate host to prevent encryption propagation across network shares.',
      '2. Notify IT Operations to verify offline storage and cold immutable backups.',
      '3. Check adjacent endpoints for identical process execution hashes.',
    ],
    verificationGuidance: 'Ensure network interface isolation flag is confirmed and no bulk file extension modifications occur.',
  },
  {
    id: 'IR-SOP-03',
    name: 'Obfuscated PowerShell Execution Cradle',
    techniqueId: 'T1059.001',
    threatType: 'Command and Scripting Interpreter',
    recommendedAction: 'collect_forensics',
    description: 'Protocol for collecting forensic evidence and isolating base64 encoded PowerShell scripts spawned from office processes.',
    prerequisites: [
      'Verify suspicious parent-child lineage (e.g., winword.exe -> powershell.exe)',
      'Examine decoded script payload for external download cradle strings',
    ],
    steps: [
      '1. Capture forensic memory package and volatile state from target host.',
      '2. Block malicious C2 IP or domain on edge perimeter proxy.',
      '3. Inspect user mailbox for phishing delivery email and quarantine message.',
    ],
    verificationGuidance: 'Verify script process PID is defunct and no scheduled tasks or registry run keys were established.',
  },
  {
    id: 'IR-SOP-04',
    name: 'Unauthorized Lateral Movement via Remote WMI',
    techniqueId: 'T1047',
    threatType: 'Windows Management Instrumentation',
    recommendedAction: 'lock_account',
    description: 'Containment protocol for unauthorized remote node command execution across domain controllers.',
    prerequisites: [
      'Verify target node destination IP and initiating service account name',
      'Confirm execution did not originate from authorized IT deployment tooling',
    ],
    steps: [
      '1. Immediately lock compromised service account to sever Kerberos authentication tickets.',
      '2. Isolate destination node pending logon session audit.',
      '3. Rotate Kerberos KRBTGT account keys if domain-wide compromise is suspected.',
    ],
    verificationGuidance: 'Confirm event ID 4624/4625 for the locked account shows authentication failure across all domain controllers.',
  },
];

interface PlaybookConsoleProps {
  alerts: SecurityAlert[];
  currentRole: UserRole;
  selectedAlertId?: string;
  onExecuteSimulation: (
    actionType: ResponseActionType,
    target: string,
    justification: string,
    alertId?: string
  ) => Promise<void>;
  onNavigateToAuditTrail?: (alertId?: string) => void;
}

export const PlaybookConsole: React.FC<PlaybookConsoleProps> = ({
  alerts,
  currentRole,
  selectedAlertId: initialSelectedAlertId,
  onExecuteSimulation,
  onNavigateToAuditTrail,
}) => {
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>(STANDARD_PLAYBOOKS[0].id);
  const [selectedAlertId, setSelectedAlertId] = useState<string>(
    initialSelectedAlertId || alerts[0]?.id || ''
  );
  const [targetAsset, setTargetAsset] = useState<string>(() => {
    if (initialSelectedAlertId) {
      const match = alerts.find((a) => a.id === initialSelectedAlertId);
      if (match) return match.hostName || match.sourceIp;
    }
    return alerts[0]?.hostName || 'ENDPOINT-PRIMARY';
  });
  const [justification, setJustification] = useState<string>('');
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionSuccess, setExecutionSuccess] = useState<string | null>(null);

  // Synchronize alert selection if incoming prop changes
  React.useEffect(() => {
    if (initialSelectedAlertId && alerts.some((a) => a.id === initialSelectedAlertId)) {
      setSelectedAlertId(initialSelectedAlertId);
      const found = alerts.find((a) => a.id === initialSelectedAlertId);
      if (found) {
        setTargetAsset(found.hostName || found.sourceIp);
      }
    }
  }, [initialSelectedAlertId, alerts]);

  const activePlaybook = STANDARD_PLAYBOOKS.find((p) => p.id === selectedPlaybookId) || STANDARD_PLAYBOOKS[0];

  const handleSelectAlert = (alertId: string) => {
    setSelectedAlertId(alertId);
    const found = alerts.find((a) => a.id === alertId);
    if (found) {
      setTargetAsset(found.hostName || found.sourceIp);
    }
  };

  const handleExecute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!justification.trim() || isExecuting) return;

    setIsExecuting(true);
    setExecutionSuccess(null);
    try {
      await onExecuteSimulation(
        activePlaybook.recommendedAction,
        targetAsset.trim(),
        justification.trim(),
        selectedAlertId || undefined
      );
      setExecutionSuccess(
        `Simulation action "${activePlaybook.recommendedAction}" for target "${targetAsset}" was successfully recorded to the audit trail and created an IT Operations task.`
      );
      setJustification('');
    } catch (err: any) {
      console.error('Playbook simulation error:', err);
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Provenance Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <BookOpen className="w-5 h-5 text-emerald-400" />
              Incident Response Playbook Console
            </h1>
            <span className="px-2 py-0.5 text-xs font-medium rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
              SOP Simulation Engine
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Standard Operating Procedures (SOPs), containment simulation checklists, and operator rationale recording.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <ProvenanceBadge
          type="synthetic_demo"
          label="SIMULATION ONLY — ZERO PRODUCTION TOUCH"
        />
        <span className="text-xs text-slate-400">
          All actions executed here are purely simulated. No real operating-system commands are issued, no live endpoints are quarantined. Actions create verifiable local audit logs and IT Operations recovery tasks.
        </span>
      </div>

      {executionSuccess && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-800 rounded-lg flex items-start gap-3">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="space-y-1 text-xs">
            <h4 className="font-semibold text-emerald-200">Simulation Confirmed & Logged</h4>
            <p className="text-emerald-300/90">{executionSuccess}</p>
            {onNavigateToAuditTrail && selectedAlertId && (
              <button
                type="button"
                onClick={() => onNavigateToAuditTrail(selectedAlertId)}
                className="text-xs underline text-emerald-200 hover:text-white pt-1"
              >
                Inspect Associated Audit Trail Entry →
              </button>
            )}
          </div>
        </div>
      )}

      {/* Main Layout Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Playbook Selector */}
        <div className="space-y-3">
          <h2 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            Approved Response SOPs
          </h2>
          <div className="space-y-2">
            {STANDARD_PLAYBOOKS.map((pb) => {
              const isSelected = pb.id === selectedPlaybookId;
              return (
                <div
                  key={pb.id}
                  onClick={() => {
                    setSelectedPlaybookId(pb.id);
                    setExecutionSuccess(null);
                  }}
                  className={`p-3.5 rounded-lg border cursor-pointer transition-colors text-xs ${
                    isSelected
                      ? 'bg-slate-900 border-emerald-500 shadow-sm'
                      : 'bg-slate-950/80 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-[11px] font-bold text-emerald-400">{pb.id}</span>
                    <span className="font-mono text-[10px] text-blue-400 bg-blue-950/60 px-1 rounded border border-blue-900/60">
                      {pb.techniqueId}
                    </span>
                  </div>
                  <div className="font-semibold text-slate-100">{pb.name}</div>
                  <div className="text-[11px] text-slate-400 mt-1 line-clamp-2">{pb.description}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right 2 Columns: Selected SOP Details & Execution Form */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800">
              <div>
                <span className="font-mono text-xs text-emerald-400 font-bold">{activePlaybook.id}</span>
                <h3 className="text-base font-bold text-slate-100">{activePlaybook.name}</h3>
                <span className="text-xs text-slate-400">{activePlaybook.threatType}</span>
              </div>
              <span className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-amber-300">
                Action: {activePlaybook.recommendedAction}
              </span>
            </div>

            {/* Prerequisites */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
                Required Operator Verification Prerequisites:
              </h4>
              <ul className="space-y-1 text-xs text-slate-300 bg-slate-950/60 p-3 rounded border border-slate-800/80">
                {activePlaybook.prerequisites.map((p, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-blue-400">•</span>
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Step-by-Step SOP Checklist */}
            <div className="space-y-2">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-purple-400" />
                Playbook Execution Steps:
              </h4>
              <div className="space-y-1.5">
                {activePlaybook.steps.map((step, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 bg-slate-950/40 rounded border border-slate-800 text-xs text-slate-200"
                  >
                    {step}
                  </div>
                ))}
              </div>
            </div>

            {/* Verification Guidance */}
            <div className="space-y-1.5">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                Containment Verification Guidance:
              </h4>
              <p className="text-xs text-slate-400 bg-slate-950/30 p-2.5 rounded border border-slate-800/60">
                {activePlaybook.verificationGuidance}
              </p>
            </div>

            {/* Simulation Execution Form */}
            <form onSubmit={handleExecute} className="pt-4 border-t border-slate-800 space-y-4">
              <h4 className="text-xs font-bold text-slate-100 flex items-center gap-2">
                <Play className="w-4 h-4 text-rose-400" />
                Execute Containment Simulation
              </h4>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                <div>
                  <label htmlFor="playbook-alert-select" className="text-slate-400 block mb-1">
                    Associate with Active Alert:
                  </label>
                  <select
                    id="playbook-alert-select"
                    value={selectedAlertId}
                    onChange={(e) => handleSelectAlert(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded p-2 focus:outline-none focus:border-emerald-500 font-mono"
                  >
                    <option value="">None (Generic Exercise)</option>
                    {alerts.map((a) => (
                      <option key={a.id} value={a.id}>
                        {a.id} — {a.title.slice(0, 35)}...
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="playbook-target-asset" className="text-slate-400 block mb-1">
                    Target Asset / Endpoint:
                  </label>
                  <input
                    id="playbook-target-asset"
                    type="text"
                    value={targetAsset}
                    onChange={(e) => setTargetAsset(e.target.value)}
                    placeholder="e.g. WORKSTATION-01 or 192.168.10.55"
                    required
                    className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded p-2 focus:outline-none focus:border-emerald-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <label htmlFor="playbook-justification" className="text-xs font-medium text-slate-300 block mb-1">
                  Mandatory Operator Rationale & Justification:
                </label>
                <textarea
                  id="playbook-justification"
                  rows={3}
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  placeholder="State the forensic indicators, verified prerequisites, and containment justification..."
                  required
                  className="w-full bg-slate-950 border border-slate-700 text-slate-200 text-xs rounded p-2.5 focus:outline-none focus:border-emerald-500 placeholder-slate-500"
                />
              </div>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2">
                <span className="text-[11px] text-slate-400 flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                  Generates an immutable simulated audit log and IT Ops task.
                </span>

                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={!justification.trim() || isExecuting || currentRole !== 'soc_analyst'}
                  className="text-xs flex items-center gap-1.5 bg-rose-600 hover:bg-rose-700 text-white"
                >
                  <Play className="w-3.5 h-3.5" />
                  {isExecuting ? 'Recording Simulation...' : `Authorize Simulated ${activePlaybook.recommendedAction}`}
                </Button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
};
