import React, { useMemo, useState, useEffect } from 'react';
import {
  Server,
  Lock,
  Users,
  Database,
  Cpu,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Info,
  ShieldCheck,
  UserCheck,
  UserX,
  UserMinus,
  RotateCcw,
  ShieldAlert,
  AlertTriangle,
  Clock,
  Shield,
  Filter,
  RefreshCw,
} from 'lucide-react';
import { UserProfile, UserRole, ROLE_METADATA } from '../../types/auth';
import { AuditLogEntry } from '../../types/audit';
import { Modal } from '../common/Modal';
import {
  validateRoleChange,
  validateSuspension,
  validateReactivation,
  validateDeactivation,
  isLastSuperAdmin,
  OPERATIONAL_ROLES,
} from '../../services/adminGovernanceService';
import {
  PlatformDiagnosticsService,
  DiagnosticStatus,
} from '../../services/platformDiagnosticsService';
import { supabase, isSupabaseConfigured } from '../../lib/supabaseClient';
import { getRepositories } from '../../repositories';
import { AccessControlMatrix } from './AccessControlMatrix';
import { AdminOverviewMetrics } from './AdminOverviewMetrics';
import { DataSourceInventory } from './DataSourceInventory';
import {
  calculateAdminOverviewMetrics,
  checkDatabaseConnectivity,
  checkCopilotStatusSafe,
  buildDataSourceInventory,
  DatabaseConnectivityStatus,
  DataSourceState,
} from '../../services/adminMetricsService';

interface PlatformAdminDashboardProps {
  currentUser: UserProfile;
}

const INITIAL_DEV_PROFILES: UserProfile[] = [
  {
    id: 'usr-analyst-01',
    name: 'Alex Mercer',
    email: 'alex.mercer@soc.internal',
    role: 'soc_analyst',
    callsign: 'SPECTER',
    title: 'Senior Incident Responder',
    accountStatus: 'approved',
    createdAt: '2026-10-10T08:00:00Z',
  },
  {
    id: 'usr-engineer-01',
    name: 'Elena Rostova',
    email: 'elena.rostova@soc.internal',
    role: 'security_engineer',
    callsign: 'AEGIS',
    title: 'Lead Detection Engineer',
    accountStatus: 'approved',
    createdAt: '2026-10-10T08:05:00Z',
  },
  {
    id: 'usr-itops-01',
    name: 'Marcus Vance',
    email: 'marcus.vance@soc.internal',
    role: 'it_operations',
    callsign: 'ANVIL',
    title: 'Infrastructure Specialist',
    accountStatus: 'approved',
    createdAt: '2026-10-10T08:10:00Z',
  },
  {
    id: 'usr-admin-01',
    name: 'Sarah Chen',
    email: 'sarah.chen@soc.internal',
    role: 'super_admin',
    callsign: 'VANGUARD',
    title: 'Chief Information Security Officer',
    accountStatus: 'approved',
    createdAt: '2026-10-10T08:15:00Z',
  },
  {
    id: 'usr-pending-01',
    name: 'Devon Vance',
    email: 'devon.vance@soc.internal',
    role: 'soc_analyst',
    callsign: 'PENDING',
    title: 'Associate Security Analyst',
    accountStatus: 'pending',
    createdAt: '2026-10-15T14:30:00Z',
  },
  {
    id: 'usr-pending-02',
    name: 'Morgan Blake',
    email: 'morgan.blake@soc.internal',
    role: 'it_operations',
    callsign: 'PENDING',
    title: 'Systems Administrator',
    accountStatus: 'pending',
    createdAt: '2026-10-16T07:15:00Z',
  },
];

export const PlatformAdminDashboard: React.FC<PlatformAdminDashboardProps> = ({ currentUser }) => {
  // Execute read-only platform diagnostics on render (non-destructive)
  const report = useMemo(() => PlatformDiagnosticsService.runDiagnostics(), []);
  const { auditRepo } = useMemo(() => getRepositories(), []);

  // User Governance State
  const [profiles, setProfiles] = useState<UserProfile[]>([]);
  const [profilesError, setProfilesError] = useState<string | null>(null);
  const [selectedRoles, setSelectedRoles] = useState<Record<string, UserRole>>({});
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);
  const [actionLoading, setActionLoading] = useState<Record<string, boolean>>({});
  const [statusFilter, setStatusFilter] = useState<'pending' | 'approved' | 'disabled' | 'all'>('pending');
  const [feedback, setFeedback] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Platform Audit Logs State (audit_category = 'platform')
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [isLoadingAuditLogs, setIsLoadingAuditLogs] = useState(false);
  const [auditLogsError, setAuditLogsError] = useState<string | null>(null);

  // Governance Modal State for Suspend, Reactivate, Deactivate, and Role Change
  const [governanceModal, setGovernanceModal] = useState<{
    isOpen: boolean;
    action: 'change_role' | 'suspend' | 'reactivate' | 'deactivate';
    targetUser: UserProfile | null;
    newRole?: UserRole;
    justification: string;
  }>({
    isOpen: false,
    action: 'suspend',
    targetUser: null,
    newRole: undefined,
    justification: '',
  });

  // Platform Bootstrap State
  const [bootstrapInfo, setBootstrapInfo] = useState<{
    isBootstrapped: boolean;
    bootstrappedAt: string | null;
    superAdminEmail: string | null;
    superAdminId: string | null;
  } | null>(null);
  const [isLoadingBootstrap, setIsLoadingBootstrap] = useState(false);

  // Database Connectivity & Data Source Inventory State
  const [dbStatus, setDbStatus] = useState<DatabaseConnectivityStatus>({
    isConfigured: isSupabaseConfigured(),
    isConnected: false,
    mode: 'development_demo',
    statusBadge: isSupabaseConfigured() ? 'Configured (Unverified)' : 'Local Demo',
    detail: isSupabaseConfigured()
      ? 'Supabase configuration detected; awaiting connectivity probe.'
      : 'Operating with local browser / in-memory adapters.',
    checkedAt: new Date().toISOString(),
  });
  const [isCheckingDb, setIsCheckingDb] = useState(false);
  const [copilotStatus, setCopilotStatus] = useState<{
    state: DataSourceState;
    detail: string;
    modelConfigured: boolean;
  }>({
    state: 'Standby',
    detail: 'Initializing copilot status probe...',
    modelConfigured: false,
  });

  // Load user profiles without silent fallback when Supabase is configured
  const fetchProfiles = async () => {
    setIsLoadingUsers(true);
    if (isSupabaseConfigured() && supabase) {
      try {
        const { data, error } = await supabase
          .from('user_profiles')
          .select('*')
          .order('created_at', { ascending: false });

        if (error) {
          setProfilesError(`Supabase query failed: ${error.message} (${error.code || 'UNKNOWN'})`);
          setProfiles([]);
          setIsLoadingUsers(false);
          return;
        }

        if (data) {
          const mapped: UserProfile[] = data.map((r: any) => ({
            id: r.id,
            name: r.name,
            email: r.email,
            role: r.role as UserRole,
            callsign: r.callsign || 'OPERATOR',
            title: r.title || 'Security Operator',
            avatarUrl: r.avatar_url,
            accountStatus: r.account_status,
            approvedBy: r.approved_by,
            approvedAt: r.approved_at,
            createdAt: r.created_at,
          }));
          setProfiles(mapped);
          setProfilesError(null);
          setIsLoadingUsers(false);
          return;
        }
      } catch (err: any) {
        setProfilesError(`Network or database exception fetching profiles: ${err?.message || 'Unknown error'}`);
        setProfiles([]);
        setIsLoadingUsers(false);
        return;
      }
    }
    // Only use initial dev profiles if Supabase is completely unconfigured (pure local mode)
    setProfiles(INITIAL_DEV_PROFILES);
    setProfilesError(null);
    setIsLoadingUsers(false);
  };

  // Fetch platform governance audit logs
  const fetchAdminAuditLogs = async () => {
    setIsLoadingAuditLogs(true);
    setAuditLogsError(null);
    try {
      const logs = await auditRepo.getLogsForUser(currentUser);
      setAuditLogs(logs || []);
    } catch (err: any) {
      setAuditLogsError(err?.message || 'Failed to retrieve platform governance audit logs.');
      setAuditLogs([]);
    } finally {
      setIsLoadingAuditLogs(false);
    }
  };

  const fetchBootstrapInfo = async () => {
    if (isSupabaseConfigured() && supabase) {
      setIsLoadingBootstrap(true);
      try {
        const { data, error } = await supabase
          .from('platform_bootstrap_state')
          .select('*')
          .eq('id', 1)
          .maybeSingle();

        if (!error && data) {
          setBootstrapInfo({
            isBootstrapped: Boolean(data.is_bootstrapped),
            bootstrappedAt: data.bootstrapped_at,
            superAdminEmail: data.super_admin_email,
            superAdminId: data.super_admin_id,
          });
        }
      } catch {
        // Silent fallback
      } finally {
        setIsLoadingBootstrap(false);
      }
    }
  };

  const probeDatabase = async () => {
    setIsCheckingDb(true);
    try {
      const result = await checkDatabaseConnectivity();
      setDbStatus(result);
    } catch (err: any) {
      setDbStatus({
        isConfigured: isSupabaseConfigured(),
        isConnected: false,
        mode: 'development_demo',
        statusBadge: 'Unreachable',
        detail: 'Database connectivity probe threw an exception.',
        errorMessage: err?.message,
        checkedAt: new Date().toISOString(),
      });
    } finally {
      setIsCheckingDb(false);
    }
  };

  const probeCopilot = async () => {
    try {
      const result = await checkCopilotStatusSafe();
      setCopilotStatus(result);
    } catch {
      setCopilotStatus({
        state: 'Standby',
        detail: 'Copilot status probe timed out. Running in deterministic advisory mode.',
        modelConfigured: false,
      });
    }
  };

  useEffect(() => {
    fetchProfiles();
    fetchBootstrapInfo();
    probeDatabase();
    probeCopilot();
    fetchAdminAuditLogs();
  }, []);

  // Compute Admin Overview metrics and Data Source Inventory
  const overviewStats = useMemo(() => calculateAdminOverviewMetrics(profiles), [profiles]);
  const inventoryItems = useMemo(
    () =>
      buildDataSourceInventory({
        dbStatus,
        copilotStatus,
        userCount: profiles.length,
      }),
    [dbStatus, copilotStatus, profiles.length]
  );

  const handleRoleChange = (userId: string, role: UserRole) => {
    setSelectedRoles((prev) => ({ ...prev, [userId]: role }));
  };

  const handleApprove = async (targetUser: UserProfile) => {
    setFeedback(null);

    // Defense-in-depth: Anti-self-approval guard
    if (targetUser.id === currentUser.id) {
      setFeedback({
        type: 'error',
        message: 'Security Policy Violation: Administrators cannot approve themselves.',
      });
      return;
    }

    const assignedRole = selectedRoles[targetUser.id] || targetUser.role || 'soc_analyst';

    // Defense-in-depth: Anti-privilege-escalation
    if (assignedRole === 'super_admin') {
      setFeedback({
        type: 'error',
        message: 'Security Policy Violation: Super Admin roles cannot be assigned through user governance.',
      });
      return;
    }

    setActionLoading((prev) => ({ ...prev, [targetUser.id]: true }));

    let lastAuditId: string | undefined;

    try {
      if (isSupabaseConfigured() && supabase) {
        const { data, error } = await supabase
          .from('user_profiles')
          .update({
            account_status: 'approved',
            role: assignedRole,
            approved_by: currentUser.id,
            approved_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          })
          .eq('id', targetUser.id)
          .select();

        if (error) {
          setFeedback({ type: 'error', message: `Database update failed: ${error.message}` });
          return;
        }

        if (!data || data.length === 0) {
          setFeedback({
            type: 'error',
            message: 'Database update affected 0 rows. You may lack permission to approve this profile.',
          });
          return;
        }

        lastAuditId = data[0]?.last_audit_id;
      }

      // Record and verify platform governance audit log
      let auditConfirmed = false;
      let auditErrorMsg = '';
      try {
        await auditRepo.recordGovernanceAction(currentUser, {
          actionType: 'unlock_account',
          targetEmail: targetUser.email,
          justification: `Access approved by Super Admin ${currentUser.callsign}. Assigned role: ${assignedRole.toUpperCase()}`,
          systemNote: `Operator account ${targetUser.email} approved by Super Admin ${currentUser.id}.`,
          expectedAuditId: lastAuditId,
        });
        auditConfirmed = true;
      } catch (auditErr: any) {
        auditErrorMsg = auditErr.message || 'Audit confirmation query failed.';
      }

      // Update local state (do not roll back profile update per explicit instructions)
      setProfiles((prev) =>
        prev.map((p) =>
          p.id === targetUser.id
            ? {
                ...p,
                accountStatus: 'approved',
                role: assignedRole,
                approvedBy: currentUser.id,
                approvedAt: new Date().toISOString(),
                lastAuditId: lastAuditId || p.lastAuditId,
              }
            : p
        )
      );

      if (auditConfirmed) {
        setFeedback({
          type: 'success',
          message: `Account for ${targetUser.name} (${targetUser.email}) approved successfully as ${ROLE_METADATA[assignedRole].label}.`,
        });
        fetchAdminAuditLogs();
      } else {
        setFeedback({
          type: 'error',
          message: `Profile update may have succeeded in database, but persistent audit confirmation is unverified: ${auditErrorMsg}`,
        });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Approval operation failed.' });
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.id]: false }));
    }
  };

  const handleReject = async (targetUser: UserProfile) => {
    setFeedback(null);

    // Defense-in-depth: Anti-self-demotion
    if (targetUser.id === currentUser.id) {
      setFeedback({
        type: 'error',
        message: 'Security Policy Violation: Administrators cannot reject or disable their own account.',
      });
      return;
    }

    // Protect last super admin
    if (targetUser.role === 'super_admin') {
      const adminCount = profiles.filter(
        (p) => p.role === 'super_admin' && p.accountStatus === 'approved' && p.id !== targetUser.id
      ).length;
      if (adminCount < 1) {
        setFeedback({
          type: 'error',
          message: 'Security Policy Violation: Cannot reject or disable the last active Super Admin.',
        });
        return;
      }
    }

    setActionLoading((prev) => ({ ...prev, [targetUser.id]: true }));

    let lastAuditId: string | undefined;

    try {
      if (isSupabaseConfigured() && supabase) {
        const { data, error } = await supabase
          .from('user_profiles')
          .update({
            account_status: 'rejected',
            updated_at: new Date().toISOString(),
          })
          .eq('id', targetUser.id)
          .select();

        if (error) {
          setFeedback({ type: 'error', message: `Database update failed: ${error.message}` });
          return;
        }

        if (!data || data.length === 0) {
          setFeedback({
            type: 'error',
            message: 'Database update affected 0 rows. You may lack permission to reject this profile.',
          });
          return;
        }

        lastAuditId = data[0]?.last_audit_id;
      }

      // Record and verify platform governance audit log
      let auditConfirmed = false;
      let auditErrorMsg = '';
      try {
        await auditRepo.recordGovernanceAction(currentUser, {
          actionType: 'lock_account',
          targetEmail: targetUser.email,
          justification: `Access request rejected by Super Admin ${currentUser.callsign}.`,
          systemNote: `Access request rejected for ${targetUser.email}.`,
          expectedAuditId: lastAuditId,
        });
        auditConfirmed = true;
      } catch (auditErr: any) {
        auditErrorMsg = auditErr.message || 'Audit confirmation query failed.';
      }

      // Update local state (do not roll back profile update per explicit instructions)
      setProfiles((prev) =>
        prev.map((p) => (p.id === targetUser.id ? { ...p, accountStatus: 'rejected', lastAuditId: lastAuditId || p.lastAuditId } : p))
      );

      if (auditConfirmed) {
        setFeedback({
          type: 'success',
          message: `Access request for ${targetUser.name} (${targetUser.email}) was rejected.`,
        });
      } else {
        setFeedback({
          type: 'error',
          message: `Profile status updated in database, but persistent audit confirmation is unverified: ${auditErrorMsg}`,
        });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Rejection operation failed.' });
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.id]: false }));
    }
  };

  const openChangeRoleModal = (targetUser: UserProfile, newRole: UserRole) => {
    setGovernanceModal({
      isOpen: true,
      action: 'change_role',
      targetUser,
      newRole,
      justification: '',
    });
  };

  const openSuspendModal = (targetUser: UserProfile) => {
    setGovernanceModal({
      isOpen: true,
      action: 'suspend',
      targetUser,
      newRole: undefined,
      justification: '',
    });
  };

  const openReactivateModal = (targetUser: UserProfile) => {
    setGovernanceModal({
      isOpen: true,
      action: 'reactivate',
      targetUser,
      newRole: undefined,
      justification: '',
    });
  };

  const openDeactivateModal = (targetUser: UserProfile) => {
    setGovernanceModal({
      isOpen: true,
      action: 'deactivate',
      targetUser,
      newRole: undefined,
      justification: '',
    });
  };

  const handleExecuteGovernanceAction = async () => {
    const { action, targetUser, newRole, justification } = governanceModal;
    if (!targetUser) return;
    setFeedback(null);

    // Policy validation
    if (action === 'change_role') {
      if (!newRole) return;
      const res = validateRoleChange(currentUser, targetUser, newRole, profiles);
      if (!res.valid) {
        setFeedback({ type: 'error', message: res.error || 'Role change invalid.' });
        return;
      }
    } else if (action === 'suspend') {
      const res = validateSuspension(currentUser, targetUser, justification, profiles);
      if (!res.valid) {
        setFeedback({ type: 'error', message: res.error || 'Suspension invalid.' });
        return;
      }
    } else if (action === 'reactivate') {
      const res = validateReactivation(currentUser, targetUser);
      if (!res.valid) {
        setFeedback({ type: 'error', message: res.error || 'Reactivation invalid.' });
        return;
      }
    } else if (action === 'deactivate') {
      const res = validateDeactivation(currentUser, targetUser, justification, profiles);
      if (!res.valid) {
        setFeedback({ type: 'error', message: res.error || 'Deactivation invalid.' });
        return;
      }
    }

    setActionLoading((prev) => ({ ...prev, [targetUser.id]: true }));
    setGovernanceModal((prev) => ({ ...prev, isOpen: false }));

    let lastAuditId: string | undefined;

    try {
      if (isSupabaseConfigured() && supabase) {
        const updatePayload: Record<string, any> = {
          updated_at: new Date().toISOString(),
        };

        if (action === 'change_role' && newRole) {
          updatePayload.role = newRole;
        } else if (action === 'suspend' || action === 'deactivate') {
          updatePayload.account_status = 'disabled';
        } else if (action === 'reactivate') {
          updatePayload.account_status = 'approved';
          updatePayload.approved_by = currentUser.id;
          updatePayload.approved_at = new Date().toISOString();
        }

        const { data, error } = await supabase
          .from('user_profiles')
          .update(updatePayload)
          .eq('id', targetUser.id)
          .select();

        if (error) {
          setFeedback({ type: 'error', message: `Database update failed: ${error.message}` });
          return;
        }

        if (!data || data.length === 0) {
          setFeedback({
            type: 'error',
            message: 'Database update affected 0 rows. You may lack permission to update this profile.',
          });
          return;
        }

        lastAuditId = data[0]?.last_audit_id;
      }

      // Record governance action in audit trail
      let auditConfirmed = false;
      let auditErrorMsg = '';
      try {
        let actionType: 'unlock_account' | 'lock_account' = 'unlock_account';
        let actionJustification = justification.trim();
        let systemNote = '';

        if (action === 'change_role' && newRole) {
          actionType = 'unlock_account';
          actionJustification = `Operational role changed to ${ROLE_METADATA[newRole].label} by Super Admin ${currentUser.callsign}.`;
          systemNote = `Role for ${targetUser.email} changed from ${targetUser.role} to ${newRole}.`;
        } else if (action === 'suspend') {
          actionType = 'lock_account';
          systemNote = `Operational account ${targetUser.email} suspended by Super Admin ${currentUser.callsign}.`;
        } else if (action === 'reactivate') {
          actionType = 'unlock_account';
          actionJustification = `Account reactivated by Super Admin ${currentUser.callsign}.`;
          systemNote = `Operational account ${targetUser.email} reactivated to approved status.`;
        } else if (action === 'deactivate') {
          actionType = 'lock_account';
          systemNote = `Operational account ${targetUser.email} deactivated with data retention. Zero database rows deleted.`;
        }

        await auditRepo.recordGovernanceAction(currentUser, {
          actionType,
          targetEmail: targetUser.email,
          justification: actionJustification,
          systemNote,
          expectedAuditId: lastAuditId,
        });
        auditConfirmed = true;
      } catch (auditErr: any) {
        auditErrorMsg = auditErr.message || 'Audit confirmation query failed.';
      }

      // Update local profiles state
      setProfiles((prev) =>
        prev.map((p) => {
          if (p.id !== targetUser.id) return p;
          if (action === 'change_role' && newRole) {
            return { ...p, role: newRole, lastAuditId: lastAuditId || p.lastAuditId };
          }
          if (action === 'suspend' || action === 'deactivate') {
            return { ...p, accountStatus: 'disabled', lastAuditId: lastAuditId || p.lastAuditId };
          }
          if (action === 'reactivate') {
            return {
              ...p,
              accountStatus: 'approved',
              approvedBy: currentUser.id,
              approvedAt: new Date().toISOString(),
              lastAuditId: lastAuditId || p.lastAuditId,
            };
          }
          return p;
        })
      );

      const successMsg =
        action === 'change_role' && newRole
          ? `Role for ${targetUser.name} (${targetUser.email}) successfully changed to ${ROLE_METADATA[newRole].label}.`
          : action === 'suspend'
          ? `Account for ${targetUser.name} (${targetUser.email}) has been suspended.`
          : action === 'reactivate'
          ? `Account for ${targetUser.name} (${targetUser.email}) has been reactivated to approved status.`
          : `Account for ${targetUser.name} (${targetUser.email}) has been deactivated (retention-safe).`;

      if (auditConfirmed) {
        setFeedback({ type: 'success', message: successMsg });
        fetchAdminAuditLogs();
      } else {
        setFeedback({
          type: 'error',
          message: `${successMsg} However, persistent audit confirmation was unverified: ${auditErrorMsg}`,
        });
      }
    } catch (err: any) {
      setFeedback({ type: 'error', message: err.message || 'Governance operation failed.' });
    } finally {
      setActionLoading((prev) => ({ ...prev, [targetUser.id]: false }));
    }
  };

  const filteredProfiles = profiles.filter((p) => {
    if (statusFilter === 'pending') return p.accountStatus === 'pending';
    if (statusFilter === 'approved') return p.accountStatus === 'approved';
    if (statusFilter === 'disabled') return p.accountStatus === 'disabled';
    return true;
  });

  const pendingCount = profiles.filter((p) => p.accountStatus === 'pending').length;
  const approvedCount = profiles.filter((p) => p.accountStatus === 'approved').length;
  const disabledCount = profiles.filter((p) => p.accountStatus === 'disabled').length;

  const renderStatusBadge = (status: DiagnosticStatus) => {
    switch (status) {
      case 'Pass':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
            <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
            Pass
          </span>
        );
      case 'Fail':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950/80 dark:text-rose-300 dark:border-rose-800">
            <XCircle className="w-3 h-3 text-rose-600 dark:text-rose-400" />
            Fail
          </span>
        );
      case 'Not checked':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
            <HelpCircle className="w-3 h-3 text-slate-500 dark:text-slate-400" />
            Not checked
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-2xl font-bold text-slate-900 dark:text-slate-100 font-heading flex items-center gap-2">
            <Server className="w-6 h-6 text-purple-600" />
            Platform Administration & Governance
          </h1>
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-purple-100 text-purple-800 dark:bg-purple-950/80 dark:text-purple-300 border border-purple-300 dark:border-purple-800">
            DOMAIN C &bull; SUPER ADMIN
          </span>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          System health oversight, tenant isolation enforcement, and platform access governance.
        </p>
      </div>

      {/* Mandatory Security Boundary Banner */}
      <div className="p-4 rounded-xl bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-900/60 space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-900 dark:text-purple-300">
          <Lock className="w-4 h-4 text-purple-600 dark:text-purple-400" />
          <span>STRICT DOMAIN SEPARATION POLICY</span>
        </div>
        <p className="text-xs text-purple-800 dark:text-purple-300/90 leading-relaxed font-sans">
          In strict accordance with the platform authorization matrix, <strong>Platform Administrators (Super Admin) do NOT inherit read or write access to private SOC alert queues, analyst notes, or operational incident investigations</strong>. Operational records remain strictly isolated to authorized security analysts and incident responders.
        </p>
      </div>

      {/* Platform Bootstrap Singleton State */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div
              className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
                bootstrapInfo?.isBootstrapped
                  ? 'bg-emerald-50 text-emerald-600 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-400 dark:border-emerald-800'
                  : 'bg-amber-50 text-amber-600 border-amber-200 dark:bg-amber-950/60 dark:text-amber-400 dark:border-amber-800'
              }`}
            >
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold font-mono uppercase text-slate-900 dark:text-slate-100">
                  Platform Bootstrap State & Singleton Lock
                </span>
                {bootstrapInfo?.isBootstrapped ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950/80 dark:text-emerald-300 dark:border-emerald-800">
                    <CheckCircle2 className="w-3 h-3 text-emerald-600 dark:text-emerald-400" />
                    INITIALIZED & LOCKED
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950/80 dark:text-amber-300 dark:border-amber-800">
                    <Clock className="w-3 h-3 text-amber-600 dark:text-amber-400" />
                    {isLoadingBootstrap ? 'VERIFYING...' : 'PENDING BOOTSTRAP'}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 font-sans max-w-xl">
                PostgreSQL singleton lock (<code className="font-mono text-purple-700 dark:text-purple-300">public.platform_bootstrap_state</code> row ID 1) enforces that initial Super Admin bootstrap is irreversible, immutable, and strictly one-time.
              </p>
            </div>
          </div>
          <div className="text-[11px] font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-950 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 shrink-0 space-y-1">
            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-400 dark:text-slate-500">Super Admin:</span>
              <span className="font-bold text-slate-800 dark:text-slate-200">
                {bootstrapInfo?.superAdminEmail || currentUser.email}
              </span>
            </div>
            {bootstrapInfo?.bootstrappedAt && (
              <div className="flex items-center justify-between gap-4">
                <span className="text-slate-400 dark:text-slate-500">Bootstrapped:</span>
                <span>{new Date(bootstrapInfo.bootstrappedAt).toLocaleString()}</span>
              </div>
            )}
            <div className="flex items-center justify-between gap-4">
              <span className="text-slate-400 dark:text-slate-500">Lock Constraint:</span>
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">CHECK (id = 1)</span>
            </div>
          </div>
        </div>
      </div>

      {/* User Profiles Query Failure Banner (Zero Silent Fallback) */}
      {profilesError && (
        <div className="p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-300 dark:border-rose-800 text-rose-800 dark:text-rose-200 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-start sm:items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5 sm:mt-0" />
            <div>
              <div className="font-bold text-xs uppercase font-mono tracking-wider">
                Database Query Error &bull; User Profiles Unavailable
              </div>
              <div className="text-xs text-rose-700 dark:text-rose-300 font-mono mt-0.5">
                {profilesError}
              </div>
              <div className="text-[11px] text-rose-600 dark:text-rose-400 mt-1 font-sans">
                Silent fallback to development mock profiles is disabled to maintain data provenance integrity.
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={fetchProfiles}
            disabled={isLoadingUsers}
            className="px-3 py-1.5 text-xs font-mono font-bold bg-rose-600 hover:bg-rose-700 text-white rounded-lg flex items-center gap-1.5 transition self-start sm:self-auto shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingUsers ? 'animate-spin' : ''}`} />
            Retry Query
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 1: ADMIN OVERVIEW & PLATFORM HEALTH METRICS */}
      {/* ========================================================================= */}
      <AdminOverviewMetrics
        stats={overviewStats}
        dbStatus={dbStatus}
        isCheckingDb={isCheckingDb}
        onRefreshDb={probeDatabase}
        auditLogs={auditLogs}
        isLoadingAuditLogs={isLoadingAuditLogs}
        auditLogsError={auditLogsError}
        onRefreshAuditLogs={fetchAdminAuditLogs}
      />

      {/* ========================================================================= */}
      {/* SECTION 2: OPERATOR ACCESS GOVERNANCE & APPROVAL QUEUE */}
      {/* ========================================================================= */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs space-y-0">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-purple-100 dark:bg-purple-950/80 border border-purple-300 dark:border-purple-800 flex items-center justify-center text-purple-700 dark:text-purple-300">
              <Users className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 font-heading">
                  Operator Access Governance & Approval Queue
                </h3>
                {pendingCount > 0 && (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border border-amber-300 dark:border-amber-800">
                    {pendingCount} PENDING
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                Review registration requests, verify operator identity, and assign authorized operational roles.
              </p>
            </div>
          </div>

          {/* Filter & Refresh Controls */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                fetchProfiles();
                fetchBootstrapInfo();
              }}
              disabled={isLoadingUsers}
              title="Refresh queue from Supabase"
              className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-purple-600 dark:hover:text-purple-400 transition cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingUsers ? 'animate-spin' : ''}`} />
            </button>

            <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-950 p-1 rounded-lg border border-slate-200 dark:border-slate-800 text-xs font-mono">
              <button
                onClick={() => setStatusFilter('pending')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  statusFilter === 'pending'
                    ? 'bg-white dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Pending ({pendingCount})
              </button>
              <button
                onClick={() => setStatusFilter('approved')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  statusFilter === 'approved'
                    ? 'bg-white dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Approved ({approvedCount})
              </button>
              <button
                onClick={() => setStatusFilter('disabled')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  statusFilter === 'disabled'
                    ? 'bg-white dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                Disabled ({disabledCount})
              </button>
              <button
                onClick={() => setStatusFilter('all')}
                className={`px-2.5 py-1 rounded transition cursor-pointer ${
                  statusFilter === 'all'
                    ? 'bg-white dark:bg-purple-950 text-purple-700 dark:text-purple-300 font-bold shadow-xs'
                    : 'text-slate-600 dark:text-slate-400'
                }`}
              >
                All Records ({profiles.length})
              </button>
            </div>
          </div>
        </div>

        {/* Feedback message banner */}
        {feedback && (
          <div
            className={`p-3 text-xs flex items-center justify-between border-b ${
              feedback.type === 'success'
                ? 'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-900/60'
                : 'bg-rose-50 text-rose-800 border-rose-200 dark:bg-rose-950/60 dark:text-rose-300 dark:border-rose-900/60'
            }`}
          >
            <span>{feedback.message}</span>
            <button
              onClick={() => setFeedback(null)}
              className="text-[11px] font-mono underline ml-3 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* User Approval Table */}
        <div className="divide-y divide-slate-200 dark:divide-slate-800">
          {filteredProfiles.length === 0 ? (
            <div className="p-8 text-center space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-600 dark:text-emerald-400 mx-auto" />
              <div className="text-xs font-bold text-slate-800 dark:text-slate-200 font-mono">
                No requests currently in {statusFilter.toUpperCase()} queue.
              </div>
              <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                All registration requests have been reviewed according to zero-trust access policies.
              </p>
            </div>
          ) : (
            filteredProfiles.map((user) => {
              const isSelf = user.id === currentUser.id;
              const isPending = user.accountStatus === 'pending';
              const isApproved = user.accountStatus === 'approved';
              const isDisabled = user.accountStatus === 'disabled';
              const isRejected = user.accountStatus === 'rejected';
              const isLastAdmin = isLastSuperAdmin(user, profiles);
              const assignedRole = selectedRoles[user.id] || user.role || 'soc_analyst';
              const isLoading = actionLoading[user.id];

              return (
                <div
                  key={user.id}
                  className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-slate-50/50 dark:hover:bg-slate-950/40 transition"
                >
                  {/* User Details */}
                  <div className="space-y-1 min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                        {user.name}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">({user.email})</span>

                      {/* Status Badge */}
                      {isApproved && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-800">
                          APPROVED &bull; {user.role ? ROLE_METADATA[user.role]?.label : 'OPERATOR'}
                        </span>
                      )}
                      {isPending && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-800 animate-pulse">
                          PENDING APPROVAL
                        </span>
                      )}
                      {isDisabled && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200 dark:bg-rose-950 dark:text-rose-300 dark:border-rose-800">
                          SUSPENDED / DISABLED
                        </span>
                      )}
                      {isRejected && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700">
                          REJECTED
                        </span>
                      )}
                      {isSelf && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-300 dark:border-purple-800">
                          CURRENT SESSION
                        </span>
                      )}
                    </div>

                    <div className="text-[11px] text-slate-500 dark:text-slate-400 font-mono flex items-center gap-3">
                      <span>Callsign: <strong className="text-slate-700 dark:text-slate-300">{user.callsign}</strong></span>
                      {user.createdAt && (
                        <span>Registered: {new Date(user.createdAt).toLocaleDateString()}</span>
                      )}
                    </div>
                  </div>

                  {/* Actions & Role Selector */}
                  <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
                    {/* Case 1: Pending Approval */}
                    {isPending && (
                      <>
                        <div className="flex items-center gap-1.5">
                          <label className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                            ROLE:
                          </label>
                          <select
                            value={assignedRole}
                            onChange={(e) => handleRoleChange(user.id, e.target.value as UserRole)}
                            disabled={isSelf || isLoading}
                            className="bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-xs font-mono px-2 py-1 text-slate-800 dark:text-slate-200 focus:ring-1 focus:ring-purple-500 cursor-pointer disabled:opacity-50"
                          >
                            <option value="soc_analyst">SOC Analyst (Triage)</option>
                            <option value="security_engineer">Security Engineer (Detection)</option>
                            <option value="it_operations">IT Operations (Remediation)</option>
                          </select>
                        </div>

                        <button
                          onClick={() => handleApprove(user)}
                          disabled={isSelf || isLoading}
                          className="px-3 py-1 rounded text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white transition flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shadow-xs"
                        >
                          <UserCheck className="w-3.5 h-3.5" />
                          <span>{isLoading ? 'Processing...' : 'Approve'}</span>
                        </button>

                        <button
                          onClick={() => handleReject(user)}
                          disabled={isSelf || isLoading}
                          className="px-2.5 py-1 rounded text-xs font-semibold bg-slate-200 dark:bg-slate-800 hover:bg-rose-100 hover:text-rose-700 dark:hover:bg-rose-950 dark:hover:text-rose-300 text-slate-700 dark:text-slate-300 transition flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <UserX className="w-3.5 h-3.5" />
                          <span>Reject</span>
                        </button>
                      </>
                    )}

                    {/* Case 2: Approved Accounts (Operational Role Change, Suspend, Deactivate) */}
                    {isApproved && (
                      <div className="flex items-center gap-2 flex-wrap">
                        {user.role !== 'super_admin' ? (
                          <div className="flex items-center gap-1.5">
                            <label className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                              ROLE:
                            </label>
                            <select
                              value={selectedRoles[user.id] || user.role}
                              onChange={(e) => handleRoleChange(user.id, e.target.value as UserRole)}
                              disabled={isSelf || isLoading}
                              className="bg-white dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-xs font-mono px-2 py-1 text-slate-800 dark:text-slate-200 focus:ring-1 focus:ring-purple-500 cursor-pointer disabled:opacity-50"
                            >
                              <option value="soc_analyst">SOC Analyst</option>
                              <option value="security_engineer">Security Engineer</option>
                              <option value="it_operations">IT Operations</option>
                            </select>
                            {selectedRoles[user.id] && selectedRoles[user.id] !== user.role && (
                              <button
                                onClick={() => openChangeRoleModal(user, selectedRoles[user.id])}
                                disabled={isSelf || isLoading}
                                className="px-2 py-1 rounded text-xs font-semibold bg-purple-600 hover:bg-purple-700 text-white transition cursor-pointer disabled:opacity-40 shadow-xs"
                              >
                                Save Role
                              </button>
                            )}
                          </div>
                        ) : (
                          <span className="text-[10px] font-mono text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/60 px-2 py-0.5 rounded border border-purple-200 dark:border-purple-800">
                            Super Admin (Bootstrap Locked)
                          </span>
                        )}

                        {/* Suspend Account Button */}
                        <button
                          onClick={() => openSuspendModal(user)}
                          disabled={isSelf || isLoading || isLastAdmin}
                          title={
                            isSelf
                              ? 'Security Policy: Administrators cannot suspend their own account'
                              : isLastAdmin
                              ? 'Security Policy: Cannot suspend the last active Super Admin'
                              : 'Suspend Operator Account'
                          }
                          className="px-2.5 py-1 rounded text-xs font-medium bg-amber-50 hover:bg-amber-100 dark:bg-amber-950/60 dark:hover:bg-amber-900/60 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800 transition flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <UserMinus className="w-3.5 h-3.5" />
                          <span>Suspend</span>
                        </button>

                        {/* Retention-Safe Deactivate Button */}
                        <button
                          onClick={() => openDeactivateModal(user)}
                          disabled={isSelf || isLoading || isLastAdmin}
                          title={
                            isSelf
                              ? 'Security Policy: Administrators cannot deactivate their own account'
                              : isLastAdmin
                              ? 'Security Policy: Cannot deactivate the last active Super Admin'
                              : 'Deactivate Account (Retention-Safe)'
                          }
                          className="px-2.5 py-1 rounded text-xs font-medium bg-rose-50 hover:bg-rose-100 dark:bg-rose-950/60 dark:hover:bg-rose-900/60 text-rose-800 dark:text-rose-300 border border-rose-300 dark:border-rose-800 transition flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <UserX className="w-3.5 h-3.5" />
                          <span>Deactivate</span>
                        </button>
                      </div>
                    )}

                    {/* Case 3: Suspended / Disabled Accounts */}
                    {isDisabled && (
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono text-rose-600 dark:text-rose-400">
                          Access Suspended
                        </span>
                        <button
                          onClick={() => openReactivateModal(user)}
                          disabled={isSelf || isLoading}
                          title={isSelf ? 'Cannot modify self' : 'Reactivate account to approved status'}
                          className="px-2.5 py-1 rounded text-xs font-medium bg-emerald-50 hover:bg-emerald-100 dark:bg-emerald-950/60 dark:hover:bg-emerald-900/60 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800 transition flex items-center gap-1 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                          <span>Reactivate</span>
                        </button>
                      </div>
                    )}

                    {/* Case 4: Rejected Requests */}
                    {isRejected && (
                      <span className="text-[11px] font-mono text-slate-400">
                        Registration Request Rejected
                      </span>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 3: ACCESS CONTROL & CAPABILITY MATRIX */}
      {/* ========================================================================= */}
      <AccessControlMatrix />

      {/* ========================================================================= */}
      {/* SECTION 4: DATA SOURCE INVENTORY & PROVENANCE CATALOG */}
      {/* ========================================================================= */}
      <DataSourceInventory items={inventoryItems} />

      {/* ========================================================================= */}
      {/* SECTION 5: PLATFORM METRICS & DIAGNOSTICS */}
      {/* ========================================================================= */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* Metric A: Build Environment */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-blue-600 dark:text-cyan-400" />
              BUILD ENVIRONMENT
            </span>
            {renderStatusBadge(report.buildEnvironment.status)}
          </div>
          <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100">
            {report.buildEnvironment.value}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Vite build target (not production infrastructure)
          </div>
        </div>

        {/* Metric B: Demo Personas */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <Users className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
              DEMO PERSONAS
            </span>
            {renderStatusBadge(report.demoPersonas.status)}
          </div>
          <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100">
            {report.demoPersonas.value}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Derived from Demo Persona Registry
          </div>
        </div>

        {/* Metric C: Browser-Storage Availability */}
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs space-y-1">
          <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 font-mono">
            <span className="flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-cyan-600 dark:text-emerald-400" />
              BROWSER STORAGE
            </span>
            {renderStatusBadge(report.browserStorage.status)}
          </div>
          <div className="text-lg font-bold font-mono text-slate-900 dark:text-slate-100">
            {report.browserStorage.value}
          </div>
          <div className="text-[11px] text-slate-500 dark:text-slate-400">
            Local browser storage; not a production database
          </div>
        </div>
      </div>

      {/* Diagnostics Panel: Read-Only Check Details */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/60 dark:bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-purple-600 dark:text-purple-400" />
            <span className="text-xs font-mono font-bold text-slate-700 dark:text-slate-300 uppercase">
              Platform Diagnostics (Local Prototype)
            </span>
          </div>
          <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
            READ-ONLY EVALUATION
          </span>
        </div>

        {/* Local Prototype Diagnostics Disclaimer Note */}
        <div className="p-3 bg-blue-50/50 dark:bg-blue-950/20 border-b border-blue-100 dark:border-blue-900/30 flex items-start gap-2.5 text-[11px] text-blue-900 dark:text-blue-300">
          <Info className="w-4 h-4 text-blue-600 dark:text-cyan-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong>Prototype Architecture Notice:</strong> These diagnostics evaluate client runtime and local browser capabilities for the Phase 1 prototype only. They do not represent a production infrastructure, backend API availability, or server database health check.
          </p>
        </div>

        {/* Detailed Check Table */}
        <div className="divide-y divide-slate-200 dark:divide-slate-800 text-xs">
          {report.allChecks.map((check) => (
            <div key={check.id} className="p-4 flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div className="space-y-1 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    {check.name}
                  </span>
                  <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                    ({check.provenance})
                  </span>
                </div>
                <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-normal font-sans">
                  {check.detail}
                </p>
              </div>

              <div className="flex items-center sm:flex-col sm:items-end gap-2 shrink-0">
                {renderStatusBadge(check.status)}
                <span className="text-[11px] font-mono font-medium text-slate-700 dark:text-slate-300">
                  {check.value}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Governance Confirmation & Justification Modal */}
      {governanceModal.isOpen && governanceModal.targetUser && (
        <Modal
          isOpen={governanceModal.isOpen}
          onClose={() => setGovernanceModal((prev) => ({ ...prev, isOpen: false }))}
          title={
            governanceModal.action === 'change_role'
              ? 'Confirm Operational Role Change'
              : governanceModal.action === 'suspend'
              ? 'Suspend Operator Account'
              : governanceModal.action === 'reactivate'
              ? 'Reactivate Operator Account'
              : 'Retention-Safe Account Deactivation'
          }
          subtitle={`Target: ${governanceModal.targetUser.name} (${governanceModal.targetUser.email})`}
          footer={
            <div className="flex items-center gap-2">
              <button
                onClick={() => setGovernanceModal((prev) => ({ ...prev, isOpen: false }))}
                className="px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-medium hover:bg-slate-50 dark:hover:bg-slate-700 transition cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteGovernanceAction}
                disabled={
                  (governanceModal.action === 'suspend' || governanceModal.action === 'deactivate') &&
                  governanceModal.justification.trim().length < 5
                }
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold text-white transition flex items-center gap-1.5 cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed shadow-xs ${
                  governanceModal.action === 'change_role'
                    ? 'bg-purple-600 hover:bg-purple-700'
                    : governanceModal.action === 'suspend'
                    ? 'bg-amber-600 hover:bg-amber-700'
                    : governanceModal.action === 'reactivate'
                    ? 'bg-emerald-600 hover:bg-emerald-700'
                    : 'bg-rose-600 hover:bg-rose-700'
                }`}
              >
                {governanceModal.action === 'change_role' && <ShieldCheck className="w-4 h-4" />}
                {governanceModal.action === 'suspend' && <UserMinus className="w-4 h-4" />}
                {governanceModal.action === 'reactivate' && <RotateCcw className="w-4 h-4" />}
                {governanceModal.action === 'deactivate' && <UserX className="w-4 h-4" />}
                <span>
                  {governanceModal.action === 'change_role'
                    ? 'Confirm Role Change'
                    : governanceModal.action === 'suspend'
                    ? 'Confirm Suspension'
                    : governanceModal.action === 'reactivate'
                    ? 'Confirm Reactivation'
                    : 'Confirm Deactivation'}
                </span>
              </button>
            </div>
          }
        >
          <div className="space-y-4">
            {governanceModal.action === 'change_role' && governanceModal.newRole && (
              <div className="space-y-3">
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  You are changing the operational role of <strong>{governanceModal.targetUser.name}</strong> from{' '}
                  <span className="font-mono font-semibold">{ROLE_METADATA[governanceModal.targetUser.role]?.label}</span> to{' '}
                  <span className="font-mono font-semibold text-purple-600 dark:text-purple-400">
                    {ROLE_METADATA[governanceModal.newRole]?.label}
                  </span>.
                </p>
                <div className="p-3 rounded-lg bg-purple-50 dark:bg-purple-950/40 border border-purple-200 dark:border-purple-800 text-[11px] text-purple-900 dark:text-purple-300 space-y-1 font-mono">
                  <div>Access changes will take effect immediately across all dashboard views.</div>
                  <div>An immutable audit record will be logged with your administrator identity.</div>
                </div>
              </div>
            )}

            {governanceModal.action === 'suspend' && (
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-xs text-amber-900 dark:text-amber-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Operational Account Suspension:</strong> This user will be immediately locked out of all operational queues, alert triages, and Copilot AI queries.
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-mono font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    MANDATORY JUSTIFICATION (Required for immutable audit trail):
                  </label>
                  <textarea
                    value={governanceModal.justification}
                    onChange={(e) =>
                      setGovernanceModal((prev) => ({ ...prev, justification: e.target.value }))
                    }
                    placeholder="Provide specific reason for suspension (e.g., Security incident response ticket SEC-402, role transfer, or policy infraction)..."
                    className="w-full h-24 p-2.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:ring-1 focus:ring-amber-500 focus:outline-none"
                  />
                  <div className="text-[10px] font-mono text-slate-500 mt-1">
                    Minimum 5 characters required ({governanceModal.justification.trim().length}/5).
                  </div>
                </div>
              </div>
            )}

            {governanceModal.action === 'reactivate' && (
              <div className="space-y-3">
                <p className="text-xs text-slate-600 dark:text-slate-300">
                  Reactivate the account for <strong>{governanceModal.targetUser.name}</strong> ({governanceModal.targetUser.email}).
                  The user will be restored to approved status as{' '}
                  <strong className="font-mono">{ROLE_METADATA[governanceModal.targetUser.role]?.label}</strong>.
                </p>
                <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 text-[11px] text-emerald-900 dark:text-emerald-300 space-y-1 font-mono">
                  <div>Access permissions will be immediately restored.</div>
                  <div>A platform audit log entry will document your reactivation action.</div>
                </div>
              </div>
            )}

            {governanceModal.action === 'deactivate' && (
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-xs text-rose-900 dark:text-rose-300 flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-600 dark:text-rose-400 shrink-0 mt-0.5" />
                  <div>
                    <strong>Retention-Safe Deactivation Notice:</strong> The user account will be permanently disabled in the database, blocking all platform access.
                    <span className="block mt-1 font-semibold">
                      To preserve audit integrity and historical forensics, no database records or audit trails will be physically deleted (zero SQL DELETE).
                    </span>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-mono font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    MANDATORY JUSTIFICATION (Required for compliance audit trail):
                  </label>
                  <textarea
                    value={governanceModal.justification}
                    onChange={(e) =>
                      setGovernanceModal((prev) => ({ ...prev, justification: e.target.value }))
                    }
                    placeholder="Specify deactivation rationale (e.g., Operator offboarding, contract completion, or security compliance)..."
                    className="w-full h-24 p-2.5 text-xs rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 placeholder:text-slate-400 focus:ring-1 focus:ring-rose-500 focus:outline-none"
                  />
                  <div className="text-[10px] font-mono text-slate-500 mt-1">
                    Minimum 5 characters required ({governanceModal.justification.trim().length}/5).
                  </div>
                </div>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
};
