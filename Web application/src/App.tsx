import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { UserRole, ROLE_METADATA } from './types/auth';
import { SecurityAlert, AlertStatus } from './types/alert';
import { MitreTactic, MitreTechnique, MitreMitigation, MitreDefenseCoverage } from './types/mitre';
import { ResponseActionType, AuditLogEntry, IncidentTask } from './types/audit';

import { getRepositories } from './repositories';
import { DeterministicTriageService } from './services/deterministicTriageService';
import { AuthorizationService } from './services/authorizationService';

// Modular Layouts
import { PublicLayout } from './layouts/PublicLayout';
import { WorkspaceLayout } from './layouts/WorkspaceLayout';

// Public components
import { PublicRoute } from './components/public/PublicHeader';
import { HomePage } from './components/public/HomePage';
import { FeaturesPage } from './components/public/FeaturesPage';
import { AboutPage } from './components/public/AboutPage';
import { ContactPage } from './components/public/ContactPage';
import { LoginPage } from './components/public/LoginPage';

// Operational & Domain Components
import { WorkspaceView } from './components/layout/AppSidebar';
import { AlertTriageDashboard } from './components/analyst/AlertTriageDashboard';
import { AnalystOverviewDashboard } from './components/analyst/AnalystOverviewDashboard';
import { InvestigationWorkspace } from './components/analyst/InvestigationWorkspace';
import { PlaybookConsole } from './components/analyst/PlaybookConsole';
import { UserProfilePage } from './components/common/UserProfilePage';
import { AlertDetailDrawer } from './components/analyst/AlertDetailDrawer';
import { SimulateActionModal } from './components/analyst/SimulateActionModal';
import { SecurityEngineerDashboard } from './components/security-engineer/SecurityEngineerDashboard';
import { SecurityEngineerOverviewPage } from './components/security-engineer/SecurityEngineerOverviewPage';
import { ITOperationsDashboard } from './components/it-operations/ITOperationsDashboard';
import { PlatformAdminDashboard } from './components/admin/PlatformAdminDashboard';
import { AuditLogViewer } from './components/audit/AuditLogViewer';
import { SocAnalystKnowledgeRecord, fetchSocAnalystKnowledge } from './services/knowledgeService';
import { SocAnalystWorkspace, SocKnowledgeView } from './components/analyst/SocAnalystWorkspace';
import { ItOpsWorkspace } from './components/it-operations/knowledge/ItOpsWorkspace';
import { ItOpsKnowledgeView } from './components/it-operations/knowledge/types';
import { checkAlertClosureEligibility } from './utils/remediationReview';
import { DetectionRecommendation, CreateRecommendationInput } from './types/recommendation';

// Repository bundle adhering to IAlertRepository, IMITRERepository, IAuditLogRepository, and IDetectionRecommendationRepository
const { alertRepo, mitreRepo, auditRepo, recommendationRepo, isLive } = getRepositories();
const triageService = new DeterministicTriageService();

const STORAGE_IN_WORKSPACE = 'cyberops_soc_in_workspace';
const STORAGE_WORKSPACE_VIEW = 'cyberops_soc_workspace_view';
const STORAGE_PUBLIC_ROUTE = 'cyberops_soc_public_route';

const VALID_PUBLIC_ROUTES: PublicRoute[] = ['home', 'features', 'about', 'contact', 'login', 'register'];

const VALID_WORKSPACE_VIEWS: WorkspaceView[] = [
  'seceng_overview',
  'overview',
  'strategies',
  'analytics',
  'log_sources',
  'data_components',
  'mitre_explorer',
  'itops_overview',
  'itops_techniques',
  'itops_mitigations',
  'alerts',
  'investigations',
  'playbooks',
  'mitre',
  'tasks',
  'audit',
  'admin',
  'profile',
];

const parsePublicRouteFromHash = (hashStr: string): PublicRoute | null => {
  if (!hashStr) return null;
  const hashWithoutPrefix = hashStr.replace(/^#\/?/, '').trim();
  const routeName = hashWithoutPrefix.split(/[?&#]/)[0].toLowerCase().trim();
  if (VALID_PUBLIC_ROUTES.includes(routeName as PublicRoute)) {
    return routeName as PublicRoute;
  }
  // If hash contains authentication, recovery, or verification tokens, route to login component
  if (
    hashWithoutPrefix.includes('access_token=') ||
    hashWithoutPrefix.includes('token_hash=') ||
    hashWithoutPrefix.includes('type=signup') ||
    hashWithoutPrefix.includes('type=recovery') ||
    hashWithoutPrefix.includes('error_code=') ||
    hashWithoutPrefix.includes('error=') ||
    hashWithoutPrefix.includes('reset-password')
  ) {
    return 'login';
  }
  return null;
};

const parseWorkspaceViewFromHash = (hashStr: string): WorkspaceView | null => {
  if (!hashStr) return null;
  const clean = hashStr.replace(/^#\/?/, '').toLowerCase().trim();
  if (VALID_WORKSPACE_VIEWS.includes(clean as WorkspaceView)) {
    return clean as WorkspaceView;
  }
  return null;
};

const getInitialInWorkspace = (): boolean => {
  if (typeof window === 'undefined') return false;
  const fromPublicHash = parsePublicRouteFromHash(window.location.hash);
  if (fromPublicHash) {
    return false;
  }
  const fromWorkspaceHash = parseWorkspaceViewFromHash(window.location.hash);
  if (fromWorkspaceHash) {
    return true;
  }
  try {
    const savedPublic = sessionStorage.getItem(STORAGE_PUBLIC_ROUTE);
    if (savedPublic && VALID_PUBLIC_ROUTES.includes(savedPublic as PublicRoute)) {
      return false;
    }
    return sessionStorage.getItem(STORAGE_IN_WORKSPACE) === 'true';
  } catch {
    return false;
  }
};

const getInitialWorkspaceView = (): WorkspaceView => {
  if (typeof window === 'undefined') return 'overview';
  const fromHash = parseWorkspaceViewFromHash(window.location.hash);
  if (fromHash) {
    return fromHash;
  }
  const saved = sessionStorage.getItem(STORAGE_WORKSPACE_VIEW);
  if (saved && VALID_WORKSPACE_VIEWS.includes(saved as WorkspaceView)) {
    return saved as WorkspaceView;
  }
  return 'overview';
};

const getInitialPublicRoute = (): PublicRoute => {
  if (typeof window !== 'undefined') {
    const search = window.location.search || '';
    if (
      search.includes('token_hash=') ||
      search.includes('type=signup') ||
      search.includes('error_code=') ||
      search.includes('error=') ||
      search.includes('code=')
    ) {
      try {
        sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, 'login');
      } catch {}
      return 'login';
    }

    // 1. URL hash is primary source of truth
    const fromHash = parsePublicRouteFromHash(window.location.hash);
    if (fromHash) {
      try {
        sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, fromHash);
      } catch {}
      return fromHash;
    }

    // 2. Check sessionStorage fallback if hash was omitted or stripped on reload
    try {
      const saved = sessionStorage.getItem(STORAGE_PUBLIC_ROUTE);
      if (saved && VALID_PUBLIC_ROUTES.includes(saved as PublicRoute)) {
        if (window.location.hash !== `#${saved}`) {
          window.history.replaceState({ route: saved }, '', `#${saved}`);
        }
        return saved as PublicRoute;
      }
    } catch {}
  }
  return 'home';
};

function AppContent() {
  const { currentUser, isAuthenticated, isAuthReady, logout } = useAuth();

  // Navigation states
  const [inWorkspace, setInWorkspace] = useState<boolean>(getInitialInWorkspace);
  const [publicRoute, setPublicRoute] = useState<PublicRoute>(getInitialPublicRoute);
  const [workspaceView, setWorkspaceView] = useState<WorkspaceView>(getInitialWorkspaceView);
  const [auditFilterAlertId, setAuditFilterAlertId] = useState<string | undefined>(undefined);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [tasksError, setTasksError] = useState<string | null>(null);
  const [auditError, setAuditError] = useState<string | null>(null);

  const [isAlertsLoading, setIsAlertsLoading] = useState<boolean>(false);
  const [isTasksLoading, setIsTasksLoading] = useState<boolean>(false);
  const [isAuditLoading, setIsAuditLoading] = useState<boolean>(false);

  // Application Data State
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [tactics, setTactics] = useState<MitreTactic[]>([]);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [mitigations, setMitigations] = useState<MitreMitigation[]>([]);
  const [coverage, setCoverage] = useState<MitreDefenseCoverage[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [tasks, setTasks] = useState<IncidentTask[]>([]);
  const [recommendations, setRecommendations] = useState<DetectionRecommendation[]>([]);
  const [isRecommendationsLoading, setIsRecommendationsLoading] = useState(false);
  const [recommendationsError, setRecommendationsError] = useState<string | null>(null);
  const [socKnowledge, setSocKnowledge] = useState<SocAnalystKnowledgeRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Concurrency, in-flight deduplication, and stale response sequence tracking
  const inFlightRef = useRef<{
    alerts: boolean;
    tasks: boolean;
    audit: boolean;
    recommendations: boolean;
  }>({
    alerts: false,
    tasks: false,
    audit: false,
    recommendations: false,
  });

  const requestSeqRef = useRef<{
    alerts: number;
    tasks: number;
    audit: number;
    recommendations: number;
  }>({
    alerts: 0,
    tasks: 0,
    audit: 0,
    recommendations: 0,
  });

  // Selected Alert for Deep Triage Drawer
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);

  // Simulated Action Modal State
  const [actionModal, setActionModal] = useState<{
    isOpen: boolean;
    actionType: ResponseActionType;
    target: string;
    alertId?: string;
  }>({
    isOpen: false,
    actionType: 'isolate_host',
    target: '',
  });

  // Dedicated Alert Fetcher with Deduplication & Error Propagation
  const fetchAlerts = useCallback(async (force = false) => {
    if (!currentUser) {
      if (isLive) {
        setAlerts([]);
        setAlertsError(null);
      } else {
        try {
          const defaultAlerts = await alertRepo.getAlertsForUser({
            id: 'anon',
            name: 'Anonymous',
            email: 'anon@guest',
            role: 'soc_analyst',
            callsign: 'GUEST',
            title: 'Guest Visitor',
          });
          setAlerts(defaultAlerts);
          setAlertsError(null);
        } catch {
          setAlerts([]);
        }
      }
      return;
    }

    if (currentUser.role === 'super_admin') {
      setAlerts([]);
      setAlertsError(null);
      return;
    }

    // Prevent duplicate simultaneous requests unless explicitly forced
    if (inFlightRef.current.alerts && !force) {
      return;
    }

    inFlightRef.current.alerts = true;
    const seq = ++requestSeqRef.current.alerts;
    setIsAlertsLoading(true);

    try {
      const fetchedAlerts = await alertRepo.getAlertsForUser(currentUser);
      if (requestSeqRef.current.alerts === seq) {
        setAlerts(fetchedAlerts);
        setAlertsError(null);
      }
    } catch (err: any) {
      console.error('Failed to query operational alerts:', err?.message || err);
      if (requestSeqRef.current.alerts === seq) {
        setAlertsError(err?.message || 'Database query failed or access denied.');
        setAlerts([]);
      }
    } finally {
      if (requestSeqRef.current.alerts === seq) {
        setIsAlertsLoading(false);
      }
      inFlightRef.current.alerts = false;
    }
  }, [currentUser]);

  // Dedicated Incident Task Fetcher with Deduplication & Explicit Error Handling
  const fetchTasks = useCallback(async (force = false) => {
    if (!currentUser || currentUser.role === 'super_admin') {
      setTasks([]);
      setTasksError(null);
      return;
    }

    // Prevent duplicate simultaneous requests unless explicitly forced
    if (inFlightRef.current.tasks && !force) {
      return;
    }

    inFlightRef.current.tasks = true;
    const seq = ++requestSeqRef.current.tasks;
    setIsTasksLoading(true);

    try {
      const fetchedTasks = await auditRepo.getIncidentTasksForUser(currentUser);
      if (requestSeqRef.current.tasks === seq) {
        setTasks(fetchedTasks);
        setTasksError(null);
      }
    } catch (err: any) {
      console.error('Failed to query incident tasks:', err?.message || err);
      if (requestSeqRef.current.tasks === seq) {
        setTasksError(err?.message || 'Failed to query incident response tasks.');
        setTasks([]);
      }
    } finally {
      if (requestSeqRef.current.tasks === seq) {
        setIsTasksLoading(false);
      }
      inFlightRef.current.tasks = false;
    }
  }, [currentUser]);

  // Dedicated Audit Log Fetcher with Deduplication & Explicit Error Handling
  const fetchAuditLogs = useCallback(async (force = false) => {
    if (!currentUser) {
      setAuditLogs([]);
      setAuditError(null);
      return;
    }

    // Prevent duplicate simultaneous requests unless explicitly forced
    if (inFlightRef.current.audit && !force) {
      return;
    }

    inFlightRef.current.audit = true;
    const seq = ++requestSeqRef.current.audit;
    setIsAuditLoading(true);

    try {
      const fetchedLogs = await auditRepo.getLogsForUser(currentUser);
      if (requestSeqRef.current.audit === seq) {
        setAuditLogs(fetchedLogs);
        setAuditError(null);
      }
    } catch (err: any) {
      console.error('Failed to query audit logs:', err?.message || err);
      if (requestSeqRef.current.audit === seq) {
        setAuditError(err?.message || 'Failed to query audit log trail.');
        setAuditLogs([]);
      }
    } finally {
      if (requestSeqRef.current.audit === seq) {
        setIsAuditLoading(false);
      }
      inFlightRef.current.audit = false;
    }
  }, [currentUser]);

  // Dedicated Detection Recommendation Fetcher with Deduplication & Error Propagation
  const fetchRecommendations = useCallback(async (force = false) => {
    if (!currentUser || currentUser.role === 'super_admin' || currentUser.role === 'it_operations') {
      setRecommendations([]);
      setRecommendationsError(null);
      return;
    }

    if (inFlightRef.current.recommendations && !force) {
      return;
    }

    inFlightRef.current.recommendations = true;
    const seq = ++requestSeqRef.current.recommendations;
    setIsRecommendationsLoading(true);

    try {
      const fetched = await recommendationRepo.getRecommendationsForUser(currentUser);
      if (requestSeqRef.current.recommendations === seq) {
        setRecommendations(fetched);
        setRecommendationsError(null);
      }
    } catch (err: any) {
      console.error('Failed to query detection recommendations:', err?.message || err);
      if (requestSeqRef.current.recommendations === seq) {
        setRecommendationsError(err?.message || 'Failed to query detection recommendations.');
        setRecommendations([]);
      }
    } finally {
      if (requestSeqRef.current.recommendations === seq) {
        setIsRecommendationsLoading(false);
      }
      inFlightRef.current.recommendations = false;
    }
  }, [currentUser]);

  // Recommendation Action Handlers
  const handleCreateRecommendation = useCallback(async (input: CreateRecommendationInput) => {
    if (!currentUser) return;
    const created = await recommendationRepo.createRecommendation(currentUser, input);
    setRecommendations((prev) => [created, ...prev]);
    fetchAuditLogs(true);
  }, [currentUser, fetchAuditLogs]);

  const handleReviewRecommendation = useCallback(async (
    id: string,
    action: 'accept' | 'reject' | 'request_clarification',
    feedback?: string
  ) => {
    if (!currentUser) return;
    const updated = await recommendationRepo.reviewRecommendation(currentUser, id, action, feedback);
    setRecommendations((prev) => prev.map((r) => (r.id === id ? updated : r)));
    fetchAuditLogs(true);
  }, [currentUser, fetchAuditLogs]);

  const handleUpdateRecommendationImplementation = useCallback(async (
    id: string,
    status: 'in_progress' | 'completed',
    notes?: string,
    sigmaRef?: string
  ) => {
    if (!currentUser) return;
    const updated = await recommendationRepo.updateImplementation(currentUser, id, status, notes, sigmaRef);
    setRecommendations((prev) => prev.map((r) => (r.id === id ? updated : r)));
    fetchAuditLogs(true);
  }, [currentUser, fetchAuditLogs]);

  const handleValidateRecommendation = useCallback(async (
    id: string,
    feedback?: string
  ) => {
    if (!currentUser) return;
    const updated = await recommendationRepo.validateRecommendation(currentUser, id, feedback);
    setRecommendations((prev) => prev.map((r) => (r.id === id ? updated : r)));
    fetchAuditLogs(true);
  }, [currentUser, fetchAuditLogs]);

  // Controlled Simulated Alert Dispatcher (Windows Event Detection Pipeline)
  const handleSimulateAlert = useCallback(async (simulatedAlert: SecurityAlert): Promise<void> => {
    if (!currentUser) {
      throw new Error('User session not found.');
    }

    // Security Engineers are architecturally read-only on operational alerts:
    // Generate local preview without attempting unauthorized database insert.
    if (currentUser.role === 'security_engineer') {
      return;
    }

    // SOC Analysts have authorized INSERT rights under alerts_insert_policy
    if (currentUser.role === 'soc_analyst') {
      if (!alertRepo.addSimulatedAlert) {
        throw new Error('Alert repository does not support simulated alert persistence.');
      }
      const savedAlert = await alertRepo.addSimulatedAlert(simulatedAlert);
      setAlerts((prev) => [savedAlert, ...prev.filter((a) => a.id !== savedAlert.id)]);
      setSelectedAlert((prev) => (prev?.id === savedAlert.id ? savedAlert : prev));
      return;
    }

    throw new Error(`Role "${currentUser.role}" is not authorized to create operational alerts.`);
  }, [currentUser, alertRepo]);

  // Retry Handlers invoking fresh data requests
  const handleRetryTasks = useCallback(() => {
    fetchTasks(true);
  }, [fetchTasks]);

  const handleRetryAlerts = useCallback(() => {
    fetchAlerts(true);
  }, [fetchAlerts]);

  const handleRetryAudit = useCallback(() => {
    fetchAuditLogs(true);
  }, [fetchAuditLogs]);

  // Load initial reference data and user operational datasets
  const loadData = useCallback(async () => {
    try {
      setIsLoading(true);

      // MITRE Reference data (shared reference read)
      const [fetchedTactics, fetchedTechniques, fetchedCoverage] = await Promise.all([
        mitreRepo.getTactics(),
        mitreRepo.getTechniques(),
        mitreRepo.getDefenseCoverage(),
      ]);
      setTactics(fetchedTactics);
      setTechniques(fetchedTechniques);
      setCoverage(fetchedCoverage);

      const mitIds = Array.from(new Set(fetchedTechniques.flatMap((t) => t.mitigationIds)));
      const fetchedMits = await Promise.all(
        mitIds.map((id) => mitreRepo.getMitigationById(id))
      );
      setMitigations(fetchedMits.filter(Boolean) as MitreMitigation[]);

      // Role-scoped operational data via decoupled fetchers
      await Promise.all([
        fetchAlerts(true),
        fetchTasks(true),
        fetchAuditLogs(true),
        fetchRecommendations(true),
      ]);

      if (currentUser?.role === 'soc_analyst') {
        fetchSocAnalystKnowledge(currentUser)
          .then((records) => setSocKnowledge(records))
          .catch((err) => console.error('Failed to load SOC Analyst knowledge:', err));
      } else {
        setSocKnowledge([]);
      }
    } catch (globalErr: any) {
      console.error('Error loading repository data:', globalErr);
      setAlertsError(globalErr?.message || 'Failed to load system data.');
    } finally {
      setIsLoading(false);
    }
  }, [currentUser, fetchAlerts, fetchTasks, fetchAuditLogs, fetchRecommendations]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Refresh operational datasets on navigation to tasks, alerts, or audit
  const prevNavViewRef = useRef<WorkspaceView | null>(null);

  useEffect(() => {
    if (!inWorkspace || !isAuthenticated || !currentUser) {
      prevNavViewRef.current = null;
      return;
    }

    if (prevNavViewRef.current === workspaceView) return;
    prevNavViewRef.current = workspaceView;

    if (workspaceView === 'tasks') {
      fetchTasks();
    } else if (workspaceView === 'alerts') {
      fetchAlerts();
      fetchRecommendations();
    } else if (workspaceView === 'audit') {
      fetchAuditLogs();
    } else if (workspaceView === 'mitre') {
      fetchRecommendations();
    }
  }, [workspaceView, inWorkspace, isAuthenticated, currentUser, fetchTasks, fetchAlerts, fetchAuditLogs, fetchRecommendations]);

  // Explicit check ensuring only approved operators with assigned non-null roles can enter workspace
  const isApprovedOperator =
    currentUser?.accountStatus === 'approved' &&
    Boolean(currentUser.role) &&
    ['soc_analyst', 'security_engineer', 'it_operations', 'super_admin'].includes(currentUser.role);

  // Enforce role-to-view authorization when role changes or if current view is unauthorized
  useEffect(() => {
    if (currentUser) {
      if (!AuthorizationService.isViewAuthorized(currentUser.role, workspaceView)) {
        const defaultView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
        setWorkspaceView(defaultView);
        try {
          sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, defaultView);
        } catch {}
      }
    }
  }, [currentUser?.role, workspaceView]);

  // Restore authorized workspace or fail closed once authentication and profile readiness resolve
  useEffect(() => {
    if (!isAuthReady) return;

    if (isAuthenticated && currentUser && isApprovedOperator) {
      const fromPublicHash =
        typeof window !== 'undefined' ? parsePublicRouteFromHash(window.location.hash) : null;
      const fromWorkspaceHash =
        typeof window !== 'undefined' ? parseWorkspaceViewFromHash(window.location.hash) : null;
      let savedPublic: string | null = null;
      try {
        savedPublic = typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_PUBLIC_ROUTE) : null;
      } catch {}
      const wasInWorkspace =
        typeof window !== 'undefined' &&
        sessionStorage.getItem(STORAGE_IN_WORKSPACE) === 'true';

      if (fromPublicHash) {
        setInWorkspace(false);
        setPublicRoute(fromPublicHash);
      } else if (fromWorkspaceHash) {
        setInWorkspace(true);
        if (AuthorizationService.isViewAuthorized(currentUser.role, fromWorkspaceHash)) {
          setWorkspaceView(fromWorkspaceHash);
          try {
            sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
            sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, fromWorkspaceHash);
          } catch {}
        } else {
          // Direct URL to unauthorized view: redirect to role's authorized default view
          const defaultView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
          setWorkspaceView(defaultView);
          try {
            sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
            sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, defaultView);
          } catch {}
          if (typeof window !== 'undefined') {
            window.history.replaceState({ view: defaultView }, '', `#${defaultView}`);
          }
        }
      } else if (wasInWorkspace && !savedPublic) {
        setInWorkspace(true);
        const savedView =
          typeof window !== 'undefined'
            ? (sessionStorage.getItem(STORAGE_WORKSPACE_VIEW) as WorkspaceView | null)
            : null;
        if (savedView && AuthorizationService.isViewAuthorized(currentUser.role, savedView)) {
          setWorkspaceView(savedView);
          if (typeof window !== 'undefined' && window.location.hash !== `#${savedView}`) {
            window.history.replaceState({ view: savedView }, '', `#${savedView}`);
          }
        } else {
          const defaultView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
          setWorkspaceView(defaultView);
          try {
            sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, defaultView);
          } catch {}
          if (typeof window !== 'undefined' && window.location.hash !== `#${defaultView}`) {
            window.history.replaceState({ view: defaultView }, '', `#${defaultView}`);
          }
        }
      } else {
        setInWorkspace(false);
      }
    } else {
      // Fail closed: clear workspace persistence if unauthenticated, pending, rejected, or invalid role
      if (typeof window !== 'undefined' && sessionStorage.getItem(STORAGE_IN_WORKSPACE)) {
        try {
          sessionStorage.removeItem(STORAGE_IN_WORKSPACE);
          sessionStorage.removeItem(STORAGE_WORKSPACE_VIEW);
        } catch {}
      }
      setInWorkspace(false);

      // If user attempted to reach a workspace hash while unauthenticated, redirect to login
      if (typeof window !== 'undefined') {
        const fromWorkspaceHash = parseWorkspaceViewFromHash(window.location.hash);
        if (fromWorkspaceHash) {
          setPublicRoute('login');
          try {
            sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, 'login');
          } catch {}
          window.history.replaceState({ route: 'login' }, '', '#login');
        }
      }
    }
  }, [isAuthReady, isAuthenticated, currentUser, isApprovedOperator]);

  // Persist authorized workspace view changes
  useEffect(() => {
    if (inWorkspace && isApprovedOperator && currentUser) {
      if (AuthorizationService.isViewAuthorized(currentUser.role, workspaceView)) {
        try {
          sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, workspaceView);
        } catch {}
      }
    }
  }, [inWorkspace, isApprovedOperator, currentUser, workspaceView]);

  // Alert operations with strict permission enforcement
  const handleUpdateAlertStatus = async (alertId: string, status: AlertStatus) => {
    if (!currentUser) return;

    // Requirement 7: When an alert has associated remediation tasks, require all of them
    // to have explicit SOC Analyst approval before allowing the alert to become resolved.
    if (status === 'resolved') {
      const eligibility = checkAlertClosureEligibility(alertId, tasks);
      if (!eligibility.eligible) {
        throw new Error(eligibility.reason || 'All associated remediation tasks must have explicit SOC Analyst approval before this alert can be resolved.');
      }
    }

    const updated = await alertRepo.updateAlertStatus(currentUser, alertId, status, tasks);
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(updated);
    }

    if (status === 'resolved') {
      try {
        const auditEntry = await auditRepo.recordSimulatedAction(currentUser, {
          actionType: 'alert_resolved',
          targetResource: updated.hostName || `Alert ${alertId}`,
          justification: 'Operational alert resolved following verification and approval of all associated remediation tasks.',
          status: 'SIMULATED_SUCCESS',
          associatedAlertId: alertId,
          systemNote: `Alert ${alertId} marked resolved by ${currentUser.name} (${currentUser.role}). All linked remediation tasks verified and approved.`,
        });
        setAuditLogs((prev) => [auditEntry, ...prev]);
        fetchAuditLogs(true);
      } catch (auditErr) {
        console.warn('Non-fatal: failed to record alert_resolved audit log:', auditErr);
      }
    }
  };

  const handleAddAnalystNote = async (alertId: string, note: string) => {
    if (!currentUser) return;
    const updated = await alertRepo.addAnalystNote(currentUser, alertId, note);
    setAlerts((prev) => prev.map((a) => (a.id === alertId ? updated : a)));
    if (selectedAlert?.id === alertId) {
      setSelectedAlert(updated);
    }
  };

  // Simulated Action Execution
  const handleInitiateSimulatedAction = (actionType: ResponseActionType, target: string, alertId?: string) => {
    setActionModal({
      isOpen: true,
      actionType,
      target,
      alertId,
    });
  };

  const handleConfirmSimulatedAction = async (justification: string) => {
    if (!currentUser) return;

    const newEntry = await auditRepo.recordSimulatedAction(currentUser, {
      actionType: actionModal.actionType,
      targetResource: actionModal.target,
      justification,
      status: 'SIMULATED_SUCCESS',
      associatedAlertId: actionModal.alertId,
      systemNote: `Simulated containment executed under Phase 1 protocol for target ${actionModal.target}.`,
    });

    setAuditLogs((prev) => [newEntry, ...prev]);

    // Create linked recovery task for IT Operations
    if (actionModal.actionType === 'isolate_host' || actionModal.actionType === 'lock_account') {
      const newTask = await auditRepo.createTask(currentUser, {
        title: `Verify Containment & Recovery for ${actionModal.target}`,
        description: `Operational task triggered following ${actionModal.actionType.replace('_', ' ')}. Rationale: ${justification}`,
        assignedRole: 'it_operations',
        status: 'in_progress',
        priority: 'high',
        targetAsset: actionModal.target,
        suggestedActionType: actionModal.actionType,
        associatedAlertId: actionModal.alertId,
      });
      setTasks((prev) => [newTask, ...prev]);
    }
  };

  // Inspect associated alert from IT Operations task with task-derived authorization
  const handleInspectAlert = async (alertId: string) => {
    if (!currentUser) return;
    try {
      // 1. Obtain current user's authorized tasks using existing task repository
      const authorizedTasks = await auditRepo.getIncidentTasksForUser(currentUser);
      // 2. Derive allowed alert IDs strictly from these authorized tasks
      const allowedAlertIds = authorizedTasks
        .map((t) => t.associatedAlertId)
        .filter((id): id is string => Boolean(id));

      // 3. Confirm requested alert is associated with an accessible task
      if (!allowedAlertIds.includes(alertId)) {
        console.warn(`Access Denied: Alert "${alertId}" is not associated with any authorized tasks.`);
        return;
      }

      // 4. Call alertRepo.getAlertByIdForUser with current user and derived allowed IDs
      const alert = await alertRepo.getAlertByIdForUser(currentUser, alertId, allowedAlertIds);
      if (alert) {
        setSelectedAlert(alert);
      }
    } catch (err: any) {
      console.error('Failed to inspect associated alert:', err?.message || err);
    }
  };

  const handleCreateTask = async (taskData: Omit<IncidentTask, 'id' | 'createdAt'>): Promise<IncidentTask> => {
    if (!currentUser) {
      throw new Error('User session not found.');
    }
    const newTask = await auditRepo.createTask(currentUser, taskData);
    setTasks((prev) => [newTask, ...prev.filter((t) => t.id !== newTask.id)]);
    await fetchTasks(true);
    fetchAuditLogs(true);
    return newTask;
  };

  const handleUpdateTaskStatus = async (taskId: string, status: IncidentTask['status'], notes?: string) => {
    if (!currentUser) return;
    const updated = await auditRepo.updateTaskStatus(currentUser, taskId, status, notes);
    setTasks((prev) => prev.map((t) => (t.id === taskId ? updated : t)));
    // Refresh audit logs so newly emitted operational audit events (remediation_started or remediation_verified) immediately sync in state
    if (status === 'completed' || status === 'in_progress') {
      fetchAuditLogs(true);
    }
  };

  const handleReviewTask = async (
    taskId: string,
    decision: 'approved' | 'rework_requested',
    notes: string
  ): Promise<void> => {
    if (!currentUser) {
      throw new Error('User session not found.');
    }
    const updated = await auditRepo.reviewRemediationTask(currentUser, taskId, decision, notes);
    setTasks((prev) => prev.map((t) => (t.id === taskId ? updated : t)));
    // Refresh audit logs so newly emitted review decision audit event immediately syncs in state
    fetchAuditLogs(true);
  };

  // Selected Alert Computations
  const selectedMitreTechnique = useMemo(() => {
    if (!selectedAlert?.mitreTechniqueId) return null;
    return techniques.find((t) => t.id === selectedAlert.mitreTechniqueId) || null;
  }, [selectedAlert, techniques]);

  const selectedMitreMitigations = useMemo(() => {
    if (!selectedMitreTechnique) return [];
    return mitigations.filter((m) => selectedMitreTechnique.mitigationIds.includes(m.id));
  }, [selectedMitreTechnique, mitigations]);

  const selectedTriageRecommendation = useMemo(() => {
    if (!selectedAlert) return null;
    return triageService.evaluateAlert(selectedAlert);
  }, [selectedAlert]);

  const criticalAlertCount = useMemo(() => {
    return alerts.filter((a) => a.severity === 'critical').length;
  }, [alerts]);

  // Unified public navigation handler with immediate scroll-to-top and browser history sync
  const handlePublicNavigate = useCallback((route: PublicRoute) => {
    setPublicRoute(route);
    try {
      sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, route);
    } catch {}
    if (['home', 'features', 'about', 'contact', 'login', 'register'].includes(route)) {
      setInWorkspace(false);
    }
    if (typeof window !== 'undefined') {
      if (window.location.hash !== `#${route}`) {
        window.history.pushState({ route }, '', `#${route}`);
      }
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
      if (document.documentElement) document.documentElement.scrollTop = 0;
      if (document.body) document.body.scrollTop = 0;
    }
  }, []);

  // Listen to browser Back/Forward (popstate/hashchange) navigation
  useEffect(() => {
    const handleUrlChange = () => {
      if (typeof window === 'undefined') return;
      const rawHash = window.location.hash;
      const search = window.location.search || '';
      const publicRouteFromHash = parsePublicRouteFromHash(rawHash);
      const workspaceViewFromHash = parseWorkspaceViewFromHash(rawHash);
      const hasAuthSearch =
        search.includes('token_hash=') ||
        search.includes('type=signup') ||
        search.includes('error_code=') ||
        search.includes('code=');

      if (publicRouteFromHash || hasAuthSearch) {
        const targetRoute = publicRouteFromHash || 'login';
        setPublicRoute(targetRoute);
        try {
          sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, targetRoute);
          sessionStorage.removeItem(STORAGE_IN_WORKSPACE);
        } catch {}
        setInWorkspace(false);
      } else if (workspaceViewFromHash) {
        if (isAuthenticated && currentUser && isApprovedOperator) {
          if (AuthorizationService.isViewAuthorized(currentUser.role, workspaceViewFromHash)) {
            setInWorkspace(true);
            setWorkspaceView(workspaceViewFromHash);
            try {
              sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
              sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, workspaceViewFromHash);
              sessionStorage.removeItem(STORAGE_PUBLIC_ROUTE);
            } catch {}
          } else {
            // Direct URL to unauthorized view: redirect to authorized default view
            const defView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
            setInWorkspace(true);
            setWorkspaceView(defView);
            try {
              sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
              sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, defView);
            } catch {}
            window.history.replaceState({ view: defView }, '', `#${defView}`);
          }
        } else {
          // Unauthenticated or unapproved: fail closed to login
          setInWorkspace(false);
          setPublicRoute('login');
          try {
            sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, 'login');
          } catch {}
          window.history.replaceState({ route: 'login' }, '', '#login');
        }
      } else if (rawHash && rawHash !== '#' && rawHash !== '') {
        // Unknown hash route handling
        if (isAuthenticated && currentUser && isApprovedOperator) {
          const defView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
          setInWorkspace(true);
          setWorkspaceView(defView);
          window.history.replaceState({ view: defView }, '', `#${defView}`);
        } else {
          setInWorkspace(false);
          setPublicRoute('home');
          window.history.replaceState({ route: 'home' }, '', '#home');
        }
      } else {
        const wasInWorkspace = sessionStorage.getItem(STORAGE_IN_WORKSPACE) === 'true';
        if (wasInWorkspace && isAuthenticated && currentUser && isApprovedOperator) {
          setInWorkspace(true);
        } else {
          setInWorkspace(false);
          setPublicRoute('home');
        }
      }
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
      if (document.documentElement) document.documentElement.scrollTop = 0;
      if (document.body) document.body.scrollTop = 0;
    };

    window.addEventListener('popstate', handleUrlChange);
    window.addEventListener('hashchange', handleUrlChange);
    return () => {
      window.removeEventListener('popstate', handleUrlChange);
      window.removeEventListener('hashchange', handleUrlChange);
    };
  }, [isAuthenticated, currentUser, isApprovedOperator]);

  // Ensure scroll position resets whenever publicRoute or inWorkspace transitions
  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
      if (document.documentElement) document.documentElement.scrollTop = 0;
      if (document.body) document.body.scrollTop = 0;
    }
  }, [publicRoute, inWorkspace]);

  // Navigate to workspace on login success
  const handleLoginSuccess = () => {
    try {
      sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
      sessionStorage.removeItem(STORAGE_PUBLIC_ROUTE);
    } catch {
      // Ignore storage errors in restricted contexts
    }
    setInWorkspace(true);
    if (typeof window !== 'undefined') {
      const fromWorkspaceHash = parseWorkspaceViewFromHash(window.location.hash);
      const targetView = (
        fromWorkspaceHash && currentUser && AuthorizationService.isViewAuthorized(currentUser.role, fromWorkspaceHash)
          ? fromWorkspaceHash
          : currentUser
          ? AuthorizationService.getDefaultViewForRole(currentUser.role)
          : 'overview'
      ) as WorkspaceView;
      setWorkspaceView(targetView);
      window.history.replaceState({ view: targetView }, '', `#${targetView}`);
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }
  };

  const handleEnterWorkspace = () => {
    try {
      sessionStorage.setItem(STORAGE_IN_WORKSPACE, 'true');
      sessionStorage.removeItem(STORAGE_PUBLIC_ROUTE);
    } catch {
      // Ignore storage errors in restricted contexts
    }
    setInWorkspace(true);
    if (typeof window !== 'undefined') {
      const fromWorkspaceHash = parseWorkspaceViewFromHash(window.location.hash);
      const targetView = (
        fromWorkspaceHash && currentUser && AuthorizationService.isViewAuthorized(currentUser.role, fromWorkspaceHash)
          ? fromWorkspaceHash
          : currentUser
          ? AuthorizationService.getDefaultViewForRole(currentUser.role)
          : 'overview'
      ) as WorkspaceView;
      setWorkspaceView(targetView);
      window.history.replaceState({ view: targetView }, '', `#${targetView}`);
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    }
  };

  const handleExitToPublic = () => {
    try {
      sessionStorage.removeItem(STORAGE_IN_WORKSPACE);
      sessionStorage.removeItem(STORAGE_WORKSPACE_VIEW);
      sessionStorage.setItem(STORAGE_PUBLIC_ROUTE, 'home');
    } catch {
      // Ignore storage errors in restricted contexts
    }
    setInWorkspace(false);
    handlePublicNavigate('home');
  };

  const wasInWorkspace =
    typeof window !== 'undefined' &&
    sessionStorage.getItem(STORAGE_IN_WORKSPACE) === 'true';
  const fromHash =
    typeof window !== 'undefined' ? parsePublicRouteFromHash(window.location.hash) : null;
  let savedPublic: string | null = null;
  try {
    savedPublic = typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_PUBLIC_ROUTE) : null;
  } catch {}
  const isViewingPublic = Boolean(
    fromHash || (savedPublic && VALID_PUBLIC_ROUTES.includes(savedPublic as PublicRoute))
  );

  // Prevent public-homepage flash while verifying live session and profile authorization
  if (!isAuthReady && wasInWorkspace && !isViewingPublic) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-200">
        <div className="flex items-center space-x-3 mb-4">
          <div className="w-4 h-4 rounded-full bg-cyan-500 animate-ping" />
          <span className="font-mono text-sm tracking-wider uppercase text-cyan-400">
            Restoring CyberOps SOC Session...
          </span>
        </div>
        <p className="text-xs text-slate-500 font-mono">
          Verifying cryptographic credentials and operational clearance...
        </p>
      </div>
    );
  }

  // If in Workspace and authenticated with approved role:
  if (inWorkspace && isAuthenticated && currentUser && isApprovedOperator) {
    // Explicit Role-to-View Authorization Guard:
    // Unauthorized views must NEVER render merely because workspaceView was manipulated.
    const isAuthorized = AuthorizationService.isViewAuthorized(currentUser.role, workspaceView);
    const effectiveView = (
      isAuthorized
        ? workspaceView
        : AuthorizationService.getDefaultViewForRole(currentUser.role)
    ) as WorkspaceView;

    return (
      <WorkspaceLayout
        currentUser={currentUser}
        currentView={effectiveView}
        onViewChange={(newView) => {
          if (AuthorizationService.isViewAuthorized(currentUser.role, newView)) {
            setWorkspaceView(newView);
            try {
              sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, newView);
            } catch {}
            if (typeof window !== 'undefined' && window.location.hash !== `#${newView}`) {
              window.history.pushState({ view: newView }, '', `#${newView}`);
            }
          } else {
            const defView = AuthorizationService.getDefaultViewForRole(currentUser.role) as WorkspaceView;
            setWorkspaceView(defView);
            try {
              sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, defView);
            } catch {}
            if (typeof window !== 'undefined' && window.location.hash !== `#${defView}`) {
              window.history.replaceState({ view: defView }, '', `#${defView}`);
            }
          }
        }}
        alertCount={alerts.length}
        criticalCount={criticalAlertCount}
        taskCount={tasks.filter((t) => t.status !== 'completed').length}
        onExitToPublic={handleExitToPublic}
        selectedAlertId={selectedAlert?.id}
      >
        {effectiveView === 'admin' && currentUser.role === 'super_admin' && (
          <PlatformAdminDashboard currentUser={currentUser} />
        )}

        {currentUser.role === 'soc_analyst' &&
          [
            'overview',
            'strategies',
            'analytics',
            'log_sources',
            'data_components',
            'mitre_explorer',
          ].includes(effectiveView) && (
            <SocAnalystWorkspace
              currentView={effectiveView as SocKnowledgeView}
              onNavigateView={(newView) => {
                setWorkspaceView(newView);
                try {
                  sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, newView);
                } catch {}
                if (typeof window !== 'undefined' && window.location.hash !== `#${newView}`) {
                  window.history.pushState({ view: newView }, '', `#${newView}`);
                }
              }}
              currentUser={currentUser}
            />
          )}

        {currentUser.role === 'it_operations' &&
          [
            'itops_overview',
            'itops_techniques',
            'itops_mitigations',
          ].includes(effectiveView) && (
            <ItOpsWorkspace
              currentView={effectiveView as ItOpsKnowledgeView}
              onNavigateView={(newView) => {
                setWorkspaceView(newView);
                try {
                  sessionStorage.setItem(STORAGE_WORKSPACE_VIEW, newView);
                } catch {}
                if (typeof window !== 'undefined' && window.location.hash !== `#${newView}`) {
                  window.history.pushState({ view: newView }, '', `#${newView}`);
                }
              }}
              currentUser={currentUser}
            />
          )}

        {effectiveView === 'overview' && currentUser.role !== 'soc_analyst' && AuthorizationService.isViewAuthorized(currentUser.role, 'overview') && (
          <AnalystOverviewDashboard
            alerts={alerts}
            tactics={tactics}
            techniques={techniques}
            currentUser={currentUser}
            onNavigateToQueue={() => setWorkspaceView('alerts')}
            onSelectAlertForInvestigation={(alert) => {
              setSelectedAlert(alert);
              setWorkspaceView('investigations');
            }}
            onRefresh={loadData}
            isLoading={isLoading}
          />
        )}

        {effectiveView === 'alerts' && AuthorizationService.isViewAuthorized(currentUser.role, 'alerts') && (
          <AlertTriageDashboard
            alerts={alerts}
            tactics={tactics}
            onSelectAlert={(a) => setSelectedAlert(a)}
            onInvestigateAlert={(a) => {
              setSelectedAlert(a);
              setWorkspaceView('investigations');
            }}
            onRefresh={handleRetryAlerts}
            isLoading={isAlertsLoading}
            selectedAlertId={selectedAlert?.id}
            currentUser={currentUser}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            error={alertsError}
            recommendations={recommendations}
            onReviewRecommendation={handleReviewRecommendation}
            onValidateRecommendation={handleValidateRecommendation}
            onRefreshRecommendations={() => fetchRecommendations(true)}
            onSimulateAlert={handleSimulateAlert}
            techniques={techniques}
          />
        )}

        {effectiveView === 'investigations' && AuthorizationService.isViewAuthorized(currentUser.role, 'investigations') && (
          <InvestigationWorkspace
            alerts={alerts}
            selectedAlertId={selectedAlert?.id}
            onSelectAlert={(a) => setSelectedAlert(a)}
            onUpdateStatus={handleUpdateAlertStatus}
            onAddNote={handleAddAnalystNote}
            techniques={techniques}
            mitigations={mitigations}
            triageEvaluator={(a) => triageService.evaluateAlert(a)}
            currentRole={currentUser.role}
            onInitiateSimulatedAction={(action, target, alertId) =>
              handleInitiateSimulatedAction(action, target, alertId)
            }
            onNavigateToAlertQueue={() => setWorkspaceView('alerts')}
            onNavigateToAuditTrail={(alertId) => {
              setAuditFilterAlertId(alertId);
              setWorkspaceView('audit');
            }}
            onNavigateToPlaybooks={(alertId) => {
              if (alertId) {
                const matchedAlert = alerts.find((a) => a.id === alertId);
                if (matchedAlert) {
                  setSelectedAlert(matchedAlert);
                }
              }
              setWorkspaceView('playbooks');
            }}
            tasks={tasks}
            currentUser={currentUser}
            onCreateTask={handleCreateTask}
            onReviewTask={handleReviewTask}
          />
        )}

        {effectiveView === 'playbooks' && AuthorizationService.isViewAuthorized(currentUser.role, 'playbooks') && (
          <PlaybookConsole
            alerts={alerts}
            currentRole={currentUser.role}
            selectedAlertId={selectedAlert?.id}
            onExecuteSimulation={async (actionType, target, justification, alertId) => {
              const newEntry = await auditRepo.recordSimulatedAction(currentUser, {
                actionType,
                targetResource: target,
                justification,
                status: 'SIMULATED_SUCCESS',
                associatedAlertId: alertId,
                systemNote: `Simulated containment executed under Phase 1 protocol for target ${target}.`,
              });
              setAuditLogs((prev) => [newEntry, ...prev]);

              if (actionType === 'isolate_host' || actionType === 'lock_account') {
                const newTask = await auditRepo.createTask(currentUser, {
                  title: `Verify Containment & Recovery for ${target}`,
                  description: `Operational task triggered following ${actionType.replace('_', ' ')}. Rationale: ${justification}`,
                  assignedRole: 'it_operations',
                  status: 'in_progress',
                  priority: 'high',
                  targetAsset: target,
                  suggestedActionType: actionType,
                  associatedAlertId: alertId,
                });
                setTasks((prev) => [newTask, ...prev]);
              }
            }}
            onNavigateToAuditTrail={(alertId) => {
              setAuditFilterAlertId(alertId);
              setWorkspaceView('audit');
            }}
          />
        )}

        {effectiveView === 'profile' && AuthorizationService.isViewAuthorized(currentUser.role, 'profile') && (
          <UserProfilePage
            currentUser={currentUser}
            onLogout={logout}
          />
        )}

        {effectiveView === 'seceng_overview' && AuthorizationService.isViewAuthorized(currentUser.role, 'seceng_overview') && (
          <SecurityEngineerOverviewPage
            currentUser={currentUser}
            onNavigateToTab={(tab) => {
              if (tab === 'threat_intel' || tab === 'mitre' || tab === 'workbench') {
                setWorkspaceView('mitre');
              } else if (tab === 'alerts') {
                setWorkspaceView('alerts');
              } else if (tab === 'audit') {
                setWorkspaceView('audit');
              }
            }}
          />
        )}

        {effectiveView === 'mitre' && AuthorizationService.isViewAuthorized(currentUser.role, 'mitre') && (
          <SecurityEngineerDashboard
            tactics={tactics}
            techniques={techniques}
            mitigations={mitigations}
            coverage={coverage}
            isLoading={isLoading}
            onRefresh={loadData}
            currentUser={currentUser}
            activeRecommendations={recommendations}
            onSubmitRecommendation={handleCreateRecommendation}
            onUpdateRecommendationImplementation={handleUpdateRecommendationImplementation}
            onRefreshRecommendations={() => fetchRecommendations(true)}
            onSimulateAlert={handleSimulateAlert}
          />
        )}

        {effectiveView === 'tasks' && AuthorizationService.isViewAuthorized(currentUser.role, 'tasks') && (
          <ITOperationsDashboard
            tasks={tasks}
            alerts={alerts}
            auditLogs={auditLogs}
            onUpdateTaskStatus={handleUpdateTaskStatus}
            onTriggerSimulatedAction={(action, target) =>
              handleInitiateSimulatedAction(action, target)
            }
            onInspectAlert={handleInspectAlert}
            currentRole={currentUser.role}
            currentUser={currentUser}
            isLoading={isTasksLoading}
            error={tasksError}
            onRetry={handleRetryTasks}
          />
        )}

        {effectiveView === 'audit' && AuthorizationService.isViewAuthorized(currentUser.role, 'audit') && (
          <AuditLogViewer
            logs={auditLogs}
            initialAlertFilter={auditFilterAlertId}
            currentUser={currentUser}
            isLoading={isAuditLoading}
            error={auditError}
            onRetry={handleRetryAudit}
          />
        )}

        {/* Deep-dive Investigation Drawer */}
        {selectedAlert && selectedTriageRecommendation && (
          <AlertDetailDrawer
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
            onUpdateStatus={handleUpdateAlertStatus}
            onAddNote={handleAddAnalystNote}
            mitreTechnique={selectedMitreTechnique}
            mitigations={selectedMitreMitigations}
            triageRecommendation={selectedTriageRecommendation}
            currentRole={currentUser.role}
            currentUser={currentUser}
            onInitiateSimulatedAction={(action, target) =>
              handleInitiateSimulatedAction(action, target, selectedAlert.id)
            }
            tasks={tasks}
            onCreateTask={handleCreateTask}
            onReviewTask={handleReviewTask}
          />
        )}

        {/* Simulated Action Confirmation Dialog */}
        <SimulateActionModal
          isOpen={actionModal.isOpen}
          onClose={() => setActionModal((prev) => ({ ...prev, isOpen: false }))}
          actionType={actionModal.actionType}
          target={actionModal.target}
          alertId={actionModal.alertId}
          currentRole={currentUser.role}
          onConfirm={handleConfirmSimulatedAction}
        />
      </WorkspaceLayout>
    );
  }

  // Otherwise, render Public Website
  return (
    <PublicLayout
      currentRoute={publicRoute}
      onNavigate={handlePublicNavigate}
      onEnterApp={handleEnterWorkspace}
      isAuthenticated={isAuthenticated}
    >
      {publicRoute === 'home' && (
        <HomePage
          onNavigate={handlePublicNavigate}
          onEnterApp={handleEnterWorkspace}
          isAuthenticated={isAuthenticated}
        />
      )}

      {publicRoute === 'features' && (
        <FeaturesPage onNavigate={handlePublicNavigate} />
      )}

      {publicRoute === 'about' && (
        <AboutPage onNavigate={handlePublicNavigate} />
      )}

      {publicRoute === 'contact' && <ContactPage />}

      {(publicRoute === 'login' || publicRoute === 'register') && (
        <LoginPage
          initialMode={publicRoute === 'register' ? 'register' : 'signin'}
          onLoginSuccess={handleLoginSuccess}
          onNavigate={handlePublicNavigate}
        />
      )}
    </PublicLayout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
