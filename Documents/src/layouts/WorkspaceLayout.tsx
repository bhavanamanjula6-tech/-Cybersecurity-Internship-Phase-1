import React, { useState, useMemo } from 'react';
import { UserProfile } from '../types/auth';
import { AppHeader } from '../components/layout/AppHeader';
import { AppSidebar, WorkspaceView } from '../components/layout/AppSidebar';
import { StorageNoticeBanner } from '../components/common/StorageNoticeBanner';
import { DevRoleSimulator } from '../components/layout/DevRoleSimulator';
import { CopilotTriggerButton } from '../components/copilot/CopilotTriggerButton';
import { CopilotDrawer } from '../components/copilot/CopilotDrawer';
import { CopilotContextType } from '../server/ai/types';

interface WorkspaceLayoutProps {
  currentUser: UserProfile;
  currentView: WorkspaceView;
  onViewChange: (view: WorkspaceView) => void;
  alertCount: number;
  criticalCount: number;
  taskCount: number;
  onExitToPublic: () => void;
  selectedAlertId?: string;
  children: React.ReactNode;
}

export const WorkspaceLayout: React.FC<WorkspaceLayoutProps> = ({
  currentUser,
  currentView,
  onViewChange,
  alertCount,
  criticalCount,
  taskCount,
  onExitToPublic,
  selectedAlertId,
  children,
}) => {
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);

  // Derive default context type from the active workspace view
  const defaultContextType = useMemo((): CopilotContextType => {
    switch (currentView) {
      case 'alerts':
      case 'investigations':
        return 'alert_triage';
      case 'mitre':
        return 'mitre_analysis';
      case 'tasks':
        return 'remediation_task';
      case 'admin':
        return 'platform_health';
      default:
        return 'general_soc';
    }
  }, [currentView]);

  return (
    <div className="min-h-screen bg-slate-100/80 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-150">
      {/* Storage Architecture Limitation Banner */}
      <StorageNoticeBanner />

      {/* Operational SOC Header */}
      <AppHeader
        alertCount={alertCount}
        criticalCount={criticalCount}
        onExitToPublic={onExitToPublic}
        onNavigateToProfile={() => onViewChange('profile')}
      />

      <div className="flex-1 flex overflow-hidden">
        {/* Role-Scoped Sidebar */}
        <AppSidebar
          currentView={currentView}
          onViewChange={onViewChange}
          currentUser={currentUser}
          alertCount={alertCount}
          taskCount={taskCount}
        />

        {/* Main Workspace Body */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 bg-slate-50/50 dark:bg-slate-950/70">
          <div className="max-w-7xl mx-auto space-y-6">{children}</div>
        </main>
      </div>

      {/* Floating Developer/Evaluation Role Simulator (Bottom-Left) */}
      <DevRoleSimulator />

      {/* Floating AI Security Copilot Trigger Button (Bottom-Right) */}
      <CopilotTriggerButton
        isOpen={isCopilotOpen}
        onClick={() => setIsCopilotOpen(!isCopilotOpen)}
      />

      {/* Responsive AI Security Copilot Chat Drawer */}
      <CopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        defaultContextType={defaultContextType}
        defaultEntityId={selectedAlertId}
      />
    </div>
  );
};
