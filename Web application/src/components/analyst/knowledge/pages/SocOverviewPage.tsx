import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  Server,
  FileCode,
  TrendingUp,
  ArrowRight,
  Layers,
  Sparkles,
  Search,
  ExternalLink,
  Eye,
  Filter,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters, SocOverviewKpis } from '../types';
import {
  computeSocOverviewKpis,
  aggregateTechniquesByTacticFromRecords,
  aggregateAnalyticsByLogSource,
  aggregateStrategiesByTechniques,
  extractTechniques,
} from '../filterUtils';
import { InteractiveBarChart, BarChartItem } from '../charts/InteractiveBarChart';
import { InteractiveDonutChart, DonutChartItem } from '../charts/InteractiveDonutChart';

interface SocOverviewPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onNavigateTab: (tab: string) => void;
  onSelectTechniqueId?: (techniqueId: string) => void;
}

export const SocOverviewPage: React.FC<SocOverviewPageProps> = ({
  records,
  allRecords,
  filters,
  onUpdateFilters,
  onNavigateTab,
  onSelectTechniqueId,
}) => {
  const [tableSearch, setTableSearch] = useState('');

  // 5 verified distinct KPIs computed dynamically from filtered records
  const kpis: SocOverviewKpis = computeSocOverviewKpis(records);
  const totalKpis: SocOverviewKpis = computeSocOverviewKpis(allRecords);

  // Dynamic aggregations from active records (NO platform chart per prompt instruction E)
  const tacticsChart = useMemo(() => aggregateTechniquesByTacticFromRecords(records), [records]);
  const strategiesChart = useMemo(() => aggregateStrategiesByTechniques(records), [records]);
  const logSourcesChart = useMemo(() => aggregateAnalyticsByLogSource(records), [records]);

  // Technique records extracted for searchable table
  const allTechniques = useMemo(() => extractTechniques(records), [records]);

  const filteredTechniques = useMemo(() => {
    if (!tableSearch.trim()) return allTechniques;
    const q = tableSearch.toLowerCase();
    return allTechniques.filter(
      (t) =>
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.tactics.some((tac) => tac.toLowerCase().includes(q)) ||
        t.platforms.some((p) => p.toLowerCase().includes(q)) ||
        t.detectionStrategyIds.some((s) => s.toLowerCase().includes(q)) ||
        t.logSources.some((l) => l.toLowerCase().includes(q))
    );
  }, [allTechniques, tableSearch]);

  // Chart Items mapped for InteractiveBarChart
  const tacticBarItems: BarChartItem[] = useMemo(() => {
    return tacticsChart.map((t) => ({
      id: t.tactic,
      label: t.tactic,
      count: t.distinctTechniques,
      percentage: t.percentage,
      isSelected: filters.selectedTactics.includes(t.tactic),
    }));
  }, [tacticsChart, filters.selectedTactics]);

  const strategyBarItems: BarChartItem[] = useMemo(() => {
    return strategiesChart.map((s) => ({
      id: s.strategyId,
      label: s.strategyName,
      subLabel: s.strategyId,
      count: s.distinctTechniques,
      isSelected: filters.selectedStrategies.includes(s.strategyId),
    }));
  }, [strategiesChart, filters.selectedStrategies]);

  const logSourceBarItems: BarChartItem[] = useMemo(() => {
    return logSourcesChart.map((l) => ({
      id: l.logSource,
      label: l.logSource,
      count: l.distinctAnalytics,
      percentage: l.percentage,
      isSelected: filters.selectedLogSources.includes(l.logSource),
    }));
  }, [logSourcesChart, filters.selectedLogSources]);

  // Donut chart items: ATT&CK Tactic distribution
  const tacticDonutItems: DonutChartItem[] = useMemo(() => {
    return tacticsChart.map((t) => ({
      id: t.tactic,
      label: t.tactic,
      count: t.distinctTechniques,
      isSelected: filters.selectedTactics.includes(t.tactic),
    }));
  }, [tacticsChart, filters.selectedTactics]);

  // Toggle helpers for interactive click-to-filter
  const toggleTactic = (tactic: string) => {
    onUpdateFilters((prev) => {
      const exists = prev.selectedTactics.includes(tactic);
      return {
        ...prev,
        selectedTactics: exists
          ? prev.selectedTactics.filter((t) => t !== tactic)
          : [...prev.selectedTactics, tactic],
      };
    });
  };

  const toggleStrategy = (strategyId: string) => {
    onUpdateFilters((prev) => {
      const exists = prev.selectedStrategies.includes(strategyId);
      return {
        ...prev,
        selectedStrategies: exists
          ? prev.selectedStrategies.filter((s) => s !== strategyId)
          : [...prev.selectedStrategies, strategyId],
      };
    });
  };

  const toggleLogSource = (logSource: string) => {
    onUpdateFilters((prev) => {
      const exists = prev.selectedLogSources.includes(logSource);
      return {
        ...prev,
        selectedLogSources: exists
          ? prev.selectedLogSources.filter((l) => l !== logSource)
          : [...prev.selectedLogSources, logSource],
      };
    });
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Verification Status */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-bold text-slate-100 font-heading">
              SOC Knowledge & Detection Engineering Posture
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
              {records.length} Active Records
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-dimensional analysis across MITRE ATT&CK tactics, detection blueprints, SIEM analytics, and telemetry sources.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <span>Click any bar to toggle cross-filters</span>
        </div>
      </div>

      {/* 2. 5 Verified Distinct Count KPI Cards (from actual schema) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* KPI 1: Techniques */}
        <div
          onClick={() => onNavigateTab('mitre_explorer')}
          className="p-4 bg-slate-900 border border-slate-800 hover:border-indigo-600/70 rounded-xl shadow-xs transition-all cursor-pointer group"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigateTab('mitre_explorer')}
          aria-label={`Distinct Techniques: ${kpis.distinctTechniques}. Click to open MITRE ATT&CK Explorer.`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold text-slate-300 group-hover:text-indigo-300 transition-colors">
              Techniques
            </span>
            <ShieldCheck className="w-4 h-4 text-indigo-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {kpis.distinctTechniques}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              / {totalKpis.distinctTechniques}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
            <span>ATT&CK Techniques</span>
            <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-indigo-400 transition-colors" />
          </p>
        </div>

        {/* KPI 2: Tactics */}
        <div
          onClick={() => onNavigateTab('mitre_explorer')}
          className="p-4 bg-slate-900 border border-slate-800 hover:border-blue-600/70 rounded-xl shadow-xs transition-all cursor-pointer group"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigateTab('mitre_explorer')}
          aria-label={`Distinct Tactics: ${kpis.distinctTactics}.`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold text-slate-300 group-hover:text-blue-300 transition-colors">
              Tactics
            </span>
            <Layers className="w-4 h-4 text-blue-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {kpis.distinctTactics}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              / {totalKpis.distinctTactics}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Enterprise Tactics</span>
            <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-blue-400 transition-colors" />
          </p>
        </div>

        {/* KPI 3: Detection Strategies */}
        <div
          onClick={() => onNavigateTab('strategies')}
          className="p-4 bg-slate-900 border border-slate-800 hover:border-cyan-600/70 rounded-xl shadow-xs transition-all cursor-pointer group"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigateTab('strategies')}
          aria-label={`Distinct Detection Strategies: ${kpis.distinctDetectionStrategies}. Click to open Detection Strategy Analytics.`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold text-slate-300 group-hover:text-cyan-300 transition-colors">
              Strategies
            </span>
            <FileCode className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {kpis.distinctDetectionStrategies}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              / {totalKpis.distinctDetectionStrategies}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Detection Blueprints</span>
            <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-cyan-400 transition-colors" />
          </p>
        </div>

        {/* KPI 4: Analytics */}
        <div
          onClick={() => onNavigateTab('analytics')}
          className="p-4 bg-slate-900 border border-slate-800 hover:border-emerald-600/70 rounded-xl shadow-xs transition-all cursor-pointer group"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigateTab('analytics')}
          aria-label={`Distinct Analytics: ${kpis.distinctAnalytics}. Click to open Analytic Analytics.`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold text-slate-300 group-hover:text-emerald-300 transition-colors">
              Analytics
            </span>
            <TrendingUp className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {kpis.distinctAnalytics}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              / {totalKpis.distinctAnalytics}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
            <span>SIEM/EDR Rules</span>
            <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-emerald-400 transition-colors" />
          </p>
        </div>

        {/* KPI 5: Log Sources */}
        <div
          onClick={() => onNavigateTab('log_sources')}
          className="p-4 bg-slate-900 border border-slate-800 hover:border-amber-600/70 rounded-xl shadow-xs transition-all cursor-pointer group"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && onNavigateTab('log_sources')}
          aria-label={`Distinct Log Sources: ${kpis.distinctLogSources}. Click to open Log Source Analytics.`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-semibold text-slate-300 group-hover:text-amber-300 transition-colors">
              Log Sources
            </span>
            <Server className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {kpis.distinctLogSources}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              / {totalKpis.distinctLogSources}
            </span>
          </div>
          <p className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
            <span>Telemetry Feeds</span>
            <ArrowRight className="w-3 h-3 text-slate-500 group-hover:text-amber-400 transition-colors" />
          </p>
        </div>
      </div>

      {/* 3. Primary Interactive Visualizations: ATT&CK Tactics Bar Chart & Tactical Share Donut Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <InteractiveBarChart
          title="MITRE ATT&CK Tactics Distribution"
          subtitle="Technique density mapped across tactical stages. Click bar to filter."
          badge={`${tacticsChart.length} Tactics`}
          icon={<Layers className="w-4 h-4 text-indigo-400" />}
          items={tacticBarItems}
          colorScheme="indigo"
          onItemClick={(item) => toggleTactic(item.id)}
          emptyMessage="No tactics matched the current filter selection."
          maxDisplay={5}
        />

        <InteractiveDonutChart
          title="ATT&CK Tactical Share"
          subtitle="Proportional share of techniques across Top 5 tactics and remaining categories."
          badge={`${tacticsChart.length} Tactics`}
          icon={<Layers className="w-4 h-4 text-cyan-400" />}
          items={tacticDonutItems}
          topN={5}
          onItemClick={(item) => toggleTactic(item.id)}
          totalLabel="Technique Mappings"
          emptyMessage="No tactical distribution available."
        />
      </div>

      {/* 4. Secondary Visualizations: Strategy Breadth & Log Source Telemetry (Top 5 Default) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <InteractiveBarChart
          title="Detection Strategies by Technique Coverage"
          subtitle="Top detection blueprints by cataloged ATT&CK technique count."
          badge={`${strategiesChart.length} Strategies`}
          icon={<FileCode className="w-4 h-4 text-cyan-400" />}
          items={strategyBarItems}
          colorScheme="cyan"
          onItemClick={(item) => toggleStrategy(item.id)}
          emptyMessage="No detection strategies matched the current filter selection."
          maxDisplay={5}
        />

        <InteractiveBarChart
          title="Telemetry Feeds by Analytic Rule Count"
          subtitle="Log sources prioritized by active SIEM/EDR detection rules."
          badge={`${logSourcesChart.length} Log Sources`}
          icon={<Server className="w-4 h-4 text-amber-400" />}
          items={logSourceBarItems}
          colorScheme="amber"
          onItemClick={(item) => toggleLogSource(item.id)}
          emptyMessage="No telemetry feeds matched the current filter selection."
          maxDisplay={5}
        />
      </div>

      {/* 5. Searchable Data Table: Filtered Cataloged Techniques */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Cataloged Techniques & Detection Mappings
              <span className="text-xs font-mono font-normal text-indigo-300 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800">
                {filteredTechniques.length} of {allTechniques.length} Techniques
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Verified ATT&CK techniques reflecting active cross-filters. Click any row to inspect deep technique metadata.
            </p>
          </div>

          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={tableSearch}
              onChange={(e) => setTableSearch(e.target.value)}
              placeholder="Search in techniques table..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th scope="col" className="p-3 font-semibold">ATT&CK ID</th>
                <th scope="col" className="p-3 font-semibold">Technique Name</th>
                <th scope="col" className="p-3 font-semibold">Tactics</th>
                <th scope="col" className="p-3 font-semibold">Platforms</th>
                <th scope="col" className="p-3 font-semibold">Strategies</th>
                <th scope="col" className="p-3 font-semibold">Log Sources</th>
                <th scope="col" className="p-3 font-semibold text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredTechniques.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500">
                    No techniques matched the active filters and table search.
                  </td>
                </tr>
              ) : (
                filteredTechniques.slice(0, 20).map((tech) => (
                  <tr
                    key={tech.id}
                    onClick={() => onSelectTechniqueId && onSelectTechniqueId(tech.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="p-3 font-mono font-bold text-indigo-400 group-hover:text-indigo-300">
                      {tech.id}
                    </td>
                    <td className="p-3 font-medium text-slate-200 group-hover:text-slate-100 max-w-[200px] truncate">
                      {tech.name}
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1 max-w-[220px]">
                        {tech.tactics.slice(0, 2).map((tac) => (
                          <span
                            key={tac}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800"
                          >
                            {tac}
                          </span>
                        ))}
                        {tech.tactics.length > 2 && (
                          <span className="text-[10px] text-slate-500 self-center">
                            +{tech.tactics.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-slate-400 max-w-[140px] truncate">
                      {tech.platforms.join(', ') || 'Enterprise'}
                    </td>
                    <td className="p-3">
                      <span className="font-mono text-cyan-400 font-semibold">
                        {tech.detectionStrategyIds.length}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className="font-mono text-amber-400 font-semibold">
                        {tech.logSources.length}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onSelectTechniqueId) onSelectTechniqueId(tech.id);
                        }}
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-indigo-300 transition-colors"
                        title="View Technique Details"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {filteredTechniques.length > 20 && (
          <div className="p-3 bg-slate-950/40 border-t border-slate-800 text-[11px] text-center text-slate-400">
            Showing first 20 of {filteredTechniques.length} techniques. Use table search or filters to narrow.
          </div>
        )}
      </div>
    </div>
  );
};
