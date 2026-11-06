import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  Shield,
  ShieldCheck,
  Layers,
  PieChart,
  Info,
  RotateCcw,
  RefreshCw,
  AlertTriangle,
  Search,
  Filter,
  Check,
  X,
  FileCode2,
} from 'lucide-react';
import { UserProfile } from '../../types/auth';
import {
  fetchSecurityEngineerKnowledge,
  SecurityEngineerKnowledgeRecord,
  aggregateMitigationCoverage,
  aggregateTechniquesByMitigationCount,
  calculateSecurityEngineerKpis,
  aggregateTechniquesByTacticForEngineer,
} from '../../services/knowledgeService';
import { InteractiveBarChart, BarChartItem } from '../analyst/knowledge/charts/InteractiveBarChart';
import { InteractiveDonutChart, DonutChartItem } from '../analyst/knowledge/charts/InteractiveDonutChart';
import { ProvenanceBadge } from '../common/ProvenanceBadge';
import { Button } from '../common/Button';

export interface SecurityEngineerOverviewPageProps {
  currentUser?: UserProfile;
  onNavigateToTab?: (tab: string) => void;
  onSelectTechniqueId?: (techniqueId: string) => void;
  onSelectMitigationId?: (mitigationId: string) => void;
}

export const SecurityEngineerOverviewPage: React.FC<SecurityEngineerOverviewPageProps> = ({
  currentUser,
  onNavigateToTab,
  onSelectTechniqueId,
  onSelectMitigationId,
}) => {
  const [records, setRecords] = useState<SecurityEngineerKnowledgeRecord[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Chart interactive filter states
  const [selectedMitigationId, setSelectedMitigationId] = useState<string | null>(null);
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Primary data loader
  const loadKnowledge = useCallback(async () => {
    if (!currentUser) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchSecurityEngineerKnowledge(currentUser);
      setRecords(data);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Failed to query Security Engineer reference knowledge.'
      );
      setRecords([]);
    } finally {
      setIsLoading(false);
    }
  }, [currentUser]);

  useEffect(() => {
    let isMounted = true;

    async function initialFetch() {
      if (!currentUser) return;
      setIsLoading(true);
      setError(null);
      try {
        const data = await fetchSecurityEngineerKnowledge(currentUser);
        if (!isMounted) return;
        setRecords(data);
      } catch (err) {
        if (!isMounted) return;
        setError(
          err instanceof Error
            ? err.message
            : 'Failed to query Security Engineer reference knowledge.'
        );
        setRecords([]);
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    initialFetch();

    return () => {
      isMounted = false;
    };
  }, [currentUser]);

  // Exact 4 KPIs derived dynamically from verified records
  const kpis = useMemo(() => calculateSecurityEngineerKpis(records), [records]);

  // Chart 1: Mitigation Coverage Aggregation
  const mitigationCoverage = useMemo(() => aggregateMitigationCoverage(records), [records]);

  // Chart 2: Techniques by Mitigation Count Aggregation
  const techniquesByMitigation = useMemo(
    () => aggregateTechniquesByMitigationCount(records),
    [records]
  );

  // Chart 3: Techniques by Tactic Aggregation
  const tacticAgg = useMemo(
    () => aggregateTechniquesByTacticForEngineer(records),
    [records]
  );

  // Prepare Chart 1 items: Top 5 Mitigations by Technique Coverage
  const mitigationBarChartItems: BarChartItem[] = useMemo(() => {
    return mitigationCoverage.mitigations.map((m) => ({
      id: m.mitigationId,
      label: m.mitigationName,
      subLabel: m.mitigationId,
      count: m.addressedTechniquesCount,
      percentage: m.percentage,
      isSelected: selectedMitigationId === m.mitigationId,
    }));
  }, [mitigationCoverage.mitigations, selectedMitigationId]);

  // Prepare Chart 2 items: Top 5 Techniques by Mitigation Count
  const techniqueBarChartItems: BarChartItem[] = useMemo(() => {
    return techniquesByMitigation.map((t) => ({
      id: t.techniqueId,
      label: t.techniqueName,
      subLabel: t.techniqueId,
      count: t.distinctMitigationsCount,
      isSelected: selectedTechniqueId === t.techniqueId,
    }));
  }, [techniquesByMitigation, selectedTechniqueId]);

  // Prepare Chart 3 items: Techniques by Individual Tactic (for InteractiveDonutChart)
  const tacticDonutChartItems: DonutChartItem[] = useMemo(() => {
    return tacticAgg.tactics.map((t) => ({
      id: t.tactic,
      label: t.tactic,
      count: t.uniqueTechniquesCount,
      isSelected: selectedTactic === t.tactic,
    }));
  }, [tacticAgg.tactics, selectedTactic]);

  // Interactive toggle handlers for charts
  const handleToggleMitigation = (item: BarChartItem) => {
    const next = selectedMitigationId === item.id ? null : item.id;
    setSelectedMitigationId(next);
    if (next && onSelectMitigationId) {
      onSelectMitigationId(next);
    }
  };

  const handleToggleTechnique = (item: BarChartItem) => {
    const next = selectedTechniqueId === item.id ? null : item.id;
    setSelectedTechniqueId(next);
    if (next && onSelectTechniqueId) {
      onSelectTechniqueId(next);
    }
  };

  const handleToggleTactic = (item: DonutChartItem) => {
    if (item.isOther) return;
    setSelectedTactic((prev) => (prev === item.id ? null : item.id));
  };

  const handleResetSelections = () => {
    setSelectedMitigationId(null);
    setSelectedTechniqueId(null);
    setSelectedTactic(null);
    setSearchQuery('');
  };

  const hasActiveFilters = Boolean(
    selectedMitigationId || selectedTechniqueId || selectedTactic || searchQuery.trim()
  );

  // Curated list of techniques matching active filters
  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      if (selectedMitigationId && r.mitigation_id !== selectedMitigationId) {
        return false;
      }
      if (selectedTechniqueId && r.technique_id !== selectedTechniqueId) {
        return false;
      }
      if (selectedTactic) {
        const rawTactics =
          r.tactic_names && r.tactic_names.trim() ? r.tactic_names : r.technique_tactics;
        if (!rawTactics || typeof rawTactics !== 'string') {
          return false;
        }
        const tokens = rawTactics.split(/[,;|\n]+/).map((t) => t.trim());
        if (!tokens.some((t) => t.toLowerCase() === selectedTactic.toLowerCase())) {
          return false;
        }
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const haystack = `${r.technique_id || ''} ${r.technique_name || ''} ${r.mitigation_id || ''} ${r.mitigation_name || ''} ${r.tactic_names || ''}`.toLowerCase();
        if (!haystack.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [records, selectedMitigationId, selectedTechniqueId, selectedTactic, searchQuery]);

  // Distinct matching techniques from filtered records
  const distinctFilteredTechniques = useMemo(() => {
    const map = new Map<
      string,
      {
        techniqueId: string;
        techniqueName: string;
        tactics: string[];
        mitigations: Map<string, string>;
      }
    >();

    for (const r of filteredRecords) {
      if (!r.technique_id) continue;
      const tid = r.technique_id.trim();

      if (!map.has(tid)) {
        const tacticsSet = new Set<string>();
        const rawTactics = r.tactic_names || r.technique_tactics;
        if (rawTactics) {
          rawTactics.split(/[,;|\n]+/).forEach((t) => {
            const clean = t.trim();
            if (clean) tacticsSet.add(clean);
          });
        }
        map.set(tid, {
          techniqueId: tid,
          techniqueName: r.technique_name || tid,
          tactics: Array.from(tacticsSet),
          mitigations: new Map<string, string>(),
        });
      }

      if (r.mitigation_id) {
        const mid = r.mitigation_id.trim();
        const mname = r.mitigation_name || mid;
        map.get(tid)!.mitigations.set(mid, mname);
      }
    }

    return Array.from(map.values());
  }, [filteredRecords]);

  // Loading skeleton state
  if (isLoading) {
    return (
      <div className="space-y-6 animate-pulse p-1">
        {/* Header Skeleton */}
        <div className="h-16 bg-slate-900 border border-slate-800 rounded-xl" />

        {/* Disclaimer Skeleton */}
        <div className="h-14 bg-slate-900 border border-slate-800 rounded-xl" />

        {/* KPI Strip Skeleton */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-24 bg-slate-900 border border-slate-800 rounded-xl" />
          ))}
        </div>

        {/* Chart Viewport Skeletons */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="h-80 bg-slate-900 border border-slate-800 rounded-xl" />
          <div className="h-80 bg-slate-900 border border-slate-800 rounded-xl" />
        </div>
        <div className="h-80 bg-slate-900 border border-slate-800 rounded-xl" />
      </div>
    );
  }

  // Error state with retry
  if (error) {
    return (
      <div className="p-8 bg-slate-900 border border-rose-900/60 rounded-xl text-center space-y-4 max-w-xl mx-auto my-8">
        <AlertTriangle className="w-10 h-10 text-rose-400 mx-auto" />
        <div className="space-y-1">
          <h2 className="text-base font-bold text-slate-100">
            Security Engineer Knowledge Unavailable
          </h2>
          <p className="text-xs text-slate-400 leading-relaxed">{error}</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={loadKnowledge}
          icon={<RefreshCw className="w-3.5 h-3.5" />}
        >
          Retry Knowledge Query
        </Button>
      </div>
    );
  }

  // Empty state
  if (records.length === 0) {
    return (
      <div className="p-12 bg-slate-900 border border-slate-800 rounded-xl text-center space-y-3">
        <Shield className="w-10 h-10 text-slate-500 mx-auto" />
        <h2 className="text-base font-bold text-slate-100">No Knowledge Records Found</h2>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          The public.security_engineer_knowledge table returned no reference rows for this role.
        </p>
        <Button size="sm" variant="outline" onClick={loadKnowledge}>
          Reload Knowledge Base
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 1. Header Toolbar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-950/80 border border-cyan-800 rounded-xl text-cyan-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold text-slate-100 font-heading">
                Security Engineering Overview
              </h1>
              <ProvenanceBadge type="authentic_mitre" label="MITRE v14.1 ENTERPRISE" />
              <span className="text-xs font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                public.security_engineer_knowledge
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Summary of MITRE technique and mitigation reference mappings across enterprise architectures.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleResetSelections}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Reset Selections</span>
            </button>
          )}
          <button
            type="button"
            onClick={loadKnowledge}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. Mandatory Disclaimer Banner */}
      <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl text-xs flex items-start gap-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-slate-200">
            Reference Mapping Architecture Disclaimer:
          </span>
          <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
            Mitigation mapping coverage represents reference mappings in the dataset. It does not confirm that mitigations are deployed or effective in the environment.
          </p>
        </div>
      </div>

      {/* 3. Four Exact KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        {/* KPI 1: Unique Techniques */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Unique Techniques</div>
          <div className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
            {kpis.uniqueTechniques}
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Distinct cataloged ATT&CK techniques</p>
        </div>

        {/* KPI 2: Unique Mitigations */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Unique Mitigations</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
            {kpis.uniqueMitigations}
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Preventative defensive controls</p>
        </div>

        {/* KPI 3: Mitigation Mapping Coverage */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Mitigation Mapping Coverage</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 tabular-nums">
            {kpis.mitigationCoverageDisplay}
          </div>
          <p className="text-[10px] text-slate-500 mt-1">
            {kpis.mitigatedTechniques} of {kpis.uniqueTechniques} techniques mapped
          </p>
        </div>

        {/* KPI 4: Total Mapping Records */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Total Mapping Records</div>
          <div className="text-2xl font-bold font-mono text-indigo-400 tabular-nums">
            {kpis.totalMappingRecords.toLocaleString()}
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Enterprise reference rows</p>
        </div>
      </div>

      {/* 4. Three Visualizations */}
      {/* Row 1: Chart 1 (Top 5 Mitigations) & Chart 2 (Top 5 Techniques) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Chart 1: Top 5 Mitigations by Technique Coverage */}
        <InteractiveBarChart
          title="Top 5 Mitigations by Technique Coverage"
          subtitle="Defensive enterprise controls ranked by distinct ATT&CK techniques addressed. Click to toggle filter."
          badge={`${kpis.uniqueMitigations} Mitigations`}
          icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
          items={mitigationBarChartItems}
          colorScheme="emerald"
          onItemClick={handleToggleMitigation}
          emptyMessage="No mitigation coverage data available."
          maxDisplay={5}
        />

        {/* Chart 2: Top 5 Techniques by Mitigation Count */}
        <InteractiveBarChart
          title="Top 5 Techniques by Mitigation Count"
          subtitle="ATT&CK techniques with the highest number of mapped preventative mitigations. Click to toggle filter."
          badge={`${techniquesByMitigation.length} Mitigated`}
          icon={<Layers className="w-4 h-4 text-cyan-400" />}
          items={techniqueBarChartItems}
          colorScheme="cyan"
          onItemClick={handleToggleTechnique}
          emptyMessage="No technique mitigation mappings available."
          maxDisplay={5}
        />
      </div>

      {/* Row 2: Chart 3: Techniques by Individual Tactic (Donut Chart) */}
      <InteractiveDonutChart
        title="Techniques by Individual Tactic"
        subtitle="Distribution of cataloged techniques across MITRE ATT&CK enterprise tactics. Click a slice to toggle filter."
        badge={`${tacticAgg.tactics.length} Tactics`}
        icon={<PieChart className="w-4 h-4 text-indigo-400" />}
        items={tacticDonutChartItems}
        topN={5}
        totalLabel="Technique-Tactic Mappings"
        onItemClick={handleToggleTactic}
        emptyMessage="No tactic distribution data available."
      />

      {/* 5. Filtered Details & Drill-down Inspection Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-heading">
              <Filter className="w-4 h-4 text-cyan-400" />
              <span>Reference Technique Drilldown</span>
              <span className="text-xs font-mono font-normal text-slate-400">
                ({distinctFilteredTechniques.length} matching techniques)
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspecting reference techniques matching active chart selections and search filters.
            </p>
          </div>

          {/* Search box within drilldown */}
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search ID, name, or mitigation..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:ring-1 focus:ring-cyan-500 focus:outline-none font-mono"
            />
          </div>
        </div>

        {/* Active Filter Pills Bar */}
        {hasActiveFilters && (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400 text-[11px] font-medium">Active Filters:</span>
            {selectedMitigationId && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800">
                <span>Mitigation: {selectedMitigationId}</span>
                <button
                  type="button"
                  onClick={() => setSelectedMitigationId(null)}
                  className="hover:text-emerald-100 cursor-pointer"
                  title="Remove mitigation filter"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {selectedTechniqueId && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
                <span>Technique: {selectedTechniqueId}</span>
                <button
                  type="button"
                  onClick={() => setSelectedTechniqueId(null)}
                  className="hover:text-cyan-100 cursor-pointer"
                  title="Remove technique filter"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {selectedTactic && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">
                <span>Tactic: {selectedTactic}</span>
                <button
                  type="button"
                  onClick={() => setSelectedTactic(null)}
                  className="hover:text-indigo-100 cursor-pointer"
                  title="Remove tactic filter"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            {searchQuery.trim() && (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                <span>Search: &quot;{searchQuery.trim()}&quot;</span>
                <button
                  type="button"
                  onClick={() => setSearchQuery('')}
                  className="hover:text-slate-100 cursor-pointer"
                  title="Clear search"
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            )}
            <button
              type="button"
              onClick={handleResetSelections}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 underline font-mono cursor-pointer ml-auto"
            >
              Reset All
            </button>
          </div>
        )}

        {/* Drilldown Technique Cards Table / List */}
        {distinctFilteredTechniques.length === 0 ? (
          <div className="py-8 text-center text-slate-500 text-xs italic">
            No ATT&CK techniques match the selected combination of chart filters and search query.
          </div>
        ) : (
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {distinctFilteredTechniques.slice(0, 50).map((tech) => {
              const mitList = Array.from(tech.mitigations.entries());

              return (
                <div
                  key={tech.techniqueId}
                  className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-xs space-y-2 hover:border-slate-700 transition"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800 shrink-0">
                        {tech.techniqueId}
                      </span>
                      <span className="font-semibold text-slate-100 truncate">
                        {tech.techniqueName}
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 shrink-0">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
                        {mitList.length} {mitList.length === 1 ? 'mitigation' : 'mitigations'}
                      </span>
                      {onNavigateToTab && (
                        <button
                          type="button"
                          onClick={() => {
                            if (onSelectTechniqueId) onSelectTechniqueId(tech.techniqueId);
                            onNavigateToTab('workbench');
                          }}
                          className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer bg-slate-900 px-2 py-0.5 rounded border border-slate-800"
                        >
                          <FileCode2 className="w-3 h-3" />
                          <span>Draft Rule</span>
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Tactics Tags */}
                  {tech.tactics.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-slate-400">
                      <span className="text-slate-500">Tactics:</span>
                      {tech.tactics.map((tac) => (
                        <span
                          key={tac}
                          className="px-1.5 py-0.2 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-900/60"
                        >
                          {tac}
                        </span>
                      ))}
                    </div>
                  )}

                  {/* Mitigations List */}
                  {mitList.length > 0 ? (
                    <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-900">
                      <span className="text-slate-500">Mitigations:</span>
                      {mitList.map(([mid, mname]) => (
                        <span
                          key={mid}
                          className="px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-900/60"
                          title={`${mid}: ${mname}`}
                        >
                          {mid} {mname !== mid ? `(${mname})` : ''}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[10px] font-mono text-amber-400/80 pt-1 border-t border-slate-900 flex items-center gap-1">
                      <Info className="w-3 h-3" />
                      <span>No preventative mitigations cataloged in reference scope (Coverage Gap)</span>
                    </div>
                  )}
                </div>
              );
            })}
            {distinctFilteredTechniques.length > 50 && (
              <div className="py-2 text-center text-slate-500 text-[11px] font-mono">
                Showing top 50 of {distinctFilteredTechniques.length} matching techniques. Refine search or chart filter for specific techniques.
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
