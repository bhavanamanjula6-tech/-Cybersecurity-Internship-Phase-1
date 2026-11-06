import React, { useState, useMemo } from 'react';
import {
  Server,
  Layers,
  ShieldCheck,
  Search,
  Filter,
  Info,
  Database,
  ExternalLink,
  RotateCcw,
  Sparkles,
} from 'lucide-react';
import { ItOperationsKnowledgeRecord } from '../../../../services/knowledgeService';
import {
  ItOpsKnowledgeFilters,
  AggregatedItOpsTechnique,
} from '../types';
import {
  extractItOpsTechniques,
  aggregateTechniquesByPlatform,
  aggregateTechniquesByTactic,
  calculateItOpsKpis,
  buildPlatformBarChartItems,
  buildTacticBarChartItems,
  filterAggregatedTechniques,
} from '../itOpsFilterUtils';
import { InteractiveBarChart } from '../../../analyst/knowledge/charts/InteractiveBarChart';
import { ItOpsTechniqueDetailModal } from '../modals/ItOpsTechniqueDetailModal';

interface ItOpsOverviewPageProps {
  records: ItOperationsKnowledgeRecord[];
  filters: ItOpsKnowledgeFilters;
  onUpdateFilters: (updater: (prev: ItOpsKnowledgeFilters) => ItOpsKnowledgeFilters) => void;
  onSelectTechniqueId?: (techniqueId: string) => void;
  onSelectMitigationId?: (mitigationId: string) => void;
}

export const ItOpsOverviewPage: React.FC<ItOpsOverviewPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
  onSelectMitigationId,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<AggregatedItOpsTechnique | null>(null);

  // KPIs derived dynamically from current filtered records
  const kpis = useMemo(() => calculateItOpsKpis(records), [records]);

  // Extract all techniques, platforms, and tactics from current records
  const allTechniques = useMemo(() => extractItOpsTechniques(records), [records]);
  const platformAgg = useMemo(() => aggregateTechniquesByPlatform(records), [records]);
  const tacticAgg = useMemo(() => aggregateTechniquesByTactic(records), [records]);

  // Chart data items (Top 5 Platforms & Top 5 Tactics by technique coverage)
  const platformBarChartItems = useMemo(
    () => buildPlatformBarChartItems(platformAgg, filters.selectedPlatforms),
    [platformAgg, filters.selectedPlatforms]
  );

  const tacticBarChartItems = useMemo(
    () => buildTacticBarChartItems(tacticAgg, filters.selectedTactics),
    [tacticAgg, filters.selectedTactics]
  );

  // Filtered techniques for table display
  const filteredTechniques = useMemo(
    () => filterAggregatedTechniques(allTechniques, filters),
    [allTechniques, filters]
  );

  const togglePlatformFilter = (platform: string) => {
    onUpdateFilters((prev) => {
      const exists = prev.selectedPlatforms.includes(platform);
      return {
        ...prev,
        selectedPlatforms: exists
          ? prev.selectedPlatforms.filter((p) => p !== platform)
          : [...prev.selectedPlatforms, platform],
      };
    });
  };

  const toggleTacticFilter = (tactic: string) => {
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

  const handleResetFilters = () => {
    onUpdateFilters((prev) => ({
      ...prev,
      searchQuery: '',
      selectedPlatforms: [],
      selectedTactics: [],
      selectedMitigations: [],
    }));
  };

  const hasActiveFilters =
    Boolean(filters.searchQuery.trim()) ||
    filters.selectedPlatforms.length > 0 ||
    filters.selectedTactics.length > 0 ||
    filters.selectedMitigations.length > 0;

  return (
    <div className="space-y-6">
      {/* 1. Header & Context */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-amber-950/80 border border-amber-800 rounded-xl text-amber-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                IT Operations Knowledge Overview
              </h2>
              <span className="text-xs font-mono text-amber-300 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                public.it_operations_knowledge
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified ATT&CK technique applicability across computing platforms and preventative mitigations.
            </p>
          </div>
        </div>

        {hasActiveFilters && (
          <button
            type="button"
            onClick={handleResetFilters}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer self-start sm:self-auto"
          >
            <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
            <span>Reset Active Selections</span>
          </button>
        )}
      </div>

      {/* 2. Non-Deployment Disclaimer Banner */}
      <div className="p-3.5 bg-slate-900/90 border border-slate-800 rounded-xl text-xs flex items-start gap-3">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="font-semibold text-slate-200">
            Reference Mapping Architecture Disclaimer:
          </span>
          <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
            Reference Knowledge Base: Connected to <code className="font-mono text-slate-300">public.it_operations_knowledge</code>.
            These metrics and distributions summarize ATT&CK technique coverage and preventative mitigations cataloged for enterprise host architectures.
            <strong> These reference distributions represent technique coverage standards, NOT physical devices or installed host inventory.</strong>
          </p>
        </div>
      </div>

      {/* 3. Four Verified KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Total Cataloged Techniques</div>
          <div className="text-2xl font-bold font-mono text-slate-100">{kpis.totalCatalogedTechniques}</div>
          <p className="text-[10px] text-slate-500 mt-1">Distinct ATT&CK technique IDs</p>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Supported Platforms</div>
          <div className="text-2xl font-bold font-mono text-cyan-400">{kpis.supportedPlatforms}</div>
          <p className="text-[10px] text-slate-500 mt-1">Computing environments</p>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Enterprise Mitigations</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{kpis.enterpriseMitigations}</div>
          <p className="text-[10px] text-slate-500 mt-1">Preventative defensive controls</p>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Covered Tactics</div>
          <div className="text-2xl font-bold font-mono text-indigo-400">{kpis.coveredTactics}</div>
          <p className="text-[10px] text-slate-500 mt-1">Enterprise attack phases</p>
        </div>
      </div>

      {/* 4. Exactly Two Charts: Top 5 Platforms Bar Chart & Top 5 Tactics Bar Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <InteractiveBarChart
          title="Top 5 Platforms by Technique Coverage"
          subtitle="Top computing environments ranked by distinct ATT&CK technique coverage. Click bar to toggle filter."
          badge={`${platformAgg.length} Platforms`}
          icon={<Server className="w-4 h-4 text-cyan-400" />}
          items={platformBarChartItems}
          colorScheme="cyan"
          onItemClick={(item) => togglePlatformFilter(item.id)}
          emptyMessage="No platform distribution data available."
          maxDisplay={5}
        />

        <InteractiveBarChart
          title="Top 5 Tactics by Technique Coverage"
          subtitle="Top enterprise attack phases ranked by distinct ATT&CK technique coverage. Click bar to toggle filter."
          badge={`${tacticAgg.length} Tactics`}
          icon={<Layers className="w-4 h-4 text-indigo-400" />}
          items={tacticBarChartItems}
          colorScheme="indigo"
          onItemClick={(item) => toggleTacticFilter(item.id)}
          emptyMessage="No tactic distribution data available."
          maxDisplay={5}
        />
      </div>

      {/* 5. Searchable Records Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Cataloged Techniques & Defensive Coverage
              <span className="text-xs font-mono font-normal text-amber-300 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                {filteredTechniques.length} of {allTechniques.length}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Verified ATT&CK techniques with mapped computing platforms and preventative mitigations.
            </p>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search techniques or platforms..."
              value={filters.searchQuery}
              onChange={(e) =>
                onUpdateFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
              }
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 border border-slate-800 rounded-lg focus:outline-none focus:border-amber-500"
            />
          </div>
        </div>

        {filteredTechniques.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 italic">
            No techniques match the current search or filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 font-mono text-[11px] text-slate-400 uppercase">
                <tr>
                  <th className="p-3 w-28">Technique ID</th>
                  <th className="p-3">Technique Name</th>
                  <th className="p-3">Target Platforms</th>
                  <th className="p-3">Covered Tactics</th>
                  <th className="p-3 text-center w-28">Mitigations</th>
                  <th className="p-3 text-right w-20">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredTechniques.slice(0, 100).map((tech) => (
                  <tr
                    key={tech.id}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                    onClick={() => setSelectedTechnique(tech)}
                  >
                    <td className="p-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                      {tech.id}
                    </td>
                    <td className="p-3 text-slate-200 font-medium">
                      {tech.name}
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {tech.platforms.slice(0, 3).map((p) => (
                          <span
                            key={p}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                          >
                            {p}
                          </span>
                        ))}
                        {tech.platforms.length > 3 && (
                          <span className="text-[10px] text-slate-500">
                            +{tech.platforms.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {tech.tactics.slice(0, 2).map((t) => (
                          <span
                            key={t}
                            className="px-1.5 py-0.5 rounded text-[10px] bg-indigo-950/70 text-indigo-300 border border-indigo-900"
                          >
                            {t}
                          </span>
                        ))}
                        {tech.tactics.length > 2 && (
                          <span className="text-[10px] text-slate-500">
                            +{tech.tactics.length - 2}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="p-3 text-center">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          tech.mitigations.length > 0
                            ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                            : 'bg-slate-800 text-slate-500 border border-slate-700'
                        }`}
                      >
                        {tech.mitigations.length}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedTechnique(tech);
                        }}
                        className="text-amber-400 hover:text-amber-300 text-xs font-medium"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredTechniques.length > 100 && (
              <div className="p-3 text-center text-xs text-slate-500 border-t border-slate-800 bg-slate-950/40">
                Displaying first 100 of {filteredTechniques.length} matching techniques. Refine search to narrow results.
              </div>
            )}
          </div>
        )}
      </div>

      {/* Technique Detail Modal */}
      <ItOpsTechniqueDetailModal
        technique={selectedTechnique}
        isOpen={Boolean(selectedTechnique)}
        onClose={() => setSelectedTechnique(null)}
        onFilterByPlatform={togglePlatformFilter}
        onSelectMitigation={onSelectMitigationId}
      />
    </div>
  );
};
