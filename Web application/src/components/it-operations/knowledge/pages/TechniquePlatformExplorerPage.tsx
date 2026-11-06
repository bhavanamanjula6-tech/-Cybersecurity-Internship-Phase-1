import React, { useState, useMemo } from 'react';
import {
  Server,
  Layers,
  Search,
  Filter,
  Info,
  ShieldCheck,
  RotateCcw,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { ItOperationsKnowledgeRecord } from '../../../../services/knowledgeService';
import {
  ItOpsKnowledgeFilters,
  AggregatedItOpsTechnique,
} from '../types';
import {
  extractItOpsTechniques,
  filterAggregatedTechniques,
  aggregateTechniquesByPlatform,
} from '../itOpsFilterUtils';
import { ItOpsTechniqueDetailModal } from '../modals/ItOpsTechniqueDetailModal';

interface TechniquePlatformExplorerPageProps {
  records: ItOperationsKnowledgeRecord[];
  filters: ItOpsKnowledgeFilters;
  onUpdateFilters: (updater: (prev: ItOpsKnowledgeFilters) => ItOpsKnowledgeFilters) => void;
  onSelectMitigationId?: (mitigationId: string) => void;
}

export const TechniquePlatformExplorerPage: React.FC<TechniquePlatformExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectMitigationId,
}) => {
  const [selectedTechnique, setSelectedTechnique] = useState<AggregatedItOpsTechnique | null>(null);

  // Extract all techniques and platforms from records
  const allTechniques = useMemo(() => extractItOpsTechniques(records), [records]);
  const allPlatforms = useMemo(() => aggregateTechniquesByPlatform(records), [records]);

  // Extract all unique tactics
  const allTactics = useMemo(() => {
    const set = new Set<string>();
    for (const t of allTechniques) {
      for (const tac of t.tactics) set.add(tac);
    }
    return Array.from(set).sort();
  }, [allTechniques]);

  // Filter techniques
  const filteredTechniques = useMemo(
    () => filterAggregatedTechniques(allTechniques, filters),
    [allTechniques, filters]
  );

  // Two KPIs: Total Cataloged Techniques, Platform-Mapped Techniques
  const totalCatalogedTechniques = allTechniques.length;
  const platformMappedTechniques = allTechniques.filter((t) => t.platforms.length > 0).length;

  const togglePlatform = (platform: string) => {
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

  const clearAllFilters = () => {
    onUpdateFilters((prev) => ({
      ...prev,
      searchQuery: '',
      selectedPlatforms: [],
      selectedTactics: [],
    }));
  };

  return (
    <div className="space-y-6">
      {/* 1. Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-950/80 border border-cyan-800 rounded-xl text-cyan-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Technique & Platform Explorer
              </h2>
              <span className="text-xs font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                {allPlatforms.length} Enterprise Platforms
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Explore MITRE ATT&CK techniques categorized by host architecture, OS platform, and attack phase.
            </p>
          </div>
        </div>

        {(Boolean(filters.searchQuery) ||
          filters.selectedPlatforms.length > 0 ||
          filters.selectedTactics.length > 0) && (
          <button
            type="button"
            onClick={clearAllFilters}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer self-start sm:self-auto"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Reset Filters</span>
          </button>
        )}
      </div>

      {/* 2. Exactly Two KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Total Cataloged Techniques</div>
          <div className="text-2xl font-bold font-mono text-slate-100">{totalCatalogedTechniques}</div>
          <p className="text-[10px] text-slate-500 mt-1">Distinct ATT&CK IDs in IT Operations reference dataset</p>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Platform-Mapped Techniques</div>
          <div className="text-2xl font-bold font-mono text-cyan-400">{platformMappedTechniques}</div>
          <p className="text-[10px] text-slate-500 mt-1">
            Techniques with verified host computing platform coverage
          </p>
        </div>
      </div>

      {/* 3. Search and Multi-Dimensional Filter Toolbar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl space-y-3.5 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by technique ID, name, or platform keywords..."
              value={filters.searchQuery}
              onChange={(e) =>
                onUpdateFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
              }
              className="w-full pl-9 pr-3 py-2 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 border border-slate-800 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="text-xs font-mono text-slate-400">
            Showing <strong className="text-slate-200">{filteredTechniques.length}</strong> of{' '}
            {allTechniques.length} techniques
          </div>
        </div>

        {/* Platform Quick Filter Pills */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-mono uppercase text-slate-400 font-bold flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            Filter by Computing Platform:
          </div>
          <div className="flex flex-wrap gap-1.5">
            {allPlatforms.map((p) => {
              const isSelected = filters.selectedPlatforms.includes(p.platform);
              return (
                <button
                  key={p.platform}
                  type="button"
                  onClick={() => togglePlatform(p.platform)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-mono transition cursor-pointer flex items-center gap-1.5 ${
                    isSelected
                      ? 'bg-cyan-950 text-cyan-300 border border-cyan-500 font-bold'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <span>{p.platform}</span>
                  <span
                    className={`text-[10px] px-1 rounded ${
                      isSelected ? 'bg-cyan-900 text-cyan-200' : 'bg-slate-800 text-slate-500'
                    }`}
                  >
                    {p.distinctTechniqueCount}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Tactic Quick Filter Pills */}
        <div className="space-y-1.5">
          <div className="text-[11px] font-mono uppercase text-slate-400 font-bold flex items-center gap-1.5">
            <Layers className="w-3.5 h-3.5 text-indigo-400" />
            Filter by ATT&CK Tactic:
          </div>
          <div className="flex flex-wrap gap-1.5 max-h-24 overflow-y-auto pr-1">
            {allTactics.map((tac) => {
              const isSelected = filters.selectedTactics.includes(tac);
              return (
                <button
                  key={tac}
                  type="button"
                  onClick={() => toggleTactic(tac)}
                  className={`px-2.5 py-1 rounded-lg text-xs transition cursor-pointer ${
                    isSelected
                      ? 'bg-indigo-950 text-indigo-300 border border-indigo-500 font-bold'
                      : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  {tac}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* 4. Searchable Data Table with Verified Fields (NO CHARTS per prompt) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs">
        {filteredTechniques.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500 italic">
            No techniques match the selected platform and search filters.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 font-mono text-[11px] text-slate-400 uppercase">
                <tr>
                  <th className="p-3 w-32">Technique ID</th>
                  <th className="p-3">Technique Title</th>
                  <th className="p-3">Target Platforms</th>
                  <th className="p-3">Enterprise Tactics</th>
                  <th className="p-3 text-center w-28">Mitigations</th>
                  <th className="p-3 text-right w-24">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredTechniques.map((tech) => (
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
                      <div className="flex flex-wrap gap-1">
                        {tech.platforms.map((p) => (
                          <span
                            key={p}
                            className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                          >
                            {p}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {tech.tactics.map((t) => (
                          <span
                            key={t}
                            className="px-2 py-0.5 rounded text-[10px] bg-indigo-950/60 text-indigo-300 border border-indigo-900"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="p-3 text-center">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          tech.mitigations.length > 0
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
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
                        className="text-cyan-400 hover:text-cyan-300 text-xs font-semibold inline-flex items-center gap-1"
                      >
                        Details <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Technique Detail Modal */}
      <ItOpsTechniqueDetailModal
        technique={selectedTechnique}
        isOpen={Boolean(selectedTechnique)}
        onClose={() => setSelectedTechnique(null)}
        onFilterByPlatform={togglePlatform}
        onFilterByTactic={toggleTactic}
        onSelectMitigation={onSelectMitigationId}
      />
    </div>
  );
};
