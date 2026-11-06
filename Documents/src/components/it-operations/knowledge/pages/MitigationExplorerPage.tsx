import React, { useState, useMemo } from 'react';
import {
  ShieldCheck,
  Search,
  Filter,
  Info,
  Server,
  Layers,
  RotateCcw,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { ItOperationsKnowledgeRecord } from '../../../../services/knowledgeService';
import {
  ItOpsKnowledgeFilters,
  AggregatedItOpsMitigation,
} from '../types';
import {
  extractItOpsMitigations,
  filterAggregatedMitigations,
} from '../itOpsFilterUtils';
import { ItOpsMitigationDetailModal } from '../modals/ItOpsMitigationDetailModal';

interface MitigationExplorerPageProps {
  records: ItOperationsKnowledgeRecord[];
  filters: ItOpsKnowledgeFilters;
  onUpdateFilters: (updater: (prev: ItOpsKnowledgeFilters) => ItOpsKnowledgeFilters) => void;
  onSelectTechniqueId?: (techniqueId: string) => void;
}

export const MitigationExplorerPage: React.FC<MitigationExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [selectedMitigation, setSelectedMitigation] = useState<AggregatedItOpsMitigation | null>(null);

  // Extract all mitigations from records
  const allMitigations = useMemo(() => extractItOpsMitigations(records), [records]);

  // Filtered mitigations
  const filteredMitigations = useMemo(
    () => filterAggregatedMitigations(allMitigations, filters),
    [allMitigations, filters]
  );

  // Two KPIs: Total Cataloged Mitigations, Techniques with Active Mitigations
  const totalMitigations = allMitigations.length;
  const totalMitigatedTechniques = useMemo(() => {
    const techSet = new Set<string>();
    for (const m of allMitigations) {
      for (const t of m.associatedTechniques) {
        techSet.add(t.id);
      }
    }
    return techSet.size;
  }, [allMitigations]);

  const clearAllFilters = () => {
    onUpdateFilters((prev) => ({
      ...prev,
      searchQuery: '',
      selectedMitigations: [],
    }));
  };

  return (
    <div className="space-y-6">
      {/* 1. Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-emerald-950/80 border border-emerald-800 rounded-xl text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Enterprise Mitigation Explorer
              </h2>
              <span className="text-xs font-mono text-emerald-300 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                {totalMitigations} Preventative Controls
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified ATT&CK mitigations, operational descriptions, and supported technique associations.
            </p>
          </div>
        </div>

        {(Boolean(filters.searchQuery) || filters.selectedMitigations.length > 0) && (
          <button
            type="button"
            onClick={clearAllFilters}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer self-start sm:self-auto"
          >
            <RotateCcw className="w-3.5 h-3.5 text-emerald-400" />
            <span>Reset Search</span>
          </button>
        )}
      </div>

      {/* 2. Exactly Two KPIs */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Distinct Preventative Mitigations</div>
          <div className="text-2xl font-bold font-mono text-slate-100">{totalMitigations}</div>
          <p className="text-[10px] text-slate-500 mt-1">Verified mitigation IDs cataloged in public.it_operations_knowledge</p>
        </div>

        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow-xs">
          <div className="text-xs font-semibold text-slate-400 mb-1">Techniques with Active Mitigations</div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{totalMitigatedTechniques}</div>
          <p className="text-[10px] text-slate-500 mt-1">
            Distinct ATT&CK techniques with at least one cataloged defensive mitigation
          </p>
        </div>
      </div>

      {/* 3. Search Toolbar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search by mitigation ID, name, or description keywords..."
            value={filters.searchQuery}
            onChange={(e) =>
              onUpdateFilters((prev) => ({ ...prev, searchQuery: e.target.value }))
            }
            className="w-full pl-9 pr-3 py-2 bg-slate-950 text-xs text-slate-200 placeholder-slate-500 border border-slate-800 rounded-lg focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="text-xs font-mono text-slate-400">
          Showing <strong className="text-slate-200">{filteredMitigations.length}</strong> of{' '}
          {allMitigations.length} mitigations
        </div>
      </div>

      {/* 4. Searchable Data Table with Verified Fields (NO CHARTS per prompt) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs">
        {filteredMitigations.length === 0 ? (
          <div className="p-12 text-center text-xs text-slate-500 italic">
            No mitigations match your search criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 border-b border-slate-800 font-mono text-[11px] text-slate-400 uppercase">
                <tr>
                  <th className="p-3 w-32">Mitigation ID</th>
                  <th className="p-3 w-64">Mitigation Name</th>
                  <th className="p-3">Operational Description</th>
                  <th className="p-3 text-center w-36">Mitigated Techniques</th>
                  <th className="p-3 text-right w-24">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {filteredMitigations.map((mit) => (
                  <tr
                    key={mit.id}
                    className="hover:bg-slate-800/40 transition cursor-pointer"
                    onClick={() => setSelectedMitigation(mit)}
                  >
                    <td className="p-3 font-mono font-bold text-emerald-400 whitespace-nowrap">
                      {mit.id}
                    </td>
                    <td className="p-3 font-semibold text-slate-200">
                      {mit.name}
                    </td>
                    <td className="p-3 text-slate-400 text-xs line-clamp-2 max-w-md">
                      {mit.description}
                    </td>
                    <td className="p-3 text-center">
                      <span className="px-2.5 py-0.5 rounded text-xs font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {mit.associatedTechniques.length}
                      </span>
                    </td>
                    <td className="p-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedMitigation(mit);
                        }}
                        className="text-emerald-400 hover:text-emerald-300 text-xs font-semibold inline-flex items-center gap-1"
                      >
                        Inspect <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Mitigation Detail Modal */}
      <ItOpsMitigationDetailModal
        mitigation={selectedMitigation}
        isOpen={Boolean(selectedMitigation)}
        onClose={() => setSelectedMitigation(null)}
        onSelectTechnique={onSelectTechniqueId}
      />
    </div>
  );
};
