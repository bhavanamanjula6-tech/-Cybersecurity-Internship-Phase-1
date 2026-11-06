import React, { useState, useMemo, useEffect } from 'react';
import {
  FileCode,
  Search,
  Eye,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters } from '../types';
import { extractDetectionStrategies } from '../filterUtils';
import { PaginationControls } from '../PaginationControls';

interface DetectionStrategyExplorerPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords?: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onSelectTechniqueId: (techniqueId: string) => void;
}

export const DetectionStrategyExplorerPage: React.FC<DetectionStrategyExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const [selectedStrategyId, setSelectedStrategyId] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  // Extract deduplicated detection strategies from filtered records
  const strategies = useMemo(() => {
    return extractDetectionStrategies(records);
  }, [records]);

  // Filtered strategies for table search
  const filteredStrategies = useMemo(() => {
    if (!localSearch.trim()) return strategies;
    const q = localSearch.toLowerCase();
    return strategies.filter(
      (s) =>
        s.strategyId.toLowerCase().includes(q) ||
        s.strategyName.toLowerCase().includes(q) ||
        s.associatedTechniques.some(
          (t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
        ) ||
        s.associatedTactics.some((tac) => tac.toLowerCase().includes(q))
    );
  }, [strategies, localSearch]);

  // Reset to page 1 whenever local search or global filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [localSearch, filters]);

  // Paginated slice
  const paginatedStrategies = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredStrategies.slice(start, start + pageSize);
  }, [filteredStrategies, currentPage, pageSize]);

  const activeStrategy = useMemo(() => {
    if (selectedStrategyId) {
      const found = filteredStrategies.find((s) => s.strategyId === selectedStrategyId);
      if (found) return found;
    }
    return filteredStrategies.length > 0 ? filteredStrategies[0] : null;
  }, [filteredStrategies, selectedStrategyId]);

  const toggleStrategyFilter = (strategyId: string) => {
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

  const totalStrategies = strategies.length;

  return (
    <div className="space-y-6">
      {/* 1. Page Heading */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-950/80 border border-cyan-800 rounded-xl text-cyan-400">
            <FileCode className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Detection Strategy Analytics
              </h2>
              <span className="text-xs font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                {totalStrategies} Cataloged Strategies
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified detection blueprints cataloged in <code className="text-slate-300 font-mono">public.soc_analyst_knowledge</code>.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Searchable Data Table with Detail Panel & Pagination */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Table column */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col">
          <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Detection Blueprint Catalog
                <span className="text-xs font-mono font-normal text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                  {filteredStrategies.length}
                </span>
              </h3>
            </div>
            <div className="relative min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder="Search strategies or techniques..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th scope="col" className="p-3 font-semibold">Strategy ID</th>
                  <th scope="col" className="p-3 font-semibold">Strategy Name</th>
                  <th scope="col" className="p-3 font-semibold">Techniques</th>
                  <th scope="col" className="p-3 font-semibold">Tactics</th>
                  <th scope="col" className="p-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredStrategies.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="p-8 text-center text-slate-500">
                      No detection strategies match the current criteria.
                    </td>
                  </tr>
                ) : (
                  paginatedStrategies.map((strat) => {
                    const isSelected = activeStrategy?.strategyId === strat.strategyId;
                    return (
                      <tr
                        key={strat.strategyId}
                        onClick={() => setSelectedStrategyId(strat.strategyId)}
                        className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${
                          isSelected ? 'bg-cyan-950/30 border-l-2 border-cyan-500' : ''
                        }`}
                      >
                        <td className="p-3 font-mono font-bold text-cyan-400 whitespace-nowrap">
                          {strat.strategyId}
                        </td>
                        <td className="p-3 font-medium text-slate-200 max-w-[220px] truncate">
                          {strat.strategyName}
                        </td>
                        <td className="p-3 font-mono text-slate-300">
                          <span className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-indigo-300 font-semibold">
                            {strat.associatedTechniques.length}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400 max-w-[160px] truncate">
                          {strat.associatedTactics.join(', ') || 'Enterprise'}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleStrategyFilter(strat.strategyId);
                            }}
                            className={`p-1 px-2 text-[10px] font-mono rounded border transition-colors ${
                              filters.selectedStrategies.includes(strat.strategyId)
                                ? 'bg-cyan-500 text-slate-950 font-bold border-cyan-400'
                                : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border-slate-800'
                            }`}
                          >
                            {filters.selectedStrategies.includes(strat.strategyId) ? 'Filtered' : 'Filter'}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Client-side Pagination Controls */}
          <PaginationControls
            currentPage={currentPage}
            totalRecords={filteredStrategies.length}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        </div>

        {/* Record Inspection & Detail Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              Blueprint Inspector
            </h3>
            {activeStrategy ? (
              <div className="mt-2">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {activeStrategy.strategyId}
                </span>
                <h4 className="text-sm font-bold text-slate-100 mt-0.5">
                  {activeStrategy.strategyName}
                </h4>
              </div>
            ) : (
              <p className="text-xs text-slate-500 mt-2">Select a strategy from the table to inspect.</p>
            )}
          </div>

          {activeStrategy && (
            <div className="space-y-4 flex-1">
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Associated ATT&CK Techniques ({activeStrategy.associatedTechniques.length})
                </span>
                <div className="mt-2 space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
                  {activeStrategy.associatedTechniques.map((tech) => (
                    <div
                      key={tech.id}
                      onClick={() => onSelectTechniqueId(tech.id)}
                      className="p-2 bg-slate-950/70 border border-slate-800 hover:border-indigo-500/60 rounded-lg flex items-center justify-between text-xs cursor-pointer group transition-colors"
                    >
                      <div className="min-w-0 pr-2">
                        <span className="font-mono font-bold text-indigo-400 group-hover:text-indigo-300">
                          {tech.id}
                        </span>
                        <p className="text-slate-300 truncate text-[11px]">{tech.name}</p>
                      </div>
                      <Eye className="w-3.5 h-3.5 text-slate-500 group-hover:text-indigo-400 shrink-0" />
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Tactical Alignment
                </span>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {activeStrategy.associatedTactics.map((tactic) => (
                    <span
                      key={tactic}
                      className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800"
                    >
                      {tactic}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
