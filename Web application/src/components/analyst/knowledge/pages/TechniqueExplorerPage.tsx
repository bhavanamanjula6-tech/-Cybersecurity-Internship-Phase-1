import React, { useState, useMemo, useEffect } from 'react';
import {
  ShieldCheck,
  Search,
  Eye,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters } from '../types';
import { extractTechniques } from '../filterUtils';
import { PaginationControls } from '../PaginationControls';

interface TechniqueExplorerPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords?: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onSelectTechniqueId: (techniqueId: string) => void;
}

export const TechniqueExplorerPage: React.FC<TechniqueExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const techniques = useMemo(() => {
    return extractTechniques(records);
  }, [records]);

  // Filtered techniques for table
  const filteredTechniques = useMemo(() => {
    if (!localSearch.trim()) return techniques;
    const q = localSearch.toLowerCase();
    return techniques.filter(
      (t) =>
        t.id.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tactics.some((tac) => tac.toLowerCase().includes(q)) ||
        t.platforms.some((p) => p.toLowerCase().includes(q))
    );
  }, [techniques, localSearch]);

  // Reset to page 1 whenever local search or global filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [localSearch, filters]);

  // Paginated slice
  const paginatedTechniques = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredTechniques.slice(start, start + pageSize);
  }, [filteredTechniques, currentPage, pageSize]);

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

  const totalTechniques = techniques.length;

  return (
    <div className="space-y-6">
      {/* 1. Page Heading */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-950/80 border border-blue-800 rounded-xl text-blue-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                MITRE ATT&CK Explorer
              </h2>
              <span className="text-xs font-mono text-cyan-300 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800">
                {totalTechniques} Techniques Cataloged
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Verified ATT&CK techniques, tactics, platforms, and detection mappings.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Searchable Data Table with Detail Inspection Trigger & Pagination */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              ATT&CK Technique Matrix Catalog
              <span className="text-xs font-mono font-normal text-indigo-300 bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800">
                {filteredTechniques.length}
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Click any technique row to inspect complete description, platforms, and detection rules.
            </p>
          </div>

          <div className="relative min-w-[240px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={localSearch}
              onChange={(e) => setLocalSearch(e.target.value)}
              placeholder="Search ID, name, tactic, or platform..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
            />
          </div>
        </div>

        <div className="overflow-x-auto flex-1">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                <th scope="col" className="p-3 font-semibold">ATT&CK ID</th>
                <th scope="col" className="p-3 font-semibold">Name</th>
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
                    No techniques match the search query.
                  </td>
                </tr>
              ) : (
                paginatedTechniques.map((tech) => (
                  <tr
                    key={tech.id}
                    onClick={() => onSelectTechniqueId(tech.id)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="p-3 font-mono font-bold text-indigo-400 group-hover:text-indigo-300">
                      {tech.id}
                    </td>
                    <td className="p-3 font-medium text-slate-200 max-w-[200px] truncate">
                      {tech.name}
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1 max-w-[200px]">
                        {tech.tactics.map((tactic) => (
                          <span
                            key={tactic}
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleTacticFilter(tactic);
                            }}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 hover:text-indigo-300 border border-slate-800"
                          >
                            {tactic}
                          </span>
                        ))}
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
                          onSelectTechniqueId(tech.id);
                        }}
                        className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-indigo-300 transition-colors"
                        aria-label={`Inspect ${tech.id}`}
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

        {/* Client-side Pagination Controls */}
        <PaginationControls
          currentPage={currentPage}
          totalRecords={filteredTechniques.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={setPageSize}
        />
      </div>
    </div>
  );
};
