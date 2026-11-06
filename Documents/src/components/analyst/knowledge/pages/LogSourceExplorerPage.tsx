import React, { useState, useMemo, useEffect } from 'react';
import {
  Server,
  Search,
  Eye,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters } from '../types';
import { extractLogSources } from '../filterUtils';
import { PaginationControls } from '../PaginationControls';

interface LogSourceExplorerPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords?: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onSelectTechniqueId: (techniqueId: string) => void;
}

export const LogSourceExplorerPage: React.FC<LogSourceExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const [selectedLogSourceName, setSelectedLogSourceName] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const logSources = useMemo(() => {
    return extractLogSources(records);
  }, [records]);

  // Filtered log sources for table
  const filteredLogSources = useMemo(() => {
    if (!localSearch.trim()) return logSources;
    const q = localSearch.toLowerCase();
    return logSources.filter(
      (ls) =>
        ls.logSourceName.toLowerCase().includes(q) ||
        ls.associatedTechniques.some(
          (t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
        ) ||
        ls.associatedAnalytics.some(
          (a) => a.id.toLowerCase().includes(q) || a.name.toLowerCase().includes(q)
        )
    );
  }, [logSources, localSearch]);

  // Reset to page 1 whenever local search or global filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [localSearch, filters]);

  // Paginated slice
  const paginatedLogSources = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredLogSources.slice(start, start + pageSize);
  }, [filteredLogSources, currentPage, pageSize]);

  const activeLogSource = useMemo(() => {
    if (selectedLogSourceName) {
      const found = filteredLogSources.find((ls) => ls.logSourceName === selectedLogSourceName);
      if (found) return found;
    }
    return filteredLogSources.length > 0 ? filteredLogSources[0] : null;
  }, [filteredLogSources, selectedLogSourceName]);

  const toggleLogSourceFilter = (name: string) => {
    onUpdateFilters((prev) => {
      const exists = prev.selectedLogSources.includes(name);
      return {
        ...prev,
        selectedLogSources: exists
          ? prev.selectedLogSources.filter((l) => l !== name)
          : [...prev.selectedLogSources, name],
      };
    });
  };

  const totalLogSources = logSources.length;

  return (
    <div className="space-y-6">
      {/* 1. Page Heading */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-amber-950/80 border border-amber-800 rounded-xl text-amber-400">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Log Source Analytics
              </h2>
              <span className="text-xs font-mono text-amber-300 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                {totalLogSources} Telemetry Feeds
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Event streams and telemetry feeds mapped to detection rules and ATT&CK techniques.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Searchable Data Table with Detail Panel & Pagination */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col">
          <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                Log Source Feed Inventory
                <span className="text-xs font-mono font-normal text-amber-300 bg-amber-950 px-2 py-0.5 rounded border border-amber-800">
                  {filteredLogSources.length}
                </span>
              </h3>
            </div>
            <div className="relative min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder="Search log source or technique..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th scope="col" className="p-3 font-semibold">Log Source Name</th>
                  <th scope="col" className="p-3 font-semibold">Analytics</th>
                  <th scope="col" className="p-3 font-semibold">Techniques</th>
                  <th scope="col" className="p-3 font-semibold text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogSources.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500">
                      No log sources match the current criteria.
                    </td>
                  </tr>
                ) : (
                  paginatedLogSources.map((ls) => {
                    const isSelected = activeLogSource?.logSourceName === ls.logSourceName;
                    return (
                      <tr
                        key={ls.logSourceName}
                        onClick={() => setSelectedLogSourceName(ls.logSourceName)}
                        className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${
                          isSelected ? 'bg-amber-950/30 border-l-2 border-amber-500' : ''
                        }`}
                      >
                        <td className="p-3 font-medium text-slate-200 max-w-[240px] truncate">
                          {ls.logSourceName}
                        </td>
                        <td className="p-3">
                          <span className="font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-300 font-semibold">
                            {ls.associatedAnalytics.length}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-indigo-300 font-semibold">
                            {ls.associatedTechniques.length}
                          </span>
                        </td>
                        <td className="p-3 text-right">
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggleLogSourceFilter(ls.logSourceName);
                            }}
                            className={`p-1 px-2 text-[10px] font-mono rounded border transition-colors ${
                              filters.selectedLogSources.includes(ls.logSourceName)
                                ? 'bg-amber-500 text-slate-950 font-bold border-amber-400'
                                : 'bg-slate-950 hover:bg-slate-800 text-slate-300 border-slate-800'
                            }`}
                          >
                            {filters.selectedLogSources.includes(ls.logSourceName) ? 'Filtered' : 'Filter'}
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
            totalRecords={filteredLogSources.length}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        </div>

        {/* Record Inspection & Detail Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              Feed Telemetry Inspector
            </h3>
            {activeLogSource ? (
              <h4 className="text-sm font-bold text-slate-100 mt-2">
                {activeLogSource.logSourceName}
              </h4>
            ) : (
              <p className="text-xs text-slate-500 mt-2">Select a log source from the table to inspect.</p>
            )}
          </div>

          {activeLogSource && (
            <div className="space-y-4 flex-1">
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Associated Techniques ({activeLogSource.associatedTechniques.length})
                </span>
                <div className="mt-2 space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
                  {activeLogSource.associatedTechniques.map((tech) => (
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
                  Associated Analytics ({activeLogSource.associatedAnalytics.length})
                </span>
                <div className="mt-2 space-y-1.5 max-h-[160px] overflow-y-auto pr-1">
                  {activeLogSource.associatedAnalytics.map((ana) => (
                    <div
                      key={ana.id}
                      className="p-2 bg-slate-950/70 border border-slate-800 rounded-lg text-xs"
                    >
                      <span className="font-mono font-bold text-emerald-400">{ana.id}</span>
                      <p className="text-slate-300 truncate text-[11px]">{ana.name}</p>
                    </div>
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
