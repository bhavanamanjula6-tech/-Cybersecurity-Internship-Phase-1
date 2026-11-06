import React, { useState, useMemo, useEffect } from 'react';
import {
  TrendingUp,
  Search,
  Eye,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters } from '../types';
import { extractAnalytics } from '../filterUtils';
import { PaginationControls } from '../PaginationControls';

interface AnalyticExplorerPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords?: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onSelectTechniqueId: (techniqueId: string) => void;
}

export const AnalyticExplorerPage: React.FC<AnalyticExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const [selectedAnalyticId, setSelectedAnalyticId] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const analytics = useMemo(() => {
    return extractAnalytics(records);
  }, [records]);

  // Filtered analytics for table
  const filteredAnalytics = useMemo(() => {
    if (!localSearch.trim()) return analytics;
    const q = localSearch.toLowerCase();
    return analytics.filter(
      (a) =>
        a.analyticId.toLowerCase().includes(q) ||
        a.analyticName.toLowerCase().includes(q) ||
        a.associatedTechniques.some(
          (t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
        ) ||
        a.associatedLogSources.some((ls) => ls.toLowerCase().includes(q))
    );
  }, [analytics, localSearch]);

  // Reset to page 1 whenever local search or global filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [localSearch, filters]);

  // Paginated slice
  const paginatedAnalytics = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredAnalytics.slice(start, start + pageSize);
  }, [filteredAnalytics, currentPage, pageSize]);

  const activeAnalytic = useMemo(() => {
    if (selectedAnalyticId) {
      const found = filteredAnalytics.find((a) => a.analyticId === selectedAnalyticId);
      if (found) return found;
    }
    return filteredAnalytics.length > 0 ? filteredAnalytics[0] : null;
  }, [filteredAnalytics, selectedAnalyticId]);

  const totalAnalytics = analytics.length;

  return (
    <div className="space-y-6">
      {/* 1. Page Heading */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-emerald-950/80 border border-emerald-800 rounded-xl text-emerald-400">
            <TrendingUp className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Analytic Analytics
              </h2>
              <span className="text-xs font-mono text-emerald-300 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                {totalAnalytics} Active Detection Rules
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              SIEM & EDR correlation rules mapped across telemetry sources and ATT&CK techniques.
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
                Analytic Rule Inventory
                <span className="text-xs font-mono font-normal text-emerald-300 bg-emerald-950 px-2 py-0.5 rounded border border-emerald-800">
                  {filteredAnalytics.length}
                </span>
              </h3>
            </div>
            <div className="relative min-w-[220px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={localSearch}
                onChange={(e) => setLocalSearch(e.target.value)}
                placeholder="Search rule ID, name, or technique..."
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <div className="overflow-x-auto flex-1">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                  <th scope="col" className="p-3 font-semibold">Analytic ID</th>
                  <th scope="col" className="p-3 font-semibold">Rule Name</th>
                  <th scope="col" className="p-3 font-semibold">Techniques</th>
                  <th scope="col" className="p-3 font-semibold">Log Sources</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredAnalytics.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="p-8 text-center text-slate-500">
                      No analytics match the current criteria.
                    </td>
                  </tr>
                ) : (
                  paginatedAnalytics.map((ana) => {
                    const isSelected = activeAnalytic?.analyticId === ana.analyticId;
                    return (
                      <tr
                        key={ana.analyticId}
                        onClick={() => setSelectedAnalyticId(ana.analyticId)}
                        className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${
                          isSelected ? 'bg-emerald-950/30 border-l-2 border-emerald-500' : ''
                        }`}
                      >
                        <td className="p-3 font-mono font-bold text-emerald-400 whitespace-nowrap">
                          {ana.analyticId}
                        </td>
                        <td className="p-3 font-medium text-slate-200 max-w-[220px] truncate">
                          {ana.analyticName}
                        </td>
                        <td className="p-3">
                          <span className="font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-indigo-300 font-semibold">
                            {ana.associatedTechniques.length}
                          </span>
                        </td>
                        <td className="p-3 text-slate-400 max-w-[180px] truncate">
                          {ana.associatedLogSources.join(', ') || 'N/A'}
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
            totalRecords={filteredAnalytics.length}
            pageSize={pageSize}
            onPageChange={setCurrentPage}
            onPageSizeChange={setPageSize}
          />
        </div>

        {/* Record Inspection & Detail Panel */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
              Analytic Rule Inspector
            </h3>
            {activeAnalytic ? (
              <div className="mt-2">
                <span className="text-xs font-mono font-bold text-emerald-400">
                  {activeAnalytic.analyticId}
                </span>
                <h4 className="text-sm font-bold text-slate-100 mt-0.5">
                  {activeAnalytic.analyticName}
                </h4>
              </div>
            ) : (
              <p className="text-xs text-slate-500 mt-2">Select an analytic from the table to inspect.</p>
            )}
          </div>

          {activeAnalytic && (
            <div className="space-y-4 flex-1">
              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Associated Techniques ({activeAnalytic.associatedTechniques.length})
                </span>
                <div className="mt-2 space-y-1.5 max-h-[260px] overflow-y-auto pr-1">
                  {activeAnalytic.associatedTechniques.map((tech) => (
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
                  Telemetry Feeds
                </span>
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {activeAnalytic.associatedLogSources.map((ls) => (
                    <span
                      key={ls}
                      className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-amber-300 border border-slate-800 font-mono"
                    >
                      {ls}
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
