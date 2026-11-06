import React, { useState, useMemo, useEffect } from 'react';
import {
  Database,
  Search,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { SocAnalystKnowledgeRecord } from '../../../../services/knowledgeService';
import { SocKnowledgeFilters } from '../types';
import { extractDataComponents } from '../filterUtils';
import { PaginationControls } from '../PaginationControls';

interface DataComponentExplorerPageProps {
  records: SocAnalystKnowledgeRecord[];
  allRecords?: SocAnalystKnowledgeRecord[];
  filters: SocKnowledgeFilters;
  onUpdateFilters: (updater: (prev: SocKnowledgeFilters) => SocKnowledgeFilters) => void;
  onSelectTechniqueId: (techniqueId: string) => void;
}

export const DataComponentExplorerPage: React.FC<DataComponentExplorerPageProps> = ({
  records,
  filters,
  onUpdateFilters,
  onSelectTechniqueId,
}) => {
  const [localSearch, setLocalSearch] = useState('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);

  const dataComponents = useMemo(() => {
    return extractDataComponents(records);
  }, [records]);

  const filteredComponents = useMemo(() => {
    if (!localSearch.trim()) return dataComponents;
    const q = localSearch.toLowerCase();
    return dataComponents.filter(
      (dc) =>
        dc.componentId.toLowerCase().includes(q) ||
        dc.componentName.toLowerCase().includes(q) ||
        dc.associatedTechniques.some(
          (t) => t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
        )
    );
  }, [dataComponents, localSearch]);

  // Reset to page 1 whenever local search or global filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [localSearch, filters]);

  // Paginated slice
  const paginatedComponents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredComponents.slice(start, start + pageSize);
  }, [filteredComponents, currentPage, pageSize]);

  return (
    <div className="space-y-6">
      {/* 1. Page Heading */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-purple-950/80 border border-purple-800 rounded-xl text-purple-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-100 font-heading">
                Data Component Analytics
              </h2>
              <span className="text-xs font-mono text-purple-300 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                Observable Telemetry Context
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Observable telemetry elements and entity contexts mapped to MITRE ATT&CK techniques.
            </p>
          </div>
        </div>
      </div>

      {/* Prominent Schema Limitation Notice (Truthful Data Boundary) */}
      <div className="p-4 bg-purple-950/40 border border-purple-800/80 rounded-xl text-xs space-y-2 text-purple-200">
        <div className="flex items-center gap-2 font-bold text-purple-300">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>Dataset Schema Boundary Notice: Data Component Column Unmapped</span>
        </div>
        <p className="leading-relaxed text-slate-300">
          The verified <code className="font-mono text-purple-300">public.soc_analyst_knowledge</code> schema contains 11 verified fields:
          <code className="font-mono text-slate-400"> row_id, techniques_id, techniques_name, techniques_description, techniques_tactics, techniques_platforms, detection_strategy_attack_id, detection_strategy_name, analytic_id, analytic_name, log_source_name</code>.
          Dedicated <code className="font-mono text-purple-300">data_components_id</code> and <code className="font-mono text-purple-300">data_components_name</code> columns are not present in this database view.
          To ensure strict data truthfulness without fabricated entities, observable telemetry coverage is displayed directly through verified <code className="font-mono text-amber-300">log_source_name</code> feeds in the Log Source Analytics explorer.
        </p>
      </div>

      {/* 2. Searchable Data Table with Pagination */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xs flex flex-col">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              Observable Telemetry Entity Inventory
              <span className="text-xs font-mono font-normal text-purple-300 bg-purple-950 px-2 py-0.5 rounded border border-purple-800">
                {filteredComponents.length > 0 ? `${filteredComponents.length} Components` : 'Schema Limitation Mode'}
              </span>
            </h3>
          </div>
          <div className="relative min-w-[220px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={localSearch}
              onChange={(e) => setLocalSearch(e.target.value)}
              placeholder="Search components or feeds..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-purple-500"
            />
          </div>
        </div>

        {filteredComponents.length > 0 ? (
          <>
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-950/60 border-b border-slate-800 text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    <th scope="col" className="p-3 font-semibold">Component ID</th>
                    <th scope="col" className="p-3 font-semibold">Component Name</th>
                    <th scope="col" className="p-3 font-semibold">Associated Techniques</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {paginatedComponents.map((dc) => (
                    <tr key={dc.componentId || dc.componentName} className="hover:bg-slate-800/50">
                      <td className="p-3 font-mono font-bold text-purple-400">{dc.componentId}</td>
                      <td className="p-3 font-medium text-slate-200">{dc.componentName}</td>
                      <td className="p-3">
                        <div className="flex flex-wrap gap-1">
                          {dc.associatedTechniques.map((t) => (
                            <span
                              key={t.id}
                              onClick={() => onSelectTechniqueId(t.id)}
                              className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-950 text-indigo-400 hover:text-indigo-300 border border-slate-800 cursor-pointer"
                            >
                              {t.id}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Client-side Pagination Controls */}
            <PaginationControls
              currentPage={currentPage}
              totalRecords={filteredComponents.length}
              pageSize={pageSize}
              onPageChange={setCurrentPage}
              onPageSizeChange={setPageSize}
            />
          </>
        ) : (
          <div className="p-8 text-center space-y-3">
            <Info className="w-8 h-8 text-purple-400/80 mx-auto" />
            <h4 className="text-sm font-semibold text-slate-200">
              Data Components Not Explicitly Populated in <code className="font-mono text-purple-300">public.soc_analyst_knowledge</code>
            </h4>
            <p className="text-xs text-slate-400 max-w-lg mx-auto">
              The application strictly enforces truthful data presentation. Because <code className="font-mono text-slate-300">data_components_id</code> is unverified in the current table schema, no fabricated records are displayed. Please refer to <strong>Log Source Analytics</strong> for verified telemetry event pipelines.
            </p>
          </div>
        )}
      </div>
    </div>
  );
};
