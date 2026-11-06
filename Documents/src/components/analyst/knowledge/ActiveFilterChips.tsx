import React from 'react';
import { Filter, X, RotateCcw } from 'lucide-react';
import { ActiveFilterChip, SocKnowledgeFilters } from './types';
import { buildActiveFilterChips } from './filterUtils';

interface ActiveFilterChipsProps {
  filters: SocKnowledgeFilters;
  onRemoveChip: (chip: ActiveFilterChip) => void;
  onClearAll: () => void;
  totalCatalogRecords: number;
  filteredRecordsCount: number;
}

export const ActiveFilterChips: React.FC<ActiveFilterChipsProps> = ({
  filters,
  onRemoveChip,
  onClearAll,
  totalCatalogRecords,
  filteredRecordsCount,
}) => {
  const chips = buildActiveFilterChips(filters);
  const isFiltered = chips.length > 0;

  return (
    <div
      className="bg-slate-950/80 border border-slate-800 rounded-lg p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
      role="region"
      aria-label="Active Knowledge Filters"
    >
      <div className="flex items-center gap-2 flex-wrap min-w-0">
        <div className="flex items-center gap-1.5 font-medium text-slate-400 shrink-0">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Active Filters:</span>
        </div>

        {!isFiltered ? (
          <span className="text-slate-500 italic text-[11px]">
            No filters applied (displaying full reference dataset)
          </span>
        ) : (
          <div className="flex items-center gap-1.5 flex-wrap">
            {chips.map((chip) => (
              <span
                key={chip.id}
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-mono bg-cyan-950/80 text-cyan-200 border border-cyan-800/80 shadow-xs"
              >
                <span>{chip.label}</span>
                <button
                  type="button"
                  onClick={() => onRemoveChip(chip)}
                  className="hover:text-rose-400 hover:bg-rose-950/50 rounded-full p-0.5 transition-colors focus:outline-none focus:ring-1 focus:ring-rose-400"
                  aria-label={`Remove filter ${chip.label}`}
                >
                  <X className="w-3 h-3" />
                </button>
              </span>
            ))}

            <button
              type="button"
              onClick={onClearAll}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium text-rose-300 hover:text-rose-200 bg-rose-950/40 hover:bg-rose-900/50 border border-rose-800/70 transition-colors ml-1 cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              Clear All ({chips.length})
            </button>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 shrink-0 text-[11px] font-mono text-slate-400">
        <span>Records:</span>
        <span
          className={`px-2 py-0.5 rounded font-bold ${
            isFiltered
              ? 'bg-amber-950/70 text-amber-300 border border-amber-800/80'
              : 'bg-slate-900 text-slate-300 border border-slate-800'
          }`}
        >
          {filteredRecordsCount} / {totalCatalogRecords}
        </span>
        {isFiltered && filteredRecordsCount === 0 && (
          <span className="text-rose-400 font-semibold">(0 matches)</span>
        )}
      </div>
    </div>
  );
};
