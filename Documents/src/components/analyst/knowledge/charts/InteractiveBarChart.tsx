import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Check, Filter } from 'lucide-react';

export interface BarChartItem {
  id: string;
  label: string;
  subLabel?: string;
  count: number;
  percentage?: number;
  isSelected?: boolean;
}

interface InteractiveBarChartProps {
  title: string;
  subtitle?: string;
  badge?: string;
  icon: React.ReactNode;
  items: BarChartItem[];
  colorScheme?: 'indigo' | 'cyan' | 'emerald' | 'amber' | 'purple';
  onItemClick: (item: BarChartItem) => void;
  emptyMessage?: string;
  maxDisplay?: number;
}

export const InteractiveBarChart: React.FC<InteractiveBarChartProps> = ({
  title,
  subtitle,
  badge,
  icon,
  items,
  colorScheme = 'indigo',
  onItemClick,
  emptyMessage = 'No data available to display.',
  maxDisplay = 5,
}) => {
  const [showAll, setShowAll] = useState(false);
  const [hoveredItem, setHoveredItem] = useState<BarChartItem | null>(null);

  // Deterministic descending sort with secondary label tie-break
  const sortedItems = [...items].sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.label.localeCompare(b.label);
  });

  const displayedItems = showAll || sortedItems.length <= maxDisplay ? sortedItems : sortedItems.slice(0, maxDisplay);
  const maxCount = sortedItems.length > 0 ? Math.max(...sortedItems.map((i) => i.count), 1) : 1;

  const colorStyles = {
    indigo: {
      bar: 'bg-gradient-to-r from-indigo-500 to-cyan-400',
      activeBar: 'bg-indigo-400',
      activeBg: 'bg-indigo-950/70 border-indigo-500 shadow-indigo-950/50 shadow-md',
      badgeBg: 'bg-indigo-950 text-indigo-300 border-indigo-800',
      badgeActive: 'bg-indigo-500 text-slate-950 font-bold',
      accentText: 'text-indigo-400',
    },
    cyan: {
      bar: 'bg-gradient-to-r from-cyan-500 to-blue-400',
      activeBar: 'bg-cyan-400',
      activeBg: 'bg-cyan-950/70 border-cyan-500 shadow-cyan-950/50 shadow-md',
      badgeBg: 'bg-cyan-950 text-cyan-300 border-cyan-800',
      badgeActive: 'bg-cyan-500 text-slate-950 font-bold',
      accentText: 'text-cyan-400',
    },
    emerald: {
      bar: 'bg-gradient-to-r from-emerald-500 to-teal-400',
      activeBar: 'bg-emerald-400',
      activeBg: 'bg-emerald-950/70 border-emerald-500 shadow-emerald-950/50 shadow-md',
      badgeBg: 'bg-emerald-950 text-emerald-300 border-emerald-800',
      badgeActive: 'bg-emerald-500 text-slate-950 font-bold',
      accentText: 'text-emerald-400',
    },
    amber: {
      bar: 'bg-gradient-to-r from-amber-500 to-orange-400',
      activeBar: 'bg-amber-400',
      activeBg: 'bg-amber-950/70 border-amber-500 shadow-amber-950/50 shadow-md',
      badgeBg: 'bg-amber-950 text-amber-300 border-amber-800',
      badgeActive: 'bg-amber-500 text-slate-950 font-bold',
      accentText: 'text-amber-400',
    },
    purple: {
      bar: 'bg-gradient-to-r from-purple-500 to-indigo-400',
      activeBar: 'bg-purple-400',
      activeBg: 'bg-purple-950/70 border-purple-500 shadow-purple-950/50 shadow-md',
      badgeBg: 'bg-purple-950 text-purple-300 border-purple-800',
      badgeActive: 'bg-purple-500 text-slate-950 font-bold',
      accentText: 'text-purple-400',
    },
  }[colorScheme];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs flex flex-col justify-between relative">
      <div>
        {/* Header */}
        <div className="flex items-center justify-between mb-1">
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <span className={colorStyles.accentText}>{icon}</span>
            <span>{title}</span>
          </h3>
          <div className="flex items-center gap-2">
            {badge && (
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${colorStyles.badgeBg}`}>
                {badge}
              </span>
            )}
            {items.length > maxDisplay && (
              <button
                type="button"
                onClick={() => setShowAll(!showAll)}
                className="text-[11px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-0.5 cursor-pointer"
              >
                {showAll ? (
                  <>Top {maxDisplay} <ChevronUp className="w-3 h-3" /></>
                ) : (
                  <>All ({items.length}) <ChevronDown className="w-3 h-3" /></>
                )}
              </button>
            )}
          </div>
        </div>

        {subtitle && (
          <p className="text-xs text-slate-400 mb-3 leading-relaxed">
            {subtitle}
          </p>
        )}

        {/* Chart Bars */}
        {items.length === 0 ? (
          <div className="py-10 text-center text-slate-500 text-xs italic">
            {emptyMessage}
          </div>
        ) : (
          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
            {displayedItems.map((item) => {
              const isSelected = !!item.isSelected;
              const barPercent = Math.max((item.count / maxCount) * 100, 2);

              return (
                <div
                  key={item.id}
                  onClick={() => onItemClick(item)}
                  onMouseEnter={() => setHoveredItem(item)}
                  onMouseLeave={() => setHoveredItem(null)}
                  className={`w-full text-left p-2.5 rounded-lg border transition-all cursor-pointer group relative ${
                    isSelected
                      ? colorStyles.activeBg
                      : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                  }`}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && onItemClick(item)}
                  aria-pressed={isSelected}
                  aria-label={`${item.label}: ${item.count} items. Click to toggle filter.`}
                >
                  <div className="flex items-center justify-between text-xs mb-1.5 gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      {isSelected && (
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      )}
                      <span className="font-medium text-slate-200 truncate">
                        {item.label}
                      </span>
                      {item.subLabel && (
                        <span className="text-[10px] font-mono text-slate-400 truncate max-w-[120px]">
                          ({item.subLabel})
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-2 font-mono text-[11px] shrink-0">
                      {typeof item.percentage === 'number' && (
                        <span className="text-slate-400">{item.percentage}%</span>
                      )}
                      <span
                        className={`px-1.5 py-0.5 rounded font-bold min-w-[28px] text-center ${
                          isSelected ? colorStyles.badgeActive : colorStyles.badgeBg
                        }`}
                      >
                        {item.count}
                      </span>
                    </div>
                  </div>

                  {/* Progress Bar Container */}
                  <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800/80">
                    <div
                      style={{ width: `${barPercent}%` }}
                      className={`h-full rounded-full transition-all duration-300 ${
                        isSelected ? colorStyles.activeBar : colorStyles.bar
                      }`}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Floating Hover Tooltip */}
      {hoveredItem && (
        <div className="mt-3 p-2 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-slate-300 flex items-center justify-between shadow-lg">
          <div className="flex items-center gap-1.5 truncate">
            <Filter className="w-3 h-3 text-cyan-400 shrink-0" />
            <span className="text-slate-400">Selected:</span>
            <span className="font-semibold text-slate-100 truncate">{hoveredItem.label}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="font-bold text-cyan-300">{hoveredItem.count} items</span>
            <span className="text-[10px] text-slate-500">(Click to toggle filter)</span>
          </div>
        </div>
      )}
    </div>
  );
};
