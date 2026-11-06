import React, { useState, useMemo } from 'react';
import { Filter, PieChart, Check } from 'lucide-react';

export interface DonutChartItem {
  id: string;
  label: string;
  subLabel?: string;
  count: number;
  isSelected?: boolean;
  color?: string;
  isOther?: boolean;
}

interface InteractiveDonutChartProps {
  title: string;
  subtitle?: string;
  badge?: string;
  icon?: React.ReactNode;
  items: DonutChartItem[];
  topN?: number; // Defaults to 5
  onItemClick?: (item: DonutChartItem) => void;
  totalLabel?: string;
  emptyMessage?: string;
}

// Vibrant cyber dark-mode palette
const DEFAULT_PALETTE = [
  '#6366f1', // Indigo
  '#06b6d4', // Cyan
  '#10b981', // Emerald
  '#f59e0b', // Amber
  '#a855f7', // Purple
  '#64748b', // Slate for 'Other'
];

export const InteractiveDonutChart: React.FC<InteractiveDonutChartProps> = ({
  title,
  subtitle,
  badge,
  icon,
  items,
  topN = 5,
  onItemClick,
  totalLabel = 'Total Records',
  emptyMessage = 'No distribution data available.',
}) => {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  // Filter positive items and sort descending by count with deterministic label tie-breaking
  const processedData = useMemo(() => {
    const validItems = items
      .filter((i) => i.count > 0)
      .sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        return a.label.localeCompare(b.label);
      });

    const total = validItems.reduce((acc, curr) => acc + curr.count, 0);
    if (total === 0) {
      return { segments: [], total: 0, hasOther: false, otherCount: 0 };
    }

    if (validItems.length <= topN) {
      const segments = validItems.map((item, idx) => ({
        ...item,
        color: item.color || DEFAULT_PALETTE[idx % DEFAULT_PALETTE.length],
        percentage: ((item.count / total) * 100).toFixed(1),
        rawPercent: item.count / total,
        isOther: false,
      }));
      return { segments, total, hasOther: false, otherCount: 0 };
    }

    // Top N categories
    const topItems = validItems.slice(0, topN);
    const otherItems = validItems.slice(topN);
    const otherCount = otherItems.reduce((acc, curr) => acc + curr.count, 0);

    const segments = topItems.map((item, idx) => ({
      ...item,
      color: item.color || DEFAULT_PALETTE[idx % DEFAULT_PALETTE.length],
      percentage: ((item.count / total) * 100).toFixed(1),
      rawPercent: item.count / total,
      isOther: false,
    }));

    if (otherCount > 0) {
      segments.push({
        id: '__other__',
        label: `Other (${otherItems.length} categories)`,
        count: otherCount,
        color: DEFAULT_PALETTE[5],
        percentage: ((otherCount / total) * 100).toFixed(1),
        rawPercent: otherCount / total,
        isOther: true,
        isSelected: false,
      });
    }

    return { segments, total, hasOther: true, otherCount };
  }, [items, topN]);

  const { segments, total } = processedData;

  // Geometry for SVG Donut
  const cx = 100;
  const cy = 100;
  const outerR = 82;
  const innerR = 52;

  // Compute SVG paths for each slice
  const slicePaths = useMemo(() => {
    if (segments.length === 0 || total === 0) return [];

    // Special case: Single segment takes 100%
    if (segments.length === 1) {
      return [
        {
          segment: segments[0],
          d: `M ${cx} ${cy - outerR} A ${outerR} ${outerR} 0 1 1 ${cx} ${cy + outerR} A ${outerR} ${outerR} 0 1 1 ${cx} ${cy - outerR} M ${cx} ${cy - innerR} A ${innerR} ${innerR} 0 1 0 ${cx} ${cy + innerR} A ${innerR} ${innerR} 0 1 0 ${cx} ${cy - innerR} Z`,
          centerAngle: 0,
        },
      ];
    }

    let currentAngle = -Math.PI / 2; // Start from top 12 o'clock
    const gap = 0.02; // Small angle gap between slices

    return segments.map((seg) => {
      const sliceAngle = seg.rawPercent * 2 * Math.PI;
      const startAngle = currentAngle + (sliceAngle > gap ? gap / 2 : 0);
      const endAngle = currentAngle + sliceAngle - (sliceAngle > gap ? gap / 2 : 0);
      currentAngle += sliceAngle;

      const x1 = cx + outerR * Math.cos(startAngle);
      const y1 = cy + outerR * Math.sin(startAngle);
      const x2 = cx + outerR * Math.cos(endAngle);
      const y2 = cy + outerR * Math.sin(endAngle);

      const x3 = cx + innerR * Math.cos(endAngle);
      const y3 = cy + innerR * Math.sin(endAngle);
      const x4 = cx + innerR * Math.cos(startAngle);
      const y4 = cy + innerR * Math.sin(startAngle);

      const largeArc = sliceAngle > Math.PI ? 1 : 0;
      const d = `M ${x1} ${y1} A ${outerR} ${outerR} 0 ${largeArc} 1 ${x2} ${y2} L ${x3} ${y3} A ${innerR} ${innerR} 0 ${largeArc} 0 ${x4} ${y4} Z`;

      return {
        segment: seg,
        d,
        centerAngle: (startAngle + endAngle) / 2,
      };
    });
  }, [segments, total]);

  const activeHoveredSegment = useMemo(() => {
    if (!hoveredId) return null;
    return segments.find((s) => s.id === hoveredId) || null;
  }, [hoveredId, segments]);

  // Identify currently selected segment (persistent across pointer movements)
  const selectedSegment = useMemo(() => {
    return segments.find((s) => s.isSelected) || null;
  }, [segments]);

  return (
    <div
      onMouseLeave={() => setHoveredId(null)}
      className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xs transition-colors flex flex-col justify-between"
    >
      {/* Chart Header */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            {icon || <PieChart className="w-4 h-4 text-indigo-400" />}
            <h3 className="text-sm font-bold text-slate-100 font-heading tracking-tight">
              {title}
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {badge && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-slate-950 text-slate-400 border border-slate-800">
                {badge}
              </span>
            )}
            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
              Top 5 + Other
            </span>
          </div>
        </div>

        {subtitle && (
          <p className="text-xs text-slate-400 mb-4 leading-relaxed">
            {subtitle}
          </p>
        )}
      </div>

      {segments.length === 0 ? (
        <div className="py-12 text-center text-slate-500 text-xs italic">
          {emptyMessage}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-12 gap-5 items-center">
          {/* Donut SVG Visual */}
          <div className="md:col-span-5 flex justify-center relative">
            <div
              className="relative w-48 h-48"
              onMouseLeave={() => setHoveredId(null)}
            >
              <svg
                viewBox="0 0 200 200"
                className="w-full h-full transform transition-transform"
                role="img"
                aria-label={`${title} Donut Chart`}
              >
                {slicePaths.map(({ segment, d }) => {
                  const isHovered = hoveredId === segment.id;
                  const isSelected = !!segment.isSelected;

                  return (
                    <path
                      key={segment.id}
                      d={d}
                      fill={segment.color}
                      opacity={hoveredId && !isHovered ? 0.45 : isSelected ? 1 : 0.9}
                      stroke={isSelected ? '#38bdf8' : isHovered ? '#ffffff' : '#0f172a'}
                      strokeWidth={isSelected ? 3 : isHovered ? 2 : 1}
                      className="cursor-pointer transition-all duration-200"
                      onMouseEnter={() => setHoveredId(segment.id)}
                      onClick={() => !segment.isOther && onItemClick && onItemClick(segment)}
                    />
                  );
                })}
              </svg>

              {/* Center Donut Hub Stats: Reflects active selection persistently; hover does not overwrite */}
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center px-4">
                {selectedSegment ? (
                  <>
                    <span className="text-lg font-bold font-mono text-slate-100">
                      {selectedSegment.percentage}%
                    </span>
                    <span className="text-[10px] font-mono text-cyan-300 font-semibold truncate max-w-[100px]" title={selectedSegment.label}>
                      {selectedSegment.count} items
                    </span>
                    <span className="text-[9px] font-mono text-slate-400 truncate max-w-[90px]">
                      {selectedSegment.label}
                    </span>
                  </>
                ) : (
                  <>
                    <span className="text-lg font-bold font-mono text-slate-100">
                      {total}
                    </span>
                    <span className="text-[10px] font-sans text-slate-400 font-medium leading-tight">
                      {totalLabel}
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>

          {/* Interactive Legend with Top 5 + Other Breakdown */}
          <div
            className="md:col-span-7 space-y-2"
            onMouseLeave={() => setHoveredId(null)}
          >
            {segments.map((seg) => {
              const isHovered = hoveredId === seg.id;
              const isSelected = !!seg.isSelected;

              return (
                <div
                  key={seg.id}
                  onClick={() => !seg.isOther && onItemClick && onItemClick(seg)}
                  onMouseEnter={() => setHoveredId(seg.id)}
                  className={`flex items-center justify-between p-2 rounded-lg border text-xs transition-all ${
                    seg.isOther
                      ? 'bg-slate-950/40 border-slate-800 text-slate-400 cursor-default'
                      : isSelected
                      ? 'bg-indigo-950/70 border-indigo-500 text-slate-100 cursor-pointer shadow-sm'
                      : isHovered
                      ? 'bg-slate-800/60 border-slate-700 text-slate-100 cursor-pointer'
                      : 'bg-slate-950/50 border-slate-800/70 text-slate-300 hover:border-slate-700 cursor-pointer'
                  }`}
                  role={seg.isOther ? 'presentation' : 'button'}
                  tabIndex={seg.isOther ? -1 : 0}
                  onKeyDown={(e) => {
                    if (!seg.isOther && (e.key === 'Enter' || e.key === ' ') && onItemClick) {
                      onItemClick(seg);
                    }
                  }}
                  aria-pressed={isSelected}
                >
                  <div className="flex items-center gap-2 min-w-0 pr-2">
                    <span
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ backgroundColor: seg.color }}
                    />
                    {isSelected && (
                      <Check className="w-3 h-3 text-cyan-400 shrink-0" />
                    )}
                    <span className="font-medium truncate text-[11px]">
                      {seg.label}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 font-mono text-[11px] shrink-0">
                    <span className="text-slate-400 font-semibold">{seg.percentage}%</span>
                    <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 font-bold text-slate-200 min-w-[24px] text-center">
                      {seg.count}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Permanent Fixed-Height Status & Hover Details Bar (Prevents Layout Shift and Blinking) */}
      <div className="mt-3 h-9 px-3 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-slate-300 flex items-center justify-between shadow-xs transition-colors">
        {activeHoveredSegment ? (
          <>
            <div className="flex items-center gap-1.5 truncate">
              <Filter className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-slate-400">Category:</span>
              <span className="font-semibold text-slate-100 truncate">
                {activeHoveredSegment.label}
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="font-bold text-cyan-300">
                {activeHoveredSegment.count} ({activeHoveredSegment.percentage}%)
              </span>
              {!activeHoveredSegment.isOther && (
                <span className="text-[10px] text-slate-500">(Click to toggle filter)</span>
              )}
            </div>
          </>
        ) : selectedSegment ? (
          <>
            <div className="flex items-center gap-1.5 truncate">
              <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="text-slate-400">Active Filter:</span>
              <span className="font-semibold text-cyan-300 truncate">
                {selectedSegment.label}
              </span>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <span className="font-bold text-slate-200">
                {selectedSegment.count} ({selectedSegment.percentage}%)
              </span>
              <span className="text-[10px] text-slate-500">(Click again to clear)</span>
            </div>
          </>
        ) : (
          <div className="flex items-center justify-between w-full text-slate-500">
            <span className="flex items-center gap-1.5 truncate text-[11px]">
              <Filter className="w-3.5 h-3.5 text-slate-600 shrink-0" />
              Hover over slice or category for distribution details
            </span>
            <span className="text-[10px] text-slate-600 shrink-0">Click to filter</span>
          </div>
        )}
      </div>
    </div>
  );
};
