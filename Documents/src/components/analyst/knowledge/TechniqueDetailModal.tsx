import React, { useEffect } from 'react';
import {
  X,
  Shield,
  Layers,
  Terminal,
  Server,
  FileCode,
  Database,
  ExternalLink,
  Info,
} from 'lucide-react';
import { AggregatedTechnique } from './types';
import { Button } from '../../common/Button';

interface TechniqueDetailModalProps {
  technique: AggregatedTechnique | null;
  onClose: () => void;
  onFilterByTactic?: (tactic: string) => void;
  onFilterByPlatform?: (platform: string) => void;
  onFilterByLogSource?: (logSource: string) => void;
}

export const TechniqueDetailModal: React.FC<TechniqueDetailModalProps> = ({
  technique,
  onClose,
  onFilterByTactic,
  onFilterByPlatform,
  onFilterByLogSource,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    if (technique) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [technique, onClose]);

  if (!technique) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs animate-fade-in"
      role="dialog"
      aria-modal="true"
      aria-labelledby="technique-modal-title"
    >
      <div
        className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/90 flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800">
                {technique.id}
              </span>
              <h2 id="technique-modal-title" className="text-base font-bold text-slate-100">
                {technique.name}
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              MITRE ATT&CK reference mapping from <code className="text-slate-300 font-mono">public.soc_analyst_knowledge</code>
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 hover:bg-slate-800 p-1.5 rounded-lg transition-colors cursor-pointer"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Scrollable Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {/* Description */}
          <div className="space-y-1.5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-cyan-400" />
              Technique Description
            </h3>
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-slate-300 leading-relaxed font-sans text-xs">
              {technique.description ? (
                technique.description
              ) : (
                <span className="text-slate-500 italic">
                  No extended narrative description provided for {technique.id} in the reference dataset.
                </span>
              )}
            </div>
          </div>

          {/* Tactics & Platforms Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Tactics */}
            <div className="space-y-2 p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-indigo-400" />
                Associated Tactics ({technique.tactics.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {technique.tactics.length === 0 ? (
                  <span className="text-slate-500 italic text-[11px]">Unclassified</span>
                ) : (
                  technique.tactics.map((tactic) => (
                    <button
                      key={tactic}
                      type="button"
                      onClick={() => onFilterByTactic?.(tactic)}
                      className="px-2 py-0.5 rounded text-[11px] font-medium bg-indigo-950/80 text-indigo-200 border border-indigo-800 hover:border-indigo-600 transition-colors cursor-pointer"
                      title={`Filter knowledge base by tactic: ${tactic}`}
                    >
                      {tactic}
                    </button>
                  ))
                )}
              </div>
            </div>

            {/* Platforms */}
            <div className="space-y-2 p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg">
              <h4 className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-purple-400" />
                Target Platforms ({technique.platforms.length})
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {technique.platforms.length === 0 ? (
                  <span className="text-slate-500 italic text-[11px]">Unspecified Platform</span>
                ) : (
                  technique.platforms.map((platform) => (
                    <button
                      key={platform}
                      type="button"
                      onClick={() => onFilterByPlatform?.(platform)}
                      className="px-2 py-0.5 rounded text-[11px] font-medium bg-purple-950/80 text-purple-200 border border-purple-800 hover:border-purple-600 transition-colors cursor-pointer"
                      title={`Filter knowledge base by platform: ${platform}`}
                    >
                      {platform}
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Detection Strategies & Analytics */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 text-cyan-400" />
              Associated Detection Strategies & Analytics
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Detection Strategies */}
              <div className="p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg space-y-2">
                <span className="font-semibold text-slate-300 block">
                  Detection Strategies ({technique.detectionStrategyIds.length})
                </span>
                {technique.detectionStrategyIds.length === 0 ? (
                  <p className="text-slate-500 italic text-[11px]">
                    No explicit strategy ID mapped in dataset.
                  </p>
                ) : (
                  <ul className="space-y-1">
                    {technique.detectionStrategyIds.map((sid) => (
                      <li
                        key={sid}
                        className="font-mono text-[11px] text-cyan-300 bg-cyan-950/40 px-2 py-1 rounded border border-cyan-800/60"
                      >
                        {sid}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Analytics */}
              <div className="p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg space-y-2">
                <span className="font-semibold text-slate-300 block">
                  Analytics ({technique.analyticIds.length})
                </span>
                {technique.analyticIds.length === 0 ? (
                  <p className="text-slate-500 italic text-[11px]">
                    No explicit analytic ID mapped in dataset.
                  </p>
                ) : (
                  <ul className="space-y-1">
                    {technique.analyticIds.map((aid) => (
                      <li
                        key={aid}
                        className="font-mono text-[11px] text-emerald-300 bg-emerald-950/40 px-2 py-1 rounded border border-emerald-800/60"
                      >
                        {aid}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>

          {/* Log Sources & Data Components */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-emerald-400" />
              Telemetry Log Sources & Data Components
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Log Sources */}
              <div className="p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg space-y-2">
                <span className="font-semibold text-slate-300 block">
                  Telemetry Log Sources ({technique.logSources.length})
                </span>
                {technique.logSources.length === 0 ? (
                  <p className="text-slate-500 italic text-[11px]">
                    Unspecified / Custom Log Source
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {technique.logSources.map((ls) => (
                      <button
                        key={ls}
                        type="button"
                        onClick={() => onFilterByLogSource?.(ls)}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-950/70 text-emerald-300 border border-emerald-800/70 hover:border-emerald-600 transition-colors cursor-pointer"
                        title={`Filter knowledge base by log source: ${ls}`}
                      >
                        {ls}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Data Components */}
              <div className="p-3.5 bg-slate-950/50 border border-slate-800/80 rounded-lg space-y-2">
                <span className="font-semibold text-slate-300 block">
                  Data Components ({technique.dataComponentNames.length || technique.dataComponentIds.length})
                </span>
                {technique.dataComponentNames.length === 0 && technique.dataComponentIds.length === 0 ? (
                  <p className="text-slate-500 italic text-[11px]">
                    No explicit data components cataloged.
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {technique.dataComponentNames.map((dcn, i) => (
                      <span
                        key={`${dcn}-${i}`}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-900 text-slate-300 border border-slate-800"
                      >
                        {dcn}
                      </span>
                    ))}
                    {technique.dataComponentIds.map((dcid) => (
                      <span
                        key={dcid}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-950/70 text-blue-300 border border-blue-800/70"
                      >
                        {dcid}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/90 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            {technique.recordCount} reference dataset row(s) mapped
          </span>
          <Button variant="secondary" size="sm" onClick={onClose}>
            Close Inspector
          </Button>
        </div>
      </div>
    </div>
  );
};
