import React from 'react';
import { X, ShieldCheck, Server, Layers, ExternalLink, Filter } from 'lucide-react';
import { AggregatedItOpsMitigation } from '../types';

interface ItOpsMitigationDetailModalProps {
  mitigation: AggregatedItOpsMitigation | null;
  isOpen: boolean;
  onClose: () => void;
  onSelectTechnique?: (techniqueId: string) => void;
}

export const ItOpsMitigationDetailModal: React.FC<ItOpsMitigationDetailModalProps> = ({
  mitigation,
  isOpen,
  onClose,
  onSelectTechnique,
}) => {
  if (!isOpen || !mitigation) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby="mitigation-detail-title"
    >
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-900/90">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                {mitigation.id}
              </span>
              <h2 id="mitigation-detail-title" className="text-base font-bold text-slate-100 font-heading">
                {mitigation.name}
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              MITRE ATT&CK Preventative & Corrective Mitigation Reference
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {/* Mitigation Description */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Operational Implementation Guidance
            </h3>
            <div className="p-3.5 bg-slate-950/70 border border-slate-800 rounded-lg text-slate-300 leading-relaxed text-xs">
              {mitigation.description}
            </div>
          </div>

          {/* Associated Target Platforms */}
          {mitigation.associatedPlatforms.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" />
                Target Platforms ({mitigation.associatedPlatforms.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {mitigation.associatedPlatforms.map((p) => (
                  <span
                    key={p}
                    className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px] font-mono"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Associated Tactics */}
          {mitigation.associatedTactics.length > 0 && (
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-400" />
                Target Tactics ({mitigation.associatedTactics.length})
              </h3>
              <div className="flex flex-wrap gap-1.5">
                {mitigation.associatedTactics.map((t) => (
                  <span
                    key={t}
                    className="px-2 py-0.5 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800 text-[11px]"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Mitigated Techniques */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Mitigated Techniques ({mitigation.associatedTechniques.length})
            </h3>
            {mitigation.associatedTechniques.length === 0 ? (
              <p className="text-slate-500 italic">No specific technique links cataloged.</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-60 overflow-y-auto pr-1">
                {mitigation.associatedTechniques.map((t) => (
                  <div
                    key={t.id}
                    className="p-2.5 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between gap-2"
                  >
                    <div className="min-w-0">
                      <div className="font-mono text-xs font-bold text-cyan-400">{t.id}</div>
                      <div className="text-slate-300 text-[11px] truncate">{t.name}</div>
                    </div>
                    {onSelectTechnique && (
                      <button
                        type="button"
                        onClick={() => {
                          onSelectTechnique(t.id);
                          onClose();
                        }}
                        className="text-cyan-400 hover:text-cyan-300 shrink-0 p-1"
                        title="View Technique"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
          >
            Close Detail
          </button>
        </div>
      </div>
    </div>
  );
};
