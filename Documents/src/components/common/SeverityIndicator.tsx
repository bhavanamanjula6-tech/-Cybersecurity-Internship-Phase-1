import React from 'react';
import { AlertSeverity } from '../../types/alert';
import { DESIGN_TOKENS } from '../../constants/designTokens';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, CheckCircle } from 'lucide-react';

interface SeverityIndicatorProps {
  severity: AlertSeverity;
  showLabel?: boolean;
  size?: 'sm' | 'md';
}

export const SeverityIndicator: React.FC<SeverityIndicatorProps> = ({
  severity,
  showLabel = true,
  size = 'md',
}) => {
  const token = DESIGN_TOKENS.severity[severity] || DESIGN_TOKENS.severity.informational;

  const getIcon = () => {
    switch (severity) {
      case 'critical':
        return <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />;
      case 'high':
        return <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />;
      case 'medium':
        return <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />;
      case 'low':
        return <CheckCircle className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />;
      case 'informational':
      default:
        return <Info className="w-3.5 h-3.5 flex-shrink-0" aria-hidden="true" />;
    }
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono font-bold tracking-wider uppercase ${
        size === 'sm' ? 'text-[11px]' : 'text-xs'
      } ${token.badgeClass}`}
      role="status"
      aria-label={`Severity: ${token.label}`}
    >
      {getIcon()}
      <span>{token.code}</span>
      {showLabel && <span className="opacity-90 normal-case font-sans font-medium">({token.label})</span>}
    </span>
  );
};
