/**
 * CyberOps SOC — Audit Log Export Service
 *
 * Implements hardened CSV and JSON export for authorized audit records.
 *
 * Security & Data Invariants:
 * 1. Role-based Access Enforcement: Only Super Admin (audit:export) can export audit logs.
 *    Unauthorized calls throw AccessDeniedError at the data-access boundary.
 * 2. Field Scoping & Least Privilege: Exports strictly authorized platform audit fields
 *    (id, timestamp, actionType, actorName, actorRole, targetResource, status, isSimulated, justification, systemNote).
 *    Never exposes credentials, access tokens, API keys, private alert details, or operational notes.
 * 3. Spreadsheet Formula Injection Mitigation (CSV Injection / CWE-1236):
 *    Prefixes any field whose trimmed value starts with '=', '+', '-', '@', '\t', or '\r'
 *    with a single apostrophe (') to neutralize formula execution in Excel/Sheets/Calc.
 * 4. RFC 4180 CSV Escaping: Properly escapes double quotes (" -> "") and wraps fields containing
 *    commas, quotes, or newlines in standard double-quote enclosures.
 * 5. UTF-8 BOM Handling: Includes \uFEFF for seamless Unicode/UTF-8 parsing in spreadsheet readers.
 * 6. Valid, Formatted JSON: Predictable property schema with explicit null safety and empty-result handling.
 */

import { AuditLogEntry } from '../types/audit';
import { UserProfile } from '../types/auth';
import { AuthorizationService } from './authorizationService';

export interface ExportedAuditRecord {
  id: string;
  timestamp: string;
  actionType: string;
  actorName: string;
  actorRole: string;
  targetResource: string;
  status: string;
  isSimulated: boolean;
  justification: string;
  systemNote: string;
}

export interface ExportDownloadResult {
  filename: string;
  mimeType: string;
  content: string;
  rowCount: number;
}

export class AuditExportService {
  /**
   * Authorized field names in standardized sequence.
   */
  public static readonly EXPORT_COLUMNS: Array<keyof ExportedAuditRecord> = [
    'id',
    'timestamp',
    'actionType',
    'actorName',
    'actorRole',
    'targetResource',
    'status',
    'isSimulated',
    'justification',
    'systemNote',
  ];

  /**
   * Sanitizes a cell string for safe CSV serialization and mitigates formula injection (CWE-1236).
   *
   * Formula characters neutralized: '=', '+', '-', '@', '\t', '\r'.
   * Delimiters requiring RFC 4180 quotation: comma (,), quote ("), newline (\n, \r).
   */
  public static sanitizeCellForCsv(raw: unknown): string {
    if (raw === null || raw === undefined) {
      return '';
    }

    let str = typeof raw === 'string' ? raw : String(raw);

    // Mitigate spreadsheet formula injection:
    // If the field begins with =, +, -, @, tab, or carriage return (ignoring leading whitespace),
    // prepend an apostrophe so spreadsheets treat the cell as raw literal text.
    if (/^\s*[=+\-@\t\r]/.test(str)) {
      str = `'${str}`;
    }

    // RFC 4180 check: if string contains double quote, comma, newline, or carriage return,
    // escape internal quotes by doubling them ("" -> """") and wrap cell in double quotes.
    if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
      const escaped = str.replace(/"/g, '""');
      return `"${escaped}"`;
    }

    return str;
  }

  /**
   * Maps an internal AuditLogEntry to a strictly scoped ExportedAuditRecord,
   * guaranteeing no sensitive credentials, tokens, or private operational alert payloads leak.
   */
  public static mapToExportRecord(entry: AuditLogEntry): ExportedAuditRecord {
    return {
      id: entry.id || '',
      timestamp: entry.timestamp || '',
      actionType: entry.actionType || '',
      actorName: entry.actorName || '',
      actorRole: entry.actorRole || '',
      targetResource: entry.targetResource || '',
      status: entry.status || '',
      isSimulated: Boolean(entry.isSimulated),
      justification: entry.justification || '',
      systemNote: entry.systemNote || '',
    };
  }

  /**
   * Generates a hardened, formula-injection-safe CSV string.
   * Asserts Super Admin authorization at the data boundary.
   */
  public static generateCsv(logs: AuditLogEntry[], user: UserProfile): string {
    AuthorizationService.assertCanExportAuditLogs(user);

    const headers = this.EXPORT_COLUMNS.map((col) => `"${col}"`).join(',');
    const rows = logs.map((log) => {
      const record = this.mapToExportRecord(log);
      return this.EXPORT_COLUMNS.map((col) => this.sanitizeCellForCsv(record[col])).join(',');
    });

    // Prepend UTF-8 BOM (\uFEFF) for Microsoft Excel compatibility
    return `\uFEFF${[headers, ...rows].join('\r\n')}\r\n`;
  }

  /**
   * Generates a schema-predictable, formatted JSON string.
   * Asserts Super Admin authorization at the data boundary.
   */
  public static generateJson(logs: AuditLogEntry[], user: UserProfile): string {
    AuthorizationService.assertCanExportAuditLogs(user);

    const sanitizedRecords: ExportedAuditRecord[] = logs.map((log) => this.mapToExportRecord(log));
    return JSON.stringify(sanitizedRecords, null, 2);
  }

  /**
   * Generates an export payload and triggers browser download if in a browser DOM context.
   */
  public static downloadExport(
    logs: AuditLogEntry[],
    user: UserProfile,
    format: 'csv' | 'json'
  ): ExportDownloadResult {
    AuthorizationService.assertCanExportAuditLogs(user);

    const timestampIso = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `cyberops_audit_export_${timestampIso}.${format}`;
    const mimeType = format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8';
    const content = format === 'csv' ? this.generateCsv(logs, user) : this.generateJson(logs, user);

    // Browser download trigger
    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
      try {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', filename);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } catch (err) {
        console.error('[CyberOps SOC] Browser download failed:', err);
      }
    }

    return {
      filename,
      mimeType,
      content,
      rowCount: logs.length,
    };
  }
}
