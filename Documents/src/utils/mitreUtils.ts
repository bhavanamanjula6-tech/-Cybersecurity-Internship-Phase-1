/**
 * MITRE ATT&CK Identifier Normalization & Display Utilities
 *
 * Enforces:
 * 1. Unified `attack_id` representation across all roles (SOC Analyst, Security Engineer, IT Operations, Alerts).
 * 2. Strict format validation for technique and sub-technique identifiers (e.g., T1059, T1059.001, T1195.001).
 * 3. Graceful handling of null, undefined, empty, or unclassified values with standard fallback.
 */

const MITRE_ATTACK_ID_REGEX = /^T\d{4}(\.\d{3})?$/i;

/**
 * Normalizes an ATT&CK technique or sub-technique identifier into standard uppercase format.
 * Examples:
 * - "t1059.001" -> "T1059.001"
 * - "T1003" -> "T1003"
 * - "  T1195.001  " -> "T1195.001"
 * - null / undefined / "" / "None" / "null" -> null
 */
export function normalizeAttackId(raw: string | null | undefined): string | null {
  if (!raw || typeof raw !== 'string') {
    return null;
  }

  const trimmed = raw.trim();
  if (
    !trimmed ||
    trimmed.toLowerCase() === 'none' ||
    trimmed.toLowerCase() === 'null' ||
    trimmed.toLowerCase() === 'n/a' ||
    trimmed.toLowerCase() === 'unknown' ||
    trimmed.toLowerCase() === 'not available'
  ) {
    return null;
  }

  if (MITRE_ATTACK_ID_REGEX.test(trimmed)) {
    return trimmed.toUpperCase();
  }

  return null;
}

/**
 * Validates whether an identifier conforms strictly to the standard ATT&CK technique or sub-technique format.
 */
export function isValidAttackId(id: string | null | undefined): boolean {
  if (!id || typeof id !== 'string') return false;
  return MITRE_ATTACK_ID_REGEX.test(id.trim());
}

/**
 * Formats an ATT&CK ID for UI display.
 * Returns the normalized ID or "Not available" when null/unmapped.
 */
export function formatAttackIdDisplay(attackId: string | null | undefined): string {
  const normalized = normalizeAttackId(attackId);
  return normalized || 'Not available';
}
