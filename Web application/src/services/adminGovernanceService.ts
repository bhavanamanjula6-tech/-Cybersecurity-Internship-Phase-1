/**
 * CyberOps SOC — Platform Admin User Governance Service
 *
 * Provides authoritative policy enforcement for Super Admin account lifecycle operations:
 * 1. Role reassignment among authorized operational roles.
 * 2. Account suspension with mandatory justification.
 * 3. Account reactivation with confirmation.
 * 4. Retention-safe account deactivation (disabling profile without physical deletion).
 *
 * SECURITY INVARIANTS:
 * - Anti-Self-Mutation: Administrators cannot modify their own role, suspend themselves, or deactivate their own account.
 * - Last Super Admin Protection: The last active Super Admin cannot be demoted, suspended, or deactivated.
 * - Anti-Privilege-Escalation: Super Admin role can never be granted via client UI controls.
 * - Retention Safety: Account records are never physically deleted (no SQL DELETE).
 * - Mandatory Justification: Suspension and deactivation require verifiable operational justification for the audit trail.
 */

import { UserProfile, UserRole, AccountStatus, ROLE_METADATA } from '../types/auth';

export interface GovernanceValidationResult {
  valid: boolean;
  error?: string;
}

export const OPERATIONAL_ROLES: UserRole[] = [
  'soc_analyst',
  'security_engineer',
  'it_operations',
];

/**
 * Checks whether the target user is the last active, approved Super Admin.
 */
export function isLastSuperAdmin(targetUser: UserProfile, allProfiles: UserProfile[]): boolean {
  if (targetUser.role !== 'super_admin' || targetUser.accountStatus !== 'approved') {
    return false;
  }

  const activeSuperAdmins = allProfiles.filter(
    (p) => p.role === 'super_admin' && p.accountStatus === 'approved' && p.id !== targetUser.id
  );

  return activeSuperAdmins.length === 0;
}

/**
 * Validates whether an administrator can change a target user's role.
 */
export function validateRoleChange(
  currentUser: UserProfile,
  targetUser: UserProfile,
  newRole: UserRole,
  allProfiles: UserProfile[]
): GovernanceValidationResult {
  // 1. Administrator authority check
  if (currentUser.role !== 'super_admin' || currentUser.accountStatus !== 'approved') {
    return {
      valid: false,
      error: 'Security Policy Violation: Only approved Platform Administrators may reassign user roles.',
    };
  }

  // 2. Anti-self-mutation guard
  if (currentUser.id === targetUser.id) {
    return {
      valid: false,
      error: 'Security Policy Violation: Administrators cannot modify their own role.',
    };
  }

  // 3. Anti-privilege-escalation: Super Admin cannot be assigned via client governance
  if (newRole === 'super_admin') {
    return {
      valid: false,
      error: 'Security Policy Violation: Super Admin role cannot be assigned through ordinary user governance.',
    };
  }

  // 4. Operational roles constraint
  if (!OPERATIONAL_ROLES.includes(newRole)) {
    return {
      valid: false,
      error: `Security Policy Violation: "${newRole}" is not a valid operational role.`,
    };
  }

  // 5. Protect last Super Admin from role demotion
  if (isLastSuperAdmin(targetUser, allProfiles)) {
    return {
      valid: false,
      error: 'Security Policy Violation: Cannot demote the last active Super Admin.',
    };
  }

  // 6. No-op check
  if (targetUser.role === newRole) {
    return {
      valid: false,
      error: `User is already assigned to the "${ROLE_METADATA[newRole].label}" role.`,
    };
  }

  return { valid: true };
}

/**
 * Validates whether an administrator can suspend a target user's account.
 */
export function validateSuspension(
  currentUser: UserProfile,
  targetUser: UserProfile,
  justification: string,
  allProfiles: UserProfile[]
): GovernanceValidationResult {
  // 1. Administrator authority check
  if (currentUser.role !== 'super_admin' || currentUser.accountStatus !== 'approved') {
    return {
      valid: false,
      error: 'Security Policy Violation: Only approved Platform Administrators may suspend accounts.',
    };
  }

  // 2. Anti-self-mutation guard
  if (currentUser.id === targetUser.id) {
    return {
      valid: false,
      error: 'Security Policy Violation: Administrators cannot suspend their own account.',
    };
  }

  // 3. Mandatory justification validation
  const trimmed = justification.trim();
  if (!trimmed || trimmed.length < 5) {
    return {
      valid: false,
      error: 'Mandatory Justification Required: A detailed reason (at least 5 characters) is required to suspend an account.',
    };
  }

  // 4. Protect last Super Admin from suspension
  if (isLastSuperAdmin(targetUser, allProfiles)) {
    return {
      valid: false,
      error: 'Security Policy Violation: Cannot suspend the last active Super Admin.',
    };
  }

  // 5. Account state check
  if (targetUser.accountStatus === 'disabled') {
    return {
      valid: false,
      error: 'User account is already suspended / disabled.',
    };
  }

  return { valid: true };
}

/**
 * Validates whether an administrator can reactivate a disabled/suspended account.
 */
export function validateReactivation(
  currentUser: UserProfile,
  targetUser: UserProfile
): GovernanceValidationResult {
  // 1. Administrator authority check
  if (currentUser.role !== 'super_admin' || currentUser.accountStatus !== 'approved') {
    return {
      valid: false,
      error: 'Security Policy Violation: Only approved Platform Administrators may reactivate accounts.',
    };
  }

  // 2. Anti-self-mutation guard (defensive, though admin's own account must be approved to be here)
  if (currentUser.id === targetUser.id) {
    return {
      valid: false,
      error: 'Security Policy Violation: Administrators cannot reactivate their own account.',
    };
  }

  // 3. State check
  if (targetUser.accountStatus === 'approved') {
    return {
      valid: false,
      error: 'User account is already active and approved.',
    };
  }

  return { valid: true };
}

/**
 * Validates whether an administrator can deactivate a target user's account with retention safety.
 */
export function validateDeactivation(
  currentUser: UserProfile,
  targetUser: UserProfile,
  justification: string,
  allProfiles: UserProfile[]
): GovernanceValidationResult {
  // 1. Administrator authority check
  if (currentUser.role !== 'super_admin' || currentUser.accountStatus !== 'approved') {
    return {
      valid: false,
      error: 'Security Policy Violation: Only approved Platform Administrators may deactivate accounts.',
    };
  }

  // 2. Anti-self-mutation guard
  if (currentUser.id === targetUser.id) {
    return {
      valid: false,
      error: 'Security Policy Violation: Administrators cannot deactivate their own account.',
    };
  }

  // 3. Mandatory justification validation
  const trimmed = justification.trim();
  if (!trimmed || trimmed.length < 5) {
    return {
      valid: false,
      error: 'Mandatory Justification Required: A detailed reason (at least 5 characters) is required to deactivate an account.',
    };
  }

  // 4. Protect last Super Admin from deactivation
  if (isLastSuperAdmin(targetUser, allProfiles)) {
    return {
      valid: false,
      error: 'Security Policy Violation: Cannot deactivate the last active Super Admin.',
    };
  }

  return { valid: true };
}
