# CyberOps SOC — Initial Super Admin Bootstrap Guide

This guide documents the secure, one-time initialization procedure for designating the primary Platform Administrator (`super_admin`).

---

## 1. Important Architecture & Security Invariants

1. **Separation of Concerns:**
   Applying database migrations and executing the initial bootstrap are **two separate, deliberate operations**. Migrations create the schema and governance triggers; the bootstrap script elevates the designated user and seals the platform bootstrap lock.
2. **Anti-Self-Approval & Anti-Privilege Escalation:**
   PostgreSQL triggers (`trg_protect_user_profile_mutation`) explicitly forbid client applications from creating or self-approving Super Admins. The `super_admin` role can **only** be granted through the one-time, atomic database RPC `public.bootstrap_initial_super_admin(TEXT)`.
3. **No Trigger Disabling or RLS Weakening:**
   The bootstrap procedure does **not** disable database triggers or weaken Row-Level Security. The trigger runs within the transaction, verifies authorization, generates a persistent platform governance audit log in `public.audit_logs`, and binds `last_audit_id`.
4. **Single-Use Concurrency Lock:**
   The procedure acquires an exclusive row lock on `public.platform_bootstrap_state WHERE id = 1 AND is_bootstrapped = false`. If the platform has already been initialized, repeat runs fail closed immediately without altering data.

---

## 2. Prerequisites for Initial Bootstrap

Before executing the bootstrap command, complete these prerequisites in order:

1. **Apply Migrations to Target Supabase Project:**
   Ensure both migrations have been applied sequentially via Supabase CLI or SQL Editor:
   - `20261015000000_initial_cyberops_soc_schema.sql`
   - `20261016000000_user_registration_and_governance.sql`
2. **Register the Intended Administrator Account:**
   The designated administrator must first create an account through the application's `/signup` page (or via `supabase.auth.signUp()`).
   - The trigger `handle_new_user()` will automatically create their `public.user_profiles` row with `account_status = 'pending'` and `role = NULL`.
   - Verify that the target email exists in `auth.users` and `public.user_profiles`.

---

## 3. Secure Credential Handling & Environment Setup

> **CRITICAL SECURITY WARNING:**  
> Never supply `SUPABASE_SERVICE_ROLE_KEY` directly inline on the command line (e.g., `SUPABASE_SERVICE_ROLE_KEY=... npm run ...`). Doing so exposes confidential administrative secrets in unencrypted shell history (`~/.bash_history`, `~/.zsh_history`) and renders them visible to other local processes via `/proc/<PID>/environ` or `ps`. Never commit service-role keys to source control or public files.

### Configuration Precedence & Conflict Prevention
The CLI evaluates configuration in the following strict, predictable precedence order:
1. **Mandatory CLI Argument:** `--confirm-project=<project-host-or-ref>` (evaluated before any network socket is opened).
2. **Current Process Environment:** Explicitly exported shell variables (`process.env`) take highest priority and are never overwritten by files on disk.
3. **Dedicated Ephemeral Bootstrap File:** `.env.bootstrap` (loaded first into unset variables, overriding baseline `.env` settings).
4. **Baseline File:** `.env` (loaded second into any remaining unset variables as baseline fallback defaults).

*Safety Conflict Invariant:*
- If `--confirm-project` (CLI) and `CONFIRM_SUPABASE_PROJECT` (environment/file) both exist but specify different targets, the CLI aborts immediately with a conflicting configuration error before initiating any network connections.
- The resolved `SUPABASE_URL` is parsed and its hostname is strictly validated against the project confirmation. If there is any mismatch, the CLI aborts without sending any requests.

Choose one of the two hardened methods below:

### Method A (Recommended): Ephemeral Restricted File (`.env.bootstrap`)
Create a temporary local environment file with strict OS read-only permissions (`0600`). The project's `.gitignore` automatically excludes all `.env*` files from version control:

```bash
# 1. Create restricted file
touch .env.bootstrap && chmod 600 .env.bootstrap

# 2. Populate configuration with template placeholders (replace with actual deployment values)
cat << 'EOF' > .env.bootstrap
SUPABASE_URL="https://<target-project-id>.supabase.co"
SUPABASE_SERVICE_ROLE_KEY="<confidential-service-role-secret>"
INITIAL_SUPER_ADMIN_EMAIL="<registered-admin-email>@domain.internal"
EOF

# 3. Execute the bootstrap CLI
npm run bootstrap:admin -- --confirm-project=<target-project-id>.supabase.co

# 4. Immediately destroy the ephemeral credential file
shred -u .env.bootstrap 2>/dev/null || rm -f .env.bootstrap
```

### Method B: In-Memory Interactive Terminal Prompt (`read -s`)
Avoid writing secrets to disk entirely by prompting silently via stdin without terminal echo:

```bash
# Set non-sensitive parameters
export SUPABASE_URL="https://<target-project-id>.supabase.co"
export INITIAL_SUPER_ADMIN_EMAIL="<registered-admin-email>@domain.internal"

# Enter confidential secret silently (no shell history entry generated)
read -s -p "Enter Supabase Service Role Key: " SUPABASE_SERVICE_ROLE_KEY && export SUPABASE_SERVICE_ROLE_KEY
echo ""

# Execute the CLI with explicit project confirmation
npm run bootstrap:admin -- --confirm-project=<target-project-id>.supabase.co

# Clear secret from session memory immediately
unset SUPABASE_SERVICE_ROLE_KEY
```

---

## 4. Execution Command (Manual & Explicit)

To protect against accidental execution against the wrong project or database, the CLI strictly requires the `--confirm-project` argument matching the target host or reference:

```bash
npm run bootstrap:admin -- --confirm-project=your-project-id.supabase.co
```
*(Or specify the project reference directly: `--confirm-project=your-project-id`)*

### Example Output on Success:
```
[BOOTSTRAP INITIATING] Target Host: your-project-id.supabase.co
[BOOTSTRAP INITIATING] Designated Super Admin: admin@yourdomain.com
[BOOTSTRAP] Calling database procedure "public.bootstrap_initial_super_admin"...

============================================================
[BOOTSTRAP SUCCESS] Platform Initialized Successfully!
  - Administrator Email : admin@yourdomain.com
  - Administrator ID    : 11111111-2222-3333-4444-555555555555
  - Governance Audit ID : aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  - Audit Action Type   : platform_bootstrap
  - Timestamp           : 2026-10-22T09:30:00.000Z
============================================================

The designated administrator may now sign in to the application and access /admin.
```

---

## 5. Verification After Bootstrap

1. **Sign in as Super Admin:**
   The administrator logs into CyberOps SOC via the application `/login` screen.
2. **Admin Dashboard Access:**
   Confirm that the user enters the Platform Administration Dashboard (`/admin`).
3. **Subsequent Operator Governance:**
   All subsequent team members (`soc_analyst`, `security_engineer`, `it_operations`) can now be reviewed, assigned roles, and approved directly in the UI by the approved Super Admin.

---

## 6. Recovery & Failure Handling

- **If the user email does not exist:**
  The RPC aborts with `Bootstrap Failure: No registered auth account exists for ...`. The transaction rolls back cleanly, and `is_bootstrapped` remains `false`. The administrator registers their account first and re-runs the CLI.
- **If already bootstrapped:**
  The RPC aborts with `Security Policy Invariant Violation: Platform has already been bootstrapped`. No changes are permitted.
- **If credentials or project mismatch:**
  The CLI aborts locally before issuing any RPC request, protecting against misconfigured targets.
- **Under no circumstances should database triggers be disabled or RLS bypassed.**
