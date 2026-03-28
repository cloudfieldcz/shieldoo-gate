-- Add user_email column to audit_log for tracking who performed admin actions.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS user_email TEXT DEFAULT '';
