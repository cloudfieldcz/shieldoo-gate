ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT '';

UPDATE api_keys SET scopes = 'proxy:fetch' WHERE scopes = '';
