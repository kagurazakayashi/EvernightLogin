-- login SQLite 设计基线 0.1；2026-11-14
-- 仅适用于全新数据库。不得对已有业务库重复执行；不含密码或密钥。
-- 本结构是待实施审查的起点，不等于已经完成第 06/07 步。
PRAGMA foreign_keys = ON;
BEGIN IMMEDIATE;

CREATE TABLE schema_history (
version TEXT PRIMARY KEY NOT NULL, description TEXT NOT NULL, applied_at_ms INTEGER NOT NULL, source_sha256 TEXT NOT NULL
);

CREATE TABLE users (
id TEXT PRIMARY KEY NOT NULL, username TEXT NOT NULL, username_normalized TEXT NOT NULL UNIQUE,
 nickname TEXT NOT NULL DEFAULT '', biography TEXT NOT NULL DEFAULT '', avatar_ref TEXT,
 language TEXT NOT NULL DEFAULT 'zh-CN', timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','disabled','pending_delete')),
 is_root INTEGER NOT NULL DEFAULT 0 CHECK(is_root IN (0,1)), security_version INTEGER NOT NULL DEFAULT 1,
 row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE UNIQUE INDEX ux_single_root ON users(is_root) WHERE is_root=1;

CREATE TABLE user_contacts (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('email','phone')), value TEXT NOT NULL, normalized_value TEXT NOT NULL,
 verified_at_ms INTEGER, is_primary INTEGER NOT NULL DEFAULT 0 CHECK(is_primary IN(0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL,
 UNIQUE(user_id,kind,normalized_value)
);

CREATE UNIQUE INDEX ux_primary_contact ON user_contacts(user_id,kind) WHERE is_primary=1;
CREATE UNIQUE INDEX ux_verified_email ON user_contacts(normalized_value) WHERE kind='email' AND verified_at_ms IS NOT NULL;

CREATE TABLE applications (
id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', icon_ref TEXT, homepage TEXT,
 owner_user_id TEXT REFERENCES users(id) ON DELETE SET NULL, contact_info TEXT,
 status TEXT NOT NULL DEFAULT 'disabled' CHECK(status IN('active','disabled')),
 client_type TEXT NOT NULL CHECK(client_type IN('confidential','public')), row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE scopes (
id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL CHECK(kind IN('system','application')),
 app_id TEXT UNIQUE REFERENCES applications(id) ON DELETE CASCADE,
 CHECK((kind='system' AND app_id IS NULL AND id='system') OR (kind='application' AND app_id IS NOT NULL AND id<>'system'))
);

CREATE TABLE app_memberships (
app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL CHECK(status IN('active','disabled')),
 profile_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(profile_json)), row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(app_id,user_id)
);

CREATE TABLE roles (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
 role_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, limits_text TEXT NOT NULL,
 is_builtin INTEGER NOT NULL DEFAULT 0 CHECK(is_builtin IN(0,1)), enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)),
 created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,role_key), UNIQUE(id,scope_id)
);

CREATE TABLE permissions (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
 permission_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL, limits_text TEXT NOT NULL,
 is_builtin INTEGER NOT NULL DEFAULT 0 CHECK(is_builtin IN(0,1)), root_only INTEGER NOT NULL DEFAULT 0 CHECK(root_only IN(0,1)),
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN(0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,permission_key), UNIQUE(id,scope_id)
);

CREATE TABLE role_permissions (
role_id TEXT NOT NULL, permission_id TEXT NOT NULL, scope_id TEXT NOT NULL,
 PRIMARY KEY(role_id,permission_id), FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE,
 FOREIGN KEY(permission_id,scope_id) REFERENCES permissions(id,scope_id) ON DELETE CASCADE
);

CREATE TABLE user_groups (
id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
 group_key TEXT NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(scope_id,group_key), UNIQUE(id,scope_id)
);

CREATE TABLE group_members (
group_id TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at_ms INTEGER NOT NULL, PRIMARY KEY(group_id,user_id)
);

CREATE TABLE user_roles (
user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id TEXT NOT NULL, scope_id TEXT NOT NULL,
 data_scope_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(data_scope_json)), assigned_by TEXT NOT NULL, created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(user_id,role_id), FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE
);

CREATE TABLE group_roles (
group_id TEXT NOT NULL, role_id TEXT NOT NULL, scope_id TEXT NOT NULL,
 data_scope_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(data_scope_json)), created_at_ms INTEGER NOT NULL,
 PRIMARY KEY(group_id,role_id), FOREIGN KEY(group_id,scope_id) REFERENCES user_groups(id,scope_id) ON DELETE CASCADE,
 FOREIGN KEY(role_id,scope_id) REFERENCES roles(id,scope_id) ON DELETE CASCADE
);

CREATE TABLE delegations (
id TEXT PRIMARY KEY NOT NULL, grantor_user_id TEXT NOT NULL REFERENCES users(id), grantee_user_id TEXT NOT NULL REFERENCES users(id),
 scope_id TEXT NOT NULL REFERENCES scopes(id), allowed_json TEXT NOT NULL CHECK(json_valid(allowed_json)), expires_at_ms INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE password_credentials (
user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0 CHECK(must_change IN(0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE password_history (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 password_hash TEXT NOT NULL, created_at_ms INTEGER NOT NULL
);

CREATE TABLE webauthn_credentials (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 credential_id BLOB NOT NULL UNIQUE, public_key BLOB NOT NULL, rp_id TEXT NOT NULL, name TEXT NOT NULL,
 sign_count INTEGER NOT NULL DEFAULT 0, transports_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(transports_json)),
 backup_eligible INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN(0,1)), backed_up INTEGER NOT NULL DEFAULT 0 CHECK(backed_up IN(0,1)),
 usage TEXT NOT NULL CHECK(usage IN('login','mfa','both')), last_used_at_ms INTEGER, revoked_at_ms INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE mfa_methods (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 method_type TEXT NOT NULL CHECK(method_type IN('email','totp','extension')), name TEXT NOT NULL,
 encrypted_secret BLOB, key_id TEXT, config_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(config_json)),
 state TEXT NOT NULL CHECK(state IN('pending','active','revoked')), last_accepted_counter INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 generation TEXT NOT NULL, code_hash TEXT NOT NULL UNIQUE, created_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER, revoked_at_ms INTEGER
);

CREATE TABLE one_time_credentials (
id TEXT PRIMARY KEY NOT NULL, purpose TEXT NOT NULL, subject_id TEXT,
 app_id TEXT REFERENCES applications(id) ON DELETE CASCADE, verifier_hash TEXT NOT NULL UNIQUE,
 key_id TEXT, context_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(context_json)), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts>=0),
 max_attempts INTEGER NOT NULL CHECK(max_attempts>0), created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
 consumed_at_ms INTEGER, revoked_at_ms INTEGER, CHECK(expires_at_ms>created_at_ms)
);

CREATE TABLE sessions (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 app_id TEXT REFERENCES applications(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE,
 kind TEXT NOT NULL CHECK(kind IN('normal','recovery','bootstrap')), auth_methods_json TEXT NOT NULL CHECK(json_valid(auth_methods_json)),
 authenticated_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, last_seen_at_ms INTEGER NOT NULL,
 idle_expires_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER,
 security_version INTEGER NOT NULL, client_info_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(client_info_json))
);

CREATE TABLE registration_requests (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN('self','invite')), state TEXT NOT NULL CHECK(state IN('pending','approved','rejected','expired','cancelled')),
 invitation_credential_id TEXT REFERENCES one_time_credentials(id) ON DELETE SET NULL, reviewer_id TEXT, reason TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE application_settings (
app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 setting_key TEXT NOT NULL, value_json TEXT NOT NULL CHECK(json_valid(value_json)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, PRIMARY KEY(app_id,setting_key)
);

CREATE TABLE application_credentials (
id TEXT PRIMARY KEY NOT NULL, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN('secret_hash','public_jwk','certificate')), verifier TEXT NOT NULL,
 expires_at_ms INTEGER, revoked_at_ms INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE oauth_grants (
id TEXT PRIMARY KEY NOT NULL, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 user_id TEXT REFERENCES users(id) ON DELETE CASCADE, subject_type TEXT NOT NULL CHECK(subject_type IN('user','service')),
 scopes_json TEXT NOT NULL CHECK(json_valid(scopes_json)), audiences_json TEXT NOT NULL CHECK(json_valid(audiences_json)),
 revoked_at_ms INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, CHECK((subject_type='user' AND user_id IS NOT NULL) OR (subject_type='service' AND user_id IS NULL))
);

CREATE TABLE authorization_codes (
id TEXT PRIMARY KEY NOT NULL, grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL UNIQUE, redirect_uri TEXT NOT NULL, pkce_challenge TEXT NOT NULL,
 nonce TEXT, auth_context_json TEXT NOT NULL CHECK(json_valid(auth_context_json)),
 created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER
);

CREATE TABLE refresh_tokens (
id TEXT PRIMARY KEY NOT NULL, grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
 family_id TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, parent_id TEXT REFERENCES refresh_tokens(id),
 created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER, revoked_at_ms INTEGER
);

CREATE TABLE token_revocations (
token_id TEXT PRIMARY KEY NOT NULL, grant_id TEXT REFERENCES oauth_grants(id) ON DELETE CASCADE,
 reason TEXT NOT NULL, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL
);

CREATE TABLE signing_keys (
id TEXT PRIMARY KEY NOT NULL, algorithm TEXT NOT NULL, public_jwk_json TEXT NOT NULL CHECK(json_valid(public_jwk_json)),
 private_key_ref TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','active','retiring','retired')), not_after_ms INTEGER, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE device_requests (
id TEXT PRIMARY KEY NOT NULL, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 flow TEXT NOT NULL CHECK(flow IN('device','qr')), device_secret_hash TEXT NOT NULL UNIQUE, user_code_hash TEXT UNIQUE,
 initiator_binding_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','approved','denied','expired','cancelled','consumed')),
 approved_by TEXT REFERENCES users(id) ON DELETE SET NULL, grant_id TEXT REFERENCES oauth_grants(id) ON DELETE SET NULL,
 requested_json TEXT NOT NULL CHECK(json_valid(requested_json)), poll_interval_seconds INTEGER NOT NULL CHECK(poll_interval_seconds>0),
 last_polled_at_ms INTEGER, expires_at_ms INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE sensitive_operations (
operation_key TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id),
 name TEXT NOT NULL, description TEXT NOT NULL, default_policy_json TEXT NOT NULL CHECK(json_valid(default_policy_json)),
 override_policy_json TEXT CHECK(override_policy_json IS NULL OR json_valid(override_policy_json)), changed_by TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE support_cases (
id TEXT PRIMARY KEY NOT NULL, target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 opened_by TEXT NOT NULL, assigned_to TEXT, state TEXT NOT NULL CHECK(state IN('open','verifying','approval_pending','approved','rejected','completed','cancelled')),
 reason TEXT NOT NULL, request_version INTEGER NOT NULL DEFAULT 1, verification_summary TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE recovery_approvals (
id TEXT PRIMARY KEY NOT NULL, case_id TEXT NOT NULL REFERENCES support_cases(id), requested_by TEXT NOT NULL,
 approved_by TEXT NOT NULL, operation TEXT NOT NULL, request_digest TEXT NOT NULL, request_version INTEGER NOT NULL,
 created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER, CHECK(approved_by<>requested_by)
);

CREATE TABLE jobs (
id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('queued','running','succeeded','failed','cancel_requested','cancelled','timed_out')),
 initiated_by_type TEXT NOT NULL, initiated_by_id TEXT NOT NULL, executed_by TEXT, cancelled_by_type TEXT, cancelled_by_id TEXT,
 cancellation_reason TEXT, cancel_requested_at_ms INTEGER, finished_at_ms INTEGER, timeout_seconds INTEGER NOT NULL CHECK(timeout_seconds>0),
 attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0), max_attempts INTEGER NOT NULL DEFAULT 1 CHECK(max_attempts>0),
 mutex_key TEXT, payload_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(payload_json)), error_code TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE job_attempts (
job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE, attempt INTEGER NOT NULL,
 started_at_ms INTEGER NOT NULL, finished_at_ms INTEGER, outcome TEXT, error_code TEXT, PRIMARY KEY(job_id,attempt)
);

CREATE TABLE schedules (
id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL, expression TEXT NOT NULL, timezone TEXT NOT NULL,
 owner_type TEXT NOT NULL, owner_id TEXT NOT NULL, scope_id TEXT NOT NULL REFERENCES scopes(id),
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1)), config_json TEXT NOT NULL CHECK(json_valid(config_json)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE schedule_firings (
schedule_id TEXT NOT NULL REFERENCES schedules(id) ON DELETE CASCADE, scheduled_at_ms INTEGER NOT NULL,
 job_id TEXT NOT NULL REFERENCES jobs(id), PRIMARY KEY(schedule_id,scheduled_at_ms)
);

CREATE TABLE audit_events (
id TEXT PRIMARY KEY NOT NULL, occurred_at_ms INTEGER NOT NULL, actor_type TEXT NOT NULL, actor_id TEXT,
 app_id_snapshot TEXT, action TEXT NOT NULL, target_type TEXT NOT NULL, target_id TEXT,
 outcome TEXT NOT NULL, error_code TEXT, reason_code TEXT, request_id TEXT, task_id TEXT,
 detail_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(detail_json))
);

CREATE TABLE outbox_events (
id TEXT PRIMARY KEY NOT NULL, event_type TEXT NOT NULL, payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
 created_at_ms INTEGER NOT NULL, published_at_ms INTEGER, attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at_ms INTEGER
);

CREATE TABLE notifications (
id TEXT PRIMARY KEY NOT NULL, user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 channel TEXT NOT NULL DEFAULT 'email', template_key TEXT NOT NULL, destination_encrypted BLOB NOT NULL, key_id TEXT NOT NULL,
 payload_encrypted BLOB, state TEXT NOT NULL CHECK(state IN('queued','sent','failed','cancelled')),
 job_id TEXT REFERENCES jobs(id) ON DELETE SET NULL, error_code TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE webhook_endpoints (
id TEXT PRIMARY KEY NOT NULL, app_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
 url TEXT NOT NULL, secret_encrypted BLOB NOT NULL, key_id TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN(0,1)), created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE webhook_deliveries (
id TEXT PRIMARY KEY NOT NULL, endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
 event_id TEXT NOT NULL REFERENCES outbox_events(id), job_id TEXT REFERENCES jobs(id),
 state TEXT NOT NULL CHECK(state IN('queued','sent','failed','cancelled')), http_status INTEGER, error_code TEXT, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL, UNIQUE(endpoint_id,event_id)
);

CREATE TABLE report_runs (
id TEXT PRIMARY KEY NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id), scope_id TEXT NOT NULL REFERENCES scopes(id),
 owner_type TEXT NOT NULL, owner_id TEXT NOT NULL, period_start_ms INTEGER NOT NULL, period_end_ms INTEGER NOT NULL,
 timezone TEXT NOT NULL, definition_json TEXT NOT NULL CHECK(json_valid(definition_json)),
 completeness_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(completeness_json)), created_at_ms INTEGER NOT NULL,
 CHECK(period_end_ms>period_start_ms)
);

CREATE TABLE artifacts (
id TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL CHECK(kind IN('report','backup','export','avatar')),
 owner_type TEXT NOT NULL, owner_id TEXT NOT NULL, scope_id TEXT REFERENCES scopes(id), job_id TEXT REFERENCES jobs(id),
 report_id TEXT REFERENCES report_runs(id), storage_ref TEXT NOT NULL, format TEXT NOT NULL, size_bytes INTEGER NOT NULL CHECK(size_bytes>=0),
 sha256 TEXT NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0 CHECK(encrypted IN(0,1)), key_id TEXT,
 manifest_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(manifest_json)), created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER
);

CREATE TABLE metrics (
id TEXT PRIMARY KEY NOT NULL, occurred_at_ms INTEGER NOT NULL, metric_key TEXT NOT NULL,
 app_id_snapshot TEXT, value REAL NOT NULL, dimensions_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(dimensions_json))
);

CREATE TABLE activity_events (
id TEXT PRIMARY KEY NOT NULL, occurred_at_ms INTEGER NOT NULL, user_id TEXT NOT NULL,
 app_id_snapshot TEXT, event_type TEXT NOT NULL, source TEXT NOT NULL, request_id TEXT
);

CREATE TABLE settings (
setting_key TEXT PRIMARY KEY NOT NULL, value_json TEXT NOT NULL CHECK(json_valid(value_json)),
 changed_by TEXT NOT NULL, row_version INTEGER NOT NULL DEFAULT 1, created_at_ms INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL
);

CREATE TABLE idempotency_records (
caller_id TEXT NOT NULL, operation TEXT NOT NULL, key_hash TEXT NOT NULL,
 request_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN('pending','completed','failed')),
 result_ref TEXT, created_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL,
 PRIMARY KEY(caller_id,operation,key_hash)
);

CREATE INDEX ix_audit_events_occurred_at_ms ON audit_events(occurred_at_ms);

CREATE INDEX ix_audit_events_request_id ON audit_events(request_id);

CREATE INDEX ix_audit_events_task_id ON audit_events(task_id);

CREATE INDEX ix_audit_events_action_occurred_at_ms ON audit_events(action,occurred_at_ms);

CREATE INDEX ix_sessions_user_id_revoked_at_ms ON sessions(user_id,revoked_at_ms);

CREATE INDEX ix_one_time_credentials_expires_at_ms ON one_time_credentials(expires_at_ms);

CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens(family_id);

CREATE INDEX ix_jobs_state_created_at_ms ON jobs(state,created_at_ms);

CREATE INDEX ix_metrics_metric_key_occurred_at_ms ON metrics(metric_key,occurred_at_ms);

CREATE INDEX ix_activity_events_occurred_at_ms_user_id ON activity_events(occurred_at_ms,user_id);

INSERT INTO scopes(id,kind,app_id) VALUES('system','system',NULL);
PRAGMA user_version = 1;
COMMIT;
