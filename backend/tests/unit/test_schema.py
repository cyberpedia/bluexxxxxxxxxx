from app.db.base import Base
from app.models import schema  # noqa: F401


REQUIRED_TABLES = {
    'users',
    'roles',
    'capabilities',
    'role_capabilities',
    'user_alias_history',
    'user_sessions',
    'teams',
    'team_members',
    'team_audit_logs',
    'events',
    'event_templates',
    'event_themes',
    'challenges',
    'challenge_versions',
    'sub_challenges',
    'flags',
    'flag_versions',
    'hints',
    'submissions',
    'solve_proofs',
    'leaderboard_entries',
    'badges',
    'user_badges',
    'achievements',
    'notifications',
    'audit_logs',
    'immutable_audit_hash_chain',
    'risk_scores',
    'ip_logs',
    'device_fingerprints',
    'rate_limit_logs',
    'api_keys',
    'feature_flags',
    'system_settings',
    'password_policies',
    'mfa_settings',
    'backups',
    'backup_logs',
    'webhook_configs',
    'lab_instances',
    'lab_logs',
    'scoring_models',
}

SOFT_DELETE_TABLES = {'users', 'teams', 'events', 'challenges', 'flags', 'notifications', 'api_keys', 'webhook_configs', 'lab_instances'}


def test_all_required_tables_exist() -> None:
    assert REQUIRED_TABLES.issubset(set(Base.metadata.tables.keys()))


def test_timestamps_present_for_all_tables() -> None:
    for table in Base.metadata.tables.values():
        assert 'created_at' in table.columns, f"missing created_at on {table.name}"
        assert 'updated_at' in table.columns, f"missing updated_at on {table.name}"


def test_soft_delete_present_on_selected_tables() -> None:
    for table_name in SOFT_DELETE_TABLES:
        table = Base.metadata.tables[table_name]
        assert 'deleted_at' in table.columns


def test_flag_version_uniqueness() -> None:
    table = Base.metadata.tables['flag_versions']
    unique_constraint_cols = {
        tuple(sorted(col.name for col in c.columns))
        for c in table.constraints
        if c.__class__.__name__ == 'UniqueConstraint'
    }
    assert ('flag_id', 'version') in unique_constraint_cols
