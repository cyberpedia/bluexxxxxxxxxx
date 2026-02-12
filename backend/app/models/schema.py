import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.security.passwords import hash_password, verify_password


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class SoftDeleteMixin:
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class User(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'users'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = hash_password(password)

    def check_password(self, password: str) -> bool:
        return verify_password(password, self.password_hash)


class Role(Base, TimestampMixin):
    __tablename__ = 'roles'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


class Capability(Base, TimestampMixin):
    __tablename__ = 'capabilities'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(String(255))


class RoleCapability(Base, TimestampMixin):
    __tablename__ = 'role_capabilities'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('roles.id', ondelete='CASCADE'), nullable=False)
    capability_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('capabilities.id', ondelete='CASCADE'), nullable=False)
    __table_args__ = (UniqueConstraint('role_id', 'capability_id', name='uq_role_capability_pair'),)


class UserAliasHistory(Base, TimestampMixin):
    __tablename__ = 'user_alias_history'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    old_alias: Mapped[str] = mapped_column(String(64), nullable=False)
    new_alias: Mapped[str] = mapped_column(String(64), nullable=False)


class UserSession(Base, TimestampMixin):
    __tablename__ = 'user_sessions'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    refresh_token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET)
    device_info: Mapped[str | None] = mapped_column(String(255))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Team(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'teams'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)


class TeamMember(Base, TimestampMixin):
    __tablename__ = 'team_members'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('teams.id', ondelete='CASCADE'), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default='member')
    __table_args__ = (UniqueConstraint('team_id', 'user_id', name='uq_team_membership'),)


class TeamAuditLog(Base, TimestampMixin):
    __tablename__ = 'team_audit_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    team_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('teams.id', ondelete='CASCADE'), nullable=False, index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    details: Mapped[dict | None] = mapped_column(JSON)


class EventTemplate(Base, TimestampMixin):
    __tablename__ = 'event_templates'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    template_data: Mapped[dict] = mapped_column(JSON, nullable=False)


class EventTheme(Base, TimestampMixin):
    __tablename__ = 'event_themes'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    theme_config: Mapped[dict] = mapped_column(JSON, nullable=False)


class Event(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'events'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    template_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('event_templates.id', ondelete='SET NULL'))
    theme_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('event_themes.id', ondelete='SET NULL'))
    __table_args__ = (CheckConstraint('ends_at > starts_at', name='event_end_after_start'),)


class Challenge(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'challenges'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('events.id', ondelete='CASCADE'), nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    __table_args__ = (UniqueConstraint('event_id', 'slug', name='uq_event_challenge_slug'),)


class ChallengeVersion(Base, TimestampMixin):
    __tablename__ = 'challenge_versions'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    __table_args__ = (UniqueConstraint('challenge_id', 'version', name='uq_challenge_version'),)


class SubChallenge(Base, TimestampMixin):
    __tablename__ = 'sub_challenges'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(180), nullable=False)


class Flag(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'flags'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False, index=True)
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('flag_versions.id', ondelete='SET NULL'))


class FlagVersion(Base, TimestampMixin):
    __tablename__ = 'flag_versions'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    flag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('flags.id', ondelete='CASCADE'), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    flag_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    __table_args__ = (UniqueConstraint('flag_id', 'version', name='uq_flag_version_pair'),)


class Hint(Base, TimestampMixin):
    __tablename__ = 'hints'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    cost: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Submission(Base, TimestampMixin):
    __tablename__ = 'submissions'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False, index=True)
    submitted_flag: Mapped[str] = mapped_column(String(255), nullable=False)
    is_correct: Mapped[bool] = mapped_column(Boolean, nullable=False)


class SolveProof(Base, TimestampMixin):
    __tablename__ = 'solve_proofs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    submission_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('submissions.id', ondelete='CASCADE'), nullable=False, unique=True)
    proof_data: Mapped[dict] = mapped_column(JSON, nullable=False)


class LeaderboardEntry(Base, TimestampMixin):
    __tablename__ = 'leaderboard_entries'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('events.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    __table_args__ = (UniqueConstraint('event_id', 'user_id', name='uq_leaderboard_event_user'),)


class Badge(Base, TimestampMixin):
    __tablename__ = 'badges'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)


class UserBadge(Base, TimestampMixin):
    __tablename__ = 'user_badges'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    badge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('badges.id', ondelete='CASCADE'), nullable=False)
    awarded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'))


class Achievement(Base, TimestampMixin):
    __tablename__ = 'achievements'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(120), nullable=False)
    meta: Mapped[dict | None] = mapped_column(JSON)


class Notification(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'notifications'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'), index=True)
    channel: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditLog(Base, TimestampMixin):
    __tablename__ = 'audit_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'))
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(80), nullable=False)
    target_id: Mapped[str] = mapped_column(String(80), nullable=False)
    request_ip: Mapped[str | None] = mapped_column(INET)
    details: Mapped[dict | None] = mapped_column(JSON)


class ImmutableAuditHashChain(Base, TimestampMixin):
    __tablename__ = 'immutable_audit_hash_chain'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_log_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('audit_logs.id', ondelete='CASCADE'), nullable=False, unique=True)
    prev_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    current_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class RiskScore(Base, TimestampMixin):
    __tablename__ = 'risk_scores'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(255))


class IpLog(Base, TimestampMixin):
    __tablename__ = 'ip_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'), index=True)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)


class DeviceFingerprint(Base, TimestampMixin):
    __tablename__ = 'device_fingerprints'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    fingerprint_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    last_seen_ip: Mapped[str | None] = mapped_column(INET)


class RateLimitLog(Base, TimestampMixin):
    __tablename__ = 'rate_limit_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    __table_args__ = (Index('ix_rate_limit_subject_endpoint', 'subject_type', 'subject_id', 'endpoint'),)


class ApiKey(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'api_keys'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FeatureFlag(Base, TimestampMixin):
    __tablename__ = 'feature_flags'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    config: Mapped[dict | None] = mapped_column(JSON)


class SystemSetting(Base, TimestampMixin):
    __tablename__ = 'system_settings'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PasswordPolicy(Base, TimestampMixin):
    __tablename__ = 'password_policies'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    min_length: Mapped[int] = mapped_column(Integer, nullable=False, default=12)
    require_uppercase: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_number: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    require_symbol: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class MFASetting(Base, TimestampMixin):
    __tablename__ = 'mfa_settings'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False, unique=True)
    method: Mapped[str] = mapped_column(String(32), nullable=False, default='totp')
    secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)


class Backup(Base, TimestampMixin):
    __tablename__ = 'backups'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    storage_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='pending')


class BackupLog(Base, TimestampMixin):
    __tablename__ = 'backup_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    backup_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('backups.id', ondelete='CASCADE'), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)


class WebhookConfig(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'webhook_configs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_key: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_url: Mapped[str] = mapped_column(String(255), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class LabInstance(Base, TimestampMixin, SoftDeleteMixin):
    __tablename__ = 'lab_instances'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    challenge_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False)
    container_id: Mapped[str | None] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='pending')


class LabLog(Base, TimestampMixin):
    __tablename__ = 'lab_logs'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    lab_instance_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('lab_instances.id', ondelete='CASCADE'), nullable=False, index=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default='info')
    message: Mapped[str] = mapped_column(Text, nullable=False)


class ScoringModel(Base, TimestampMixin):
    __tablename__ = 'scoring_models'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

