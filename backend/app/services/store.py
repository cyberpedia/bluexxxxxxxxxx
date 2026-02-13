from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import secrets
import threading
import uuid

from app.security.passwords import hash_password, verify_password
from app.services.challenge_engine import ChallengeRecord, HintRule, SolveRecord
from datetime import datetime
from enum import Enum
import hashlib
import secrets
import uuid

from app.security.passwords import hash_password, verify_password


class AccountState(str, Enum):
    active = 'active'
    suspended = 'suspended'
    banned = 'banned'
    shadow = 'shadow'


@dataclass
class UserRecord:
    id: str
    email: str
    username: str
    password_hash: str
    email_verified: bool = False
    email_verify_code: str | None = None
    mfa_secret: str | None = None
    mfa_backup_hashes: list[str] = field(default_factory=list)
    force_password_reset: bool = False
    state: AccountState = AccountState.active
    capabilities: set[str] = field(default_factory=set)
    xp: int = 0
    streak_days: int = 0
    trophies: list[str] = field(default_factory=list)
    badges: set[str] = field(default_factory=set)
    achievements: set[str] = field(default_factory=set)


@dataclass
class SessionRecord:
    id: str
    user_id: str
    refresh_token_hash: str
    ip: str
    user_agent: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=datetime.utcnow)
    revoked: bool = False


@dataclass
class TeamRecord:
    id: str
    event_id: str
    name: str
    captain_id: str
    members: dict[str, str] = field(default_factory=dict)
    members: dict[str, str] = field(default_factory=dict)  # user_id -> role
    invite_approvals_required: bool = True
    roster_locked: bool = False


@dataclass
class APIKeyRecord:
    id: str
    user_id: str
    prefix: str
    key_hash: str


class InMemoryStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.users: dict[str, UserRecord] = {}
        self.user_by_email: dict[str, str] = {}
        self.user_by_username: dict[str, str] = {}
        self.sessions: dict[str, SessionRecord] = {}
        self.teams: dict[str, TeamRecord] = {}
        self.api_keys: dict[str, APIKeyRecord] = {}
        self.audit_logs: list[dict] = []
        self.ip_whitelist: set[str] = set()
        self.ip_blacklist: set[str] = set()
        self.rate_limit: dict[str, list[float]] = {}
        self.challenges: dict[str, ChallengeRecord] = {}
        self.hints: dict[str, HintRule] = {}
        self.solves: dict[str, SolveRecord] = {}
        self.score_adjustments: dict[str, object] = {}
        self.hidden_teams: set[str] = set()
        self.leaderboard_frozen: bool = False

    def audit(self, actor_user_id: str | None, action: str, details: dict) -> None:
        self.audit_logs.append(
            {
                'id': str(uuid.uuid4()),
                'actor_user_id': actor_user_id,
                'action': action,
                'details': details,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'created_at': datetime.utcnow().isoformat(),
            }
        )

    def register_user(self, email: str, username: str, password: str) -> UserRecord:
        with self.lock:
            uid = str(uuid.uuid4())
            verify_code = secrets.token_urlsafe(24)
            user = UserRecord(
                id=uid,
                email=email.lower(),
                username=username,
                password_hash=hash_password(password),
                email_verify_code=verify_code,
            )
            self.users[uid] = user
            self.user_by_email[user.email] = uid
            self.user_by_username[user.username] = uid
            self.audit(uid, 'identity.user_registered', {'email': user.email})
            return user
        uid = str(uuid.uuid4())
        verify_code = secrets.token_urlsafe(24)
        user = UserRecord(
            id=uid,
            email=email.lower(),
            username=username,
            password_hash=hash_password(password),
            email_verify_code=verify_code,
        )
        self.users[uid] = user
        self.user_by_email[user.email] = uid
        self.user_by_username[user.username] = uid
        self.audit(uid, 'identity.user_registered', {'email': user.email})
        return user

    def find_user_by_email(self, email: str) -> UserRecord | None:
        uid = self.user_by_email.get(email.lower())
        return self.users.get(uid) if uid else None

    def find_user_by_id(self, uid: str) -> UserRecord | None:
        return self.users.get(uid)

    def validate_password(self, user: UserRecord, password: str) -> bool:
        return verify_password(password, user.password_hash)

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode('utf-8')).hexdigest()


store = InMemoryStore()
