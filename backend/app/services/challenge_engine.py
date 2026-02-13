from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import re

from app.security.flags import constant_time_flag_compare


class ChallengeLifecycle:
    draft = 'draft'
    review = 'review'
    approved = 'approved'
    published = 'published'
    archived = 'archived'


@dataclass
class FlagRule:
    mode: str  # exact | regex | partial | file | api
    value: str
    rotate_at: datetime | None = None
    expires_at: datetime | None = None


@dataclass
class HintRule:
    id: str
    challenge_id: str
    content: str
    cost: int
    enabled: bool = True
    release_at: datetime | None = None
    auto_after_solves: int | None = None
    usage_count: int = 0


@dataclass
class ChallengeRecord:
    id: str
    title: str
    description: str
    category: str
    lifecycle: str = ChallengeLifecycle.draft
    scoring_mode: str = 'static'  # static|dynamic|progressive|first_blood|time_decay
    base_points: int = 500
    min_points: int = 100
    first_blood_bonus: int = 50
    published_at: datetime | None = None
    visible_from: datetime | None = None
    visible_to: datetime | None = None
    flags: list[FlagRule] = field(default_factory=list)
    parts: list[str] = field(default_factory=list)
    enable_hints: bool = True
    unlock_solve_x: int | None = None
    unlock_of_y: int | None = None
    unlock_score_threshold: int | None = None
    unlock_time: datetime | None = None
    admin_override: bool = False


@dataclass
class SolveRecord:
    id: str
    user_id: str
    challenge_id: str
    awarded_points: int
    solved_at: datetime
    revoked: bool = False


def can_view_challenge(challenge: ChallengeRecord, solved_count: int, score: int, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    if challenge.admin_override:
        return True
    if challenge.lifecycle != ChallengeLifecycle.published:
        return False
    if challenge.visible_from and now < challenge.visible_from:
        return False
    if challenge.visible_to and now > challenge.visible_to:
        return False
    if challenge.unlock_time and now < challenge.unlock_time:
        return False
    if challenge.unlock_score_threshold and score < challenge.unlock_score_threshold:
        return False
    if challenge.unlock_solve_x and challenge.unlock_of_y and solved_count < challenge.unlock_solve_x:
        return False
    return True


def score_for_solve(challenge: ChallengeRecord, solve_count: int, minutes_since_publish: int) -> int:
    if challenge.scoring_mode == 'static':
        return challenge.base_points
    if challenge.scoring_mode == 'dynamic':
        deduction = min(solve_count * 10, challenge.base_points - challenge.min_points)
        return max(challenge.base_points - deduction, challenge.min_points)
    if challenge.scoring_mode == 'progressive':
        increment = min(solve_count * 5, 150)
        return challenge.base_points + increment
    if challenge.scoring_mode == 'first_blood':
        return challenge.base_points + (challenge.first_blood_bonus if solve_count == 0 else 0)
    if challenge.scoring_mode == 'time_decay':
        decay = int(120 * (1 - math.exp(-minutes_since_publish / 60)))
        return max(challenge.base_points - decay, challenge.min_points)
    return challenge.base_points


def validate_flag(flag: FlagRule, submitted: str) -> bool:
    now = datetime.now(timezone.utc)
    if flag.rotate_at and now >= flag.rotate_at:
        return False
    if flag.expires_at and now >= flag.expires_at:
        return False

    if flag.mode == 'exact':
        return constant_time_flag_compare(flag.value, submitted)
    if flag.mode == 'regex':
        return bool(re.match(flag.value, submitted))
    if flag.mode == 'partial':
        return flag.value in submitted
    if flag.mode == 'file':
        return submitted.endswith(flag.value)
    if flag.mode == 'api':
        return submitted == f'api::{flag.value}'
    return False
