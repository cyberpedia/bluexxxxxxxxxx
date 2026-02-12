from datetime import datetime, timezone
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, WebSocket
from pydantic import BaseModel, EmailStr, Field, constr

from app.config.settings import settings
from app.security.jwt import create_access_token, create_refresh_token, decode_token
from app.security.mfa import generate_backup_codes, setup_totp, use_backup_code, verify_totp
from app.security.policy import enforce_password_policy
from app.security.rbac import get_current_user, require_capability
from app.services.challenge_engine import (
    ChallengeLifecycle,
    ChallengeRecord,
    FlagRule,
    HintRule,
    SolveRecord,
    can_view_challenge,
    score_for_solve,
    validate_flag,
)
from app.services.store import AccountState, APIKeyRecord, SessionRecord, TeamRecord, store
from app.services.leaderboard import (
    ScoreAdjustment,
    build_category_board,
    build_individual_board,
    build_org_board,
    build_team_board,
    category_dominance,
    export_csv_signed,
    export_pdf_signed,
    maybe_freeze,
    score_progression,
    solve_velocity,
    verify_integrity,
)
from app.services.realtime import connect, disconnect, fire_and_forget, publish_first_blood, publish_solve_event, recent_feed, record_solve_event

api_router = APIRouter()


class RegisterIn(BaseModel):
    email: EmailStr
    username: constr(min_length=3, max_length=64)
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str | None = None
    backup_code: str | None = None


class EmailVerifyIn(BaseModel):
    email: EmailStr
    code: str


class TeamCreateIn(BaseModel):
    event_id: constr(min_length=1, max_length=100)
    name: constr(min_length=2, max_length=120)
    invite_approval: bool = True


class TeamAddMemberIn(BaseModel):
    user_id: str
    role: str = 'member'


class ChallengeIn(BaseModel):
    title: constr(min_length=3, max_length=200)
    description: constr(min_length=3, max_length=8000)
    category: constr(min_length=2, max_length=64)
    lifecycle: str = ChallengeLifecycle.draft
    scoring_mode: str = 'static'
    base_points: int = Field(500, ge=1, le=5000)
    min_points: int = Field(100, ge=1, le=5000)
    first_blood_bonus: int = Field(50, ge=0, le=1000)
    visible_from: datetime | None = None
    visible_to: datetime | None = None


class FlagIn(BaseModel):
    mode: str
    value: constr(min_length=1, max_length=255)
    rotate_at: datetime | None = None
    expires_at: datetime | None = None


class SubmitIn(BaseModel):
    submitted_flag: constr(min_length=1, max_length=2000)


class HintIn(BaseModel):
    content: constr(min_length=1, max_length=5000)
    cost: int = Field(0, ge=0, le=1000)
    enabled: bool = True
    release_at: datetime | None = None
    auto_after_solves: int | None = Field(default=None, ge=1, le=1000)


def _assert_challenge_editor(user) -> None:
    if 'challenge:write' not in user.capabilities:
        raise HTTPException(status_code=403, detail='Missing challenge:write capability')


@api_router.post('/auth/register')
def register(payload: RegisterIn):
    if store.find_user_by_email(payload.email):
        raise HTTPException(status_code=409, detail='Email already exists')
    enforce_password_policy(payload.password)
    user = store.register_user(payload.email, payload.username, payload.password)
    return {'user_id': user.id, 'email_verified': user.email_verified, 'verification_code': user.email_verify_code}


@api_router.post('/auth/verify-email')
def verify_email(payload: EmailVerifyIn):
    user = store.find_user_by_email(payload.email)
    if not user or user.email_verify_code != payload.code:
        raise HTTPException(status_code=400, detail='Invalid verification code')
    user.email_verified = True
    user.email_verify_code = None
    store.audit(user.id, 'identity.email_verified', {})
    return {'verified': True}


@api_router.post('/auth/mfa/setup')
def mfa_setup(user=Depends(get_current_user)):
    secret = setup_totp(user)
    backup_codes = generate_backup_codes(store, user)
    store.audit(user.id, 'identity.mfa_enabled', {})
    return {'secret': secret, 'backup_codes': backup_codes}


@api_router.post('/auth/login')
def login(payload: LoginIn, request: Request, response: Response):
    user = store.find_user_by_email(payload.email)
    if not user or not store.validate_password(user, payload.password):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if user.state in {AccountState.suspended, AccountState.banned}:
        raise HTTPException(status_code=403, detail=f'Account {user.state.value}')
    if settings.require_email_verification and not user.email_verified:
        raise HTTPException(status_code=403, detail='Email not verified')
    if user.force_password_reset:
        raise HTTPException(status_code=403, detail='Password reset required')
    if user.mfa_secret:
        ok = False
        if payload.mfa_code:
            ok = verify_totp(user, payload.mfa_code)
        elif payload.backup_code:
            ok = use_backup_code(store, user, payload.backup_code)
        if not ok:
            raise HTTPException(status_code=401, detail='MFA required')

    session_id = str(uuid.uuid4())
    refresh_token = create_refresh_token(user.id, session_id)
    access_token = create_access_token(user.id, sorted(user.capabilities))
    ip = request.client.host if request.client else 'unknown'
    ua = request.headers.get('user-agent', 'unknown')
    store.sessions[session_id] = SessionRecord(
        id=session_id, user_id=user.id, refresh_token_hash=store.digest(refresh_token), ip=ip, user_agent=ua
    )

    response.set_cookie('access_token', access_token, httponly=True, secure=settings.secure_cookies, samesite='strict')
    response.set_cookie('refresh_token', refresh_token, httponly=True, secure=settings.secure_cookies, samesite='strict')
    store.audit(user.id, 'identity.login', {'session_id': session_id, 'ip': ip})
    return {'access_token': access_token, 'refresh_token': refresh_token, 'state': user.state.value}


@api_router.post('/auth/refresh')
def refresh_token(response: Response, request: Request):
    token = request.cookies.get('refresh_token')
    if not token:
        raise HTTPException(status_code=401, detail='Missing refresh token')
    payload = decode_token(token)
    if payload.get('type') != 'refresh':
        raise HTTPException(status_code=401, detail='Wrong token type')
    sid = payload['sid']
    session = store.sessions.get(sid)
    if not session or session.revoked or session.refresh_token_hash != store.digest(token):
        raise HTTPException(status_code=401, detail='Invalid session')
    user = store.find_user_by_id(payload['sub'])
    if not user:
        raise HTTPException(status_code=401, detail='Invalid user')
    access = create_access_token(user.id, sorted(user.capabilities))
    response.set_cookie('access_token', access, httponly=True, secure=settings.secure_cookies, samesite='strict')
    return {'access_token': access}


@api_router.post('/auth/logout')
def logout(response: Response, request: Request, user=Depends(get_current_user)):
    token = request.cookies.get('refresh_token')
    if token:
        payload = decode_token(token)
        sid = payload.get('sid')
        if sid and sid in store.sessions:
            store.sessions[sid].revoked = True
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')
    store.audit(user.id, 'identity.logout', {})
    return {'ok': True}


@api_router.post('/auth/logout-all')
def logout_all(user=Depends(get_current_user)):
    for s in store.sessions.values():
        if s.user_id == user.id:
            s.revoked = True
    store.audit(user.id, 'identity.logout_all', {})
    return {'ok': True}


@api_router.post('/users/{user_id}/state', dependencies=[Depends(require_capability('user:state:update'))])
def set_state(user_id: str, state: AccountState, actor=Depends(get_current_user)):
    user = store.find_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    user.state = state
    store.audit(actor.id, 'identity.state_changed', {'target_user_id': user_id, 'state': state.value})
    return {'user_id': user_id, 'state': state.value}


@api_router.post('/users/{user_id}/force-password-reset', dependencies=[Depends(require_capability('user:password:force_reset'))])
def force_password_reset(user_id: str, actor=Depends(get_current_user)):
    user = store.find_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    user.force_password_reset = True
    store.audit(actor.id, 'identity.force_password_reset', {'target_user_id': user_id})
    return {'ok': True}


@api_router.post('/api-keys')
def create_api_key(user=Depends(get_current_user)):
    raw = f'ck_{secrets.token_urlsafe(24)}'
    key_id = str(uuid.uuid4())
    key = APIKeyRecord(id=key_id, user_id=user.id, prefix=raw[:12], key_hash=store.digest(raw))
    store.api_keys[key_id] = key
    store.audit(user.id, 'identity.api_key_created', {'key_id': key_id})
    return {'api_key': raw, 'key_id': key_id, 'prefix': key.prefix}


@api_router.delete('/api-keys/{key_id}')
def revoke_api_key(key_id: str, user=Depends(get_current_user)):
    key = store.api_keys.get(key_id)
    if not key or key.user_id != user.id:
        raise HTTPException(status_code=404, detail='API key not found')
    del store.api_keys[key_id]
    store.audit(user.id, 'identity.api_key_revoked', {'key_id': key_id})
    return {'ok': True}


@api_router.post('/security/ip/blacklist/{ip}', dependencies=[Depends(require_capability('security:ip:blacklist'))])
def blacklist_ip(ip: str, actor=Depends(get_current_user)):
    store.ip_blacklist.add(ip)
    store.audit(actor.id, 'security.ip_blacklisted', {'ip': ip})
    return {'ok': True}


@api_router.post('/security/ip/whitelist/{ip}', dependencies=[Depends(require_capability('security:ip:whitelist'))])
def whitelist_ip(ip: str, actor=Depends(get_current_user)):
    store.ip_whitelist.add(ip)
    store.audit(actor.id, 'security.ip_whitelisted', {'ip': ip})
    return {'ok': True}


@api_router.get('/security/duplicate-accounts/{email}')
def duplicate_account_heuristic(email: str, user=Depends(get_current_user)):
    domain = email.lower().split('@')[-1]
    candidates = [u.email for u in store.users.values() if u.email.split('@')[-1] == domain]
    suspected = [u for u in candidates if u != email.lower()]
    score = min(len(suspected) * 20, 100)
    store.audit(user.id, 'security.duplicate_heuristic_checked', {'email': email, 'score': score})
    return {'risk_score': score, 'suspected_matches': suspected}


@api_router.post('/teams')
def create_team(payload: TeamCreateIn, user=Depends(get_current_user)):
    if not settings.enable_team_creation:
        raise HTTPException(status_code=403, detail='Team creation disabled')
    team = TeamRecord(
        id=str(uuid.uuid4()),
        event_id=payload.event_id,
        name=payload.name,
        captain_id=user.id,
        members={user.id: 'captain'},
        invite_approvals_required=payload.invite_approval,
        roster_locked=settings.team_roster_lock,
    )
    store.teams[team.id] = team
    store.audit(user.id, 'team.created', {'team_id': team.id, 'event_id': payload.event_id})
    return {'team_id': team.id, 'name': team.name}


@api_router.post('/teams/{team_id}/members')
def add_team_member(team_id: str, payload: TeamAddMemberIn, user=Depends(get_current_user)):
    team = store.teams.get(team_id)
    if not team:
        raise HTTPException(status_code=404, detail='Team not found')
    if team.roster_locked:
        raise HTTPException(status_code=403, detail='Team roster locked')
    if user.id not in team.members or team.members[user.id] not in {'captain', 'co-captain'}:
        raise HTTPException(status_code=403, detail='Not authorized for team management')
    if len(team.members) >= settings.max_team_size:
        raise HTTPException(status_code=400, detail='Team is full')
    if payload.role not in {'member', 'co-captain'}:
        raise HTTPException(status_code=400, detail='Invalid role')
    if team.invite_approvals_required and team.members[user.id] != 'captain':
        raise HTTPException(status_code=403, detail='Invite approval required by captain')
    team.members[payload.user_id] = payload.role
    store.audit(user.id, 'team.member_added', {'team_id': team_id, 'user_id': payload.user_id, 'role': payload.role})
    return {'ok': True, 'team_size': len(team.members)}


@api_router.post('/teams/{team_id}/lock')
def lock_team(team_id: str, user=Depends(get_current_user)):
    team = store.teams.get(team_id)
    if not team:
        raise HTTPException(status_code=404, detail='Team not found')
    if team.members.get(user.id) != 'captain':
        raise HTTPException(status_code=403, detail='Captain required')
    team.roster_locked = True
    store.audit(user.id, 'team.roster_locked', {'team_id': team_id})
    return {'ok': True}


@api_router.get('/team-audit/{team_id}')
def get_team_audit(team_id: str, user=Depends(get_current_user)):
    team = store.teams.get(team_id)
    if not team or user.id not in team.members:
        raise HTTPException(status_code=404, detail='Team not found')
    logs = [a for a in store.audit_logs if a['action'].startswith('team.') and a['details'].get('team_id') == team_id]
    return {'logs': logs}


# Challenge engine
@api_router.post('/challenges')
def create_challenge(payload: ChallengeIn, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    with store.lock:
        cid = str(uuid.uuid4())
        challenge = ChallengeRecord(
            id=cid,
            title=payload.title,
            description=payload.description,
            category=payload.category,
            lifecycle=payload.lifecycle,
            scoring_mode=payload.scoring_mode,
            base_points=payload.base_points,
            min_points=payload.min_points,
            first_blood_bonus=payload.first_blood_bonus,
            visible_from=payload.visible_from,
            visible_to=payload.visible_to,
        )
        if challenge.lifecycle == ChallengeLifecycle.published:
            challenge.published_at = datetime.now(timezone.utc)
        store.challenges[cid] = challenge
        store.audit(user.id, 'challenge.created', {'challenge_id': cid})
    return {'challenge_id': cid}


@api_router.get('/challenges')
def list_challenges(user=Depends(get_current_user)):
    score = sum(s.awarded_points for s in store.solves.values() if s.user_id == user.id and not s.revoked)
    solved_count = len([s for s in store.solves.values() if s.user_id == user.id and not s.revoked])
    now = datetime.now(timezone.utc)
    data = [c for c in store.challenges.values() if can_view_challenge(c, solved_count, score, now) or 'challenge:write' in user.capabilities]
    return {'items': data}


@api_router.put('/challenges/{challenge_id}')
def update_challenge(challenge_id: str, payload: ChallengeIn, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    with store.lock:
        challenge = store.challenges.get(challenge_id)
        if not challenge:
            raise HTTPException(status_code=404, detail='Challenge not found')
        challenge.title = payload.title
        challenge.description = payload.description
        challenge.category = payload.category
        challenge.lifecycle = payload.lifecycle
        challenge.scoring_mode = payload.scoring_mode
        challenge.base_points = payload.base_points
        challenge.min_points = payload.min_points
        challenge.first_blood_bonus = payload.first_blood_bonus
        challenge.visible_from = payload.visible_from
        challenge.visible_to = payload.visible_to
        if challenge.lifecycle == ChallengeLifecycle.published and challenge.published_at is None:
            challenge.published_at = datetime.now(timezone.utc)
        store.audit(user.id, 'challenge.updated', {'challenge_id': challenge_id})
    return {'ok': True}


@api_router.delete('/challenges/{challenge_id}')
def archive_challenge(challenge_id: str, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    challenge = store.challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail='Challenge not found')
    challenge.lifecycle = ChallengeLifecycle.archived
    store.audit(user.id, 'challenge.archived', {'challenge_id': challenge_id})
    return {'ok': True}


@api_router.post('/challenges/{challenge_id}/duplicate')
def duplicate_challenge(challenge_id: str, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    src = store.challenges.get(challenge_id)
    if not src:
        raise HTTPException(status_code=404, detail='Challenge not found')
    clone_id = str(uuid.uuid4())
    clone = ChallengeRecord(**{**src.__dict__, 'id': clone_id, 'title': f'{src.title} (Copy)', 'lifecycle': ChallengeLifecycle.draft})
    store.challenges[clone_id] = clone
    store.audit(user.id, 'challenge.duplicated', {'source_challenge_id': challenge_id, 'challenge_id': clone_id})
    return {'challenge_id': clone_id}


@api_router.get('/challenges/{challenge_id}/export')
def export_challenge(challenge_id: str, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    c = store.challenges.get(challenge_id)
    if not c:
        raise HTTPException(status_code=404, detail='Challenge not found')
    hints = [h for h in store.hints.values() if h.challenge_id == challenge_id]
    return {'challenge': c.__dict__, 'hints': [h.__dict__ for h in hints]}


@api_router.post('/challenges/import')
def import_challenge(payload: dict, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    try:
        cdata = payload['challenge']
        cid = str(uuid.uuid4())
        c = ChallengeRecord(**{**cdata, 'id': cid, 'lifecycle': ChallengeLifecycle.draft})
        store.challenges[cid] = c
        for h in payload.get('hints', []):
            hid = str(uuid.uuid4())
            store.hints[hid] = HintRule(id=hid, challenge_id=cid, **{k: v for k, v in h.items() if k not in {'id', 'challenge_id'}})
        store.audit(user.id, 'challenge.imported', {'challenge_id': cid})
        return {'challenge_id': cid}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f'Invalid import payload: {exc}')


@api_router.post('/challenges/{challenge_id}/flags')
def add_flag(challenge_id: str, payload: FlagIn, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    challenge = store.challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail='Challenge not found')
    if payload.mode not in {'exact', 'regex', 'partial', 'file', 'api'}:
        raise HTTPException(status_code=400, detail='Invalid flag mode')
    challenge.flags.append(
        FlagRule(mode=payload.mode, value=payload.value, rotate_at=payload.rotate_at, expires_at=payload.expires_at)
    )
    store.audit(user.id, 'challenge.flag_added', {'challenge_id': challenge_id, 'mode': payload.mode})
    return {'ok': True}


@api_router.post('/challenges/{challenge_id}/hints')
def add_hint(challenge_id: str, payload: HintIn, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    challenge = store.challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail='Challenge not found')
    hid = str(uuid.uuid4())
    hint = HintRule(
        id=hid,
        challenge_id=challenge_id,
        content=payload.content,
        cost=payload.cost,
        enabled=payload.enabled,
        release_at=payload.release_at,
        auto_after_solves=payload.auto_after_solves,
    )
    store.hints[hid] = hint
    store.audit(user.id, 'challenge.hint_added', {'challenge_id': challenge_id, 'hint_id': hid})
    return {'hint_id': hid}


@api_router.get('/challenges/{challenge_id}/hints')
def get_hints(challenge_id: str, user=Depends(get_current_user)):
    challenge = store.challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail='Challenge not found')
    if not challenge.enable_hints:
        return {'hints': []}
    solves = len([s for s in store.solves.values() if s.challenge_id == challenge_id and not s.revoked])
    now = datetime.now(timezone.utc)
    visible = []
    for hint in store.hints.values():
        if hint.challenge_id != challenge_id or not hint.enabled:
            continue
        if hint.release_at and now < hint.release_at:
            if 'challenge:write' not in user.capabilities:
                continue
        if hint.auto_after_solves and solves < hint.auto_after_solves and 'challenge:write' not in user.capabilities:
            continue
        hint.usage_count += 1
        visible.append(hint)
    return {'hints': visible}


@api_router.post('/challenges/{challenge_id}/submit')
def submit_flag(challenge_id: str, payload: SubmitIn, user=Depends(get_current_user)):
    challenge = store.challenges.get(challenge_id)
    if not challenge:
        raise HTTPException(status_code=404, detail='Challenge not found')
    if challenge.lifecycle != ChallengeLifecycle.published and 'challenge:write' not in user.capabilities:
        raise HTTPException(status_code=403, detail='Challenge not available')

    for solved in store.solves.values():
        if solved.user_id == user.id and solved.challenge_id == challenge_id and not solved.revoked:
            return {'correct': True, 'already_solved': True, 'points': solved.awarded_points}

    matched = any(validate_flag(rule, payload.submitted_flag) for rule in challenge.flags)
    if not matched:
        store.audit(user.id, 'challenge.submit_failed', {'challenge_id': challenge_id})
        return {'correct': False}

    challenge_solves = len([s for s in store.solves.values() if s.challenge_id == challenge_id and not s.revoked])
    minutes = 0
    if challenge.published_at:
        minutes = int((datetime.now(timezone.utc) - challenge.published_at).total_seconds() / 60)
    points = score_for_solve(challenge, challenge_solves, minutes)
    sid = str(uuid.uuid4())
    solve = SolveRecord(id=sid, user_id=user.id, challenge_id=challenge_id, awarded_points=points, solved_at=datetime.now(timezone.utc))
    store.solves[sid] = solve
    first_blood = challenge_solves == 0
    _update_gamification_for_solve(user, points, first_blood)
    store.audit(user.id, 'challenge.solved', {'challenge_id': challenge_id, 'points': points, 'first_blood': first_blood})
    record_solve_event(challenge_id, user.id, points, first_blood)
    fire_and_forget(publish_solve_event(challenge_id, user.id, points))
    if first_blood:
        fire_and_forget(publish_first_blood(challenge_id, user.id))
    return {'correct': True, 'points': points}


class ManualAwardIn(BaseModel):
    user_id: str
    points: int = Field(ge=1, le=10000)


@api_router.post('/challenges/{challenge_id}/manual-award', dependencies=[Depends(require_capability('challenge:score:admin'))])
def manual_award(challenge_id: str, payload: ManualAwardIn, admin=Depends(get_current_user)):
    sid = str(uuid.uuid4())
    store.solves[sid] = SolveRecord(
        id=sid,
        user_id=payload.user_id,
        challenge_id=challenge_id,
        awarded_points=payload.points,
        solved_at=datetime.now(timezone.utc),
    )
    store.audit(admin.id, 'challenge.manual_award', {'challenge_id': challenge_id, 'user_id': payload.user_id, 'points': payload.points})
    return {'solve_id': sid}


class AdjustSolveIn(BaseModel):
    solve_id: str
    revoke: bool = False
    new_timestamp: datetime | None = None
    retroactive_points: int | None = Field(default=None, ge=1, le=10000)


@api_router.post('/challenges/{challenge_id}/solve-controls', dependencies=[Depends(require_capability('challenge:score:admin'))])
def solve_controls(challenge_id: str, payload: AdjustSolveIn, admin=Depends(get_current_user)):
    solve = store.solves.get(payload.solve_id)
    if not solve or solve.challenge_id != challenge_id:
        raise HTTPException(status_code=404, detail='Solve not found')
    if payload.revoke:
        solve.revoked = True
    if payload.new_timestamp:
        solve.solved_at = payload.new_timestamp
    if payload.retroactive_points is not None:
        solve.awarded_points = payload.retroactive_points
    store.audit(admin.id, 'challenge.solve_adjusted', {'challenge_id': challenge_id, 'solve_id': payload.solve_id})
    return {'ok': True}


@api_router.get('/challenges/{challenge_id}/analytics')
def challenge_analytics(challenge_id: str, user=Depends(get_current_user)):
    _assert_challenge_editor(user)
    hint_usage = [h.usage_count for h in store.hints.values() if h.challenge_id == challenge_id]
    solve_count = len([s for s in store.solves.values() if s.challenge_id == challenge_id and not s.revoked])
    return {'solve_count': solve_count, 'hint_usage_total': sum(hint_usage)}




# Leaderboards & gamification
class ScoreAdjustmentIn(BaseModel):
    target_type: str
    target_id: str
    delta: int = Field(ge=-10000, le=10000)
    reason: constr(min_length=3, max_length=500)


@api_router.get('/leaderboards/{mode}')
def get_leaderboard(mode: str, user=Depends(get_current_user)):
    if mode == 'individual':
        board = build_individual_board(store)
    elif mode == 'teams':
        board = build_team_board(store)
    elif mode == 'categories':
        board = build_category_board(store)
    elif mode == 'orgs':
        board = build_org_board(store)
    else:
        raise HTTPException(status_code=400, detail='Invalid mode')
    return {'mode': mode, 'frozen': store.leaderboard_frozen, 'items': maybe_freeze(board, store)}


@api_router.post('/leaderboards/freeze', dependencies=[Depends(require_capability('leaderboard:admin'))])
def freeze(admin=Depends(get_current_user)):
    store.leaderboard_frozen = True
    store.audit(admin.id, 'leaderboard.freeze', {})
    return {'ok': True}


@api_router.post('/leaderboards/unfreeze', dependencies=[Depends(require_capability('leaderboard:admin'))])
def unfreeze(admin=Depends(get_current_user)):
    store.leaderboard_frozen = False
    store.audit(admin.id, 'leaderboard.unfreeze', {})
    return {'ok': True}


@api_router.post('/leaderboards/adjust', dependencies=[Depends(require_capability('leaderboard:admin'))])
def adjust_score(payload: ScoreAdjustmentIn, admin=Depends(get_current_user)):
    if payload.target_type not in {'user', 'team', 'org'}:
        raise HTTPException(status_code=400, detail='Invalid target_type')
    aid = str(uuid.uuid4())
    store.score_adjustments[aid] = ScoreAdjustment(
        id=aid,
        target_type=payload.target_type,
        target_id=payload.target_id,
        delta=payload.delta,
        reason=payload.reason,
        admin_user_id=admin.id,
    )
    store.audit(admin.id, 'leaderboard.manual_adjust', {'adjustment_id': aid, 'target': payload.target_id, 'delta': payload.delta})
    return {'adjustment_id': aid}


@api_router.post('/leaderboards/hide-team/{team_id}', dependencies=[Depends(require_capability('leaderboard:admin'))])
def hide_team(team_id: str, admin=Depends(get_current_user)):
    store.hidden_teams.add(team_id)
    store.audit(admin.id, 'leaderboard.hide_team', {'team_id': team_id})
    return {'ok': True}


@api_router.post('/leaderboards/show-team/{team_id}', dependencies=[Depends(require_capability('leaderboard:admin'))])
def show_team(team_id: str, admin=Depends(get_current_user)):
    store.hidden_teams.discard(team_id)
    store.audit(admin.id, 'leaderboard.show_team', {'team_id': team_id})
    return {'ok': True}


@api_router.get('/leaderboards/export/{fmt}')
def export_board(fmt: str, mode: str = 'individual', user=Depends(get_current_user)):
    if mode == 'individual':
        rows = build_individual_board(store)
    elif mode == 'teams':
        rows = build_team_board(store)
    elif mode == 'categories':
        rows = build_category_board(store)
    elif mode == 'orgs':
        rows = build_org_board(store)
    else:
        raise HTTPException(status_code=400, detail='Invalid mode')

    secret = settings.jwt_secret
    if fmt == 'csv':
        payload, signature = export_csv_signed(rows, secret)
    elif fmt == 'pdf':
        payload, signature = export_pdf_signed(rows, secret)
    else:
        raise HTTPException(status_code=400, detail='Invalid format')

    store.audit(user.id, 'leaderboard.export', {'format': fmt, 'mode': mode})
    return {'payload': payload, 'signature': signature}


class IntegrityIn(BaseModel):
    payload: str
    signature: str


@api_router.post('/leaderboards/integrity/verify')
def integrity_verify(payload: IntegrityIn, user=Depends(get_current_user)):
    ok = verify_integrity(payload.payload, payload.signature, settings.jwt_secret)
    return {'valid': ok}


@api_router.get('/leaderboards/analytics/progression/{user_id}')
def analytics_progression(user_id: str, user=Depends(get_current_user)):
    return {'points': score_progression(store, user_id)}


@api_router.get('/leaderboards/analytics/solve-velocity')
def analytics_velocity(user=Depends(get_current_user)):
    return {'series': solve_velocity(store)}


@api_router.get('/leaderboards/analytics/category-dominance')
def analytics_category(user=Depends(get_current_user)):
    return {'items': category_dominance(store)}


@api_router.get('/gamification/me')
def gamification_me(user=Depends(get_current_user)):
    return {
        'xp': user.xp,
        'badges': sorted(user.badges),
        'achievements': sorted(user.achievements),
        'streak_days': user.streak_days,
        'trophies': user.trophies,
    }


def _update_gamification_for_solve(user, points: int, first_blood: bool) -> None:
    user.xp += max(points // 10, 5)
    user.streak_days = max(1, user.streak_days)
    if first_blood:
        user.trophies.append('first-blood')
    if user.xp >= 100 and 'xp-100' not in user.badges:
        user.badges.add('xp-100')
    if user.xp >= 500 and 'xp-500' not in user.badges:
        user.badges.add('xp-500')
    if user.xp >= 1000:
        user.achievements.add('veteran')


@api_router.get('/spectator/dashboard')
def spectator_dashboard(limit: int = 20):
    return {
        'live_solves': recent_feed(limit),
        'first_bloods': list(recent_feed(5)),
        'overlay_url': '/api/v1/spectator/overlay',
        'big_screen': {'theme': 'dark', 'refresh_s': 5},
    }


@api_router.get('/spectator/overlay')
def spectator_overlay():
    top = build_individual_board(store)[:5]
    return {'top': top, 'live_feed': recent_feed(10)}


@api_router.websocket('/ws/spectator')
async def spectator_ws(websocket: WebSocket):
    await connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:  # noqa: BLE001
        await disconnect(websocket)


@api_router.get('/status', tags=['system'])
def status_route() -> dict[str, str]:
    return {'service': 'cerberus', 'state': 'ready'}
