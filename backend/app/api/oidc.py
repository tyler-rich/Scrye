"""OIDC configuration and the authorization-code login flow (docs/PLAN.md §5).

Two routers live here:

- ``config_router`` (``/oidc``): admin-only CRUD for the singleton OIDC provider
  configuration. The client secret is write-only and field-encrypted.
- ``login_router`` (``/auth/oidc``): the public ``login`` → ``callback`` flow.
  ``login`` records per-request ``state``/``nonce``/PKCE in ``oidc_login_flows``
  and redirects to the provider; ``callback`` validates the response, links or
  auto-provisions a local account, and starts a normal session.

Local and OIDC auth run concurrently — enabling OIDC never disables local login.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import oidc, service
from app.auth.cookies import set_session_cookies
from app.auth.deps import AuthContext, client_ip, require_csrf, require_role
from app.auth.passwords import hash_password
from app.core.audit import record_audit
from app.core.config import get_settings
from app.core.crypto import SecretDecryptError
from app.core.masking import MaskedSecret, masked_secret
from app.core.secret_store import AAD_OIDC_CLIENT_SECRET, decrypt_secret, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import OIDC_CONFIG_ID, OidcConfig, OidcIdentity, OidcLoginFlow, Role, User
from app.db.session import get_db

logger = logging.getLogger(__name__)

config_router = APIRouter(prefix="/oidc", tags=["oidc"])
login_router = APIRouter(prefix="/auth/oidc", tags=["oidc"])

_admin = require_role(Role.ADMIN)

#: Login-screen path the callback redirects to on failure (with an error code).
_LOGIN_PATH = "/login"
#: How long an in-progress login flow row stays valid before being purged.
_FLOW_TTL = timedelta(minutes=10)
_USERNAME_SANITIZE = re.compile(r"[^a-z0-9._-]+")

#: Bare name of the per-flow browser-binding cookie (see OidcLoginFlow).
_BINDING_COOKIE_BARE = "scrye_oidc_binding"
#: ``__Host-`` prefixed variant. The prefix is browser-enforced: such a cookie
#: MUST be ``Secure``, have ``Path=/``, and carry NO ``Domain`` attribute, so a
#: sibling subdomain (e.g. another ``*.your-domain.tld`` host) can never
#: plant it for the parent domain — closing the cookie-fixation gap the plain
#: host cookie left open. Requires TLS, so it is only usable when the session
#: cookie is itself ``Secure``; over plain-HTTP dev we fall back to the bare name.
_BINDING_COOKIE_HOST = f"__Host-{_BINDING_COOKIE_BARE}"


def _binding_cookie() -> tuple[str, str, bool]:
    """Return ``(name, path, secure)`` for the browser-binding cookie.

    Uses a ``__Host-`` prefixed, root-path, ``Secure`` cookie in production
    (behind TLS) so no sibling subdomain can set it; falls back to a plain
    host cookie only when ``Secure`` is unavailable (local HTTP dev), where a
    ``__Host-`` cookie would be rejected by the browser outright.
    """
    secure = get_settings().session_cookie_secure
    if secure:
        # __Host- mandates Path=/ and Secure, and forbids Domain.
        return _BINDING_COOKIE_HOST, "/", True
    return _BINDING_COOKIE_BARE, "/api/auth/oidc", False


def _hash_binding(value: str) -> str:
    """Hash a browser-binding token for at-rest storage on the flow row."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OidcConfigOut(BaseModel):
    """Admin read view of the OIDC configuration (secret masked)."""

    model_config = ConfigDict(from_attributes=True)

    enabled: bool
    display_name: str
    issuer: str | None
    client_id: str | None
    client_secret: MaskedSecret
    scopes: str
    username_claim: str
    email_claim: str
    groups_claim: str | None
    admin_group: str | None
    auto_provision: bool
    default_role: Role
    callback_path: str = "/api/auth/oidc/callback"


class OidcConfigUpdateIn(BaseModel):
    """Admin payload to update the OIDC configuration (all fields optional)."""

    enabled: bool | None = None
    display_name: str | None = Field(default=None, min_length=1, max_length=64)
    issuer: str | None = Field(default=None, max_length=512)
    client_id: str | None = Field(default=None, max_length=255)
    client_secret: SecretStr | None = None
    scopes: str | None = Field(default=None, min_length=1, max_length=255)
    username_claim: str | None = Field(default=None, min_length=1, max_length=64)
    email_claim: str | None = Field(default=None, min_length=1, max_length=64)
    groups_claim: str | None = Field(default=None, max_length=64)
    admin_group: str | None = Field(default=None, max_length=128)
    auto_provision: bool | None = None
    default_role: Role | None = None


def _get_or_create_config(db: Session) -> OidcConfig:
    """Return the singleton OIDC config row, creating a default if absent."""
    config = db.get(OidcConfig, OIDC_CONFIG_ID)
    if config is None:
        config = OidcConfig(id=OIDC_CONFIG_ID)
        db.add(config)
        db.flush()
    return config


def _to_out(config: OidcConfig) -> OidcConfigOut:
    """Build the masked read view of the OIDC config."""
    return OidcConfigOut(
        enabled=config.enabled,
        display_name=config.display_name,
        issuer=config.issuer,
        client_id=config.client_id,
        client_secret=masked_secret(config.secret_updated_at),
        scopes=config.scopes,
        username_claim=config.username_claim,
        email_claim=config.email_claim,
        groups_claim=config.groups_claim,
        admin_group=config.admin_group,
        auto_provision=config.auto_provision,
        default_role=config.default_role,
    )


@config_router.get("/config", response_model=OidcConfigOut)
def get_oidc_config(
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> OidcConfigOut:
    """Return the OIDC provider configuration (admin; client secret masked)."""
    return _to_out(_get_or_create_config(db))


@config_router.put("/config", response_model=OidcConfigOut)
def update_oidc_config(
    payload: OidcConfigUpdateIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    _: AuthContext = Depends(_admin),
    db: Session = Depends(get_db),
) -> OidcConfigOut:
    """Update the OIDC configuration; omitting ``client_secret`` keeps the stored one."""
    config = _get_or_create_config(db)
    data = payload.model_dump(exclude_unset=True)

    if "client_secret" in data:
        secret = payload.client_secret.get_secret_value() if payload.client_secret else ""
        if secret:
            config.client_secret_ciphertext = encrypt_secret(secret, aad=AAD_OIDC_CLIENT_SECRET)
            config.secret_updated_at = utcnow()
        else:
            config.client_secret_ciphertext = None
            config.secret_updated_at = None
        data.pop("client_secret")

    for field_name, value in data.items():
        setattr(config, field_name, value)

    if config.enabled and (not config.issuer or not config.client_id):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="Issuer and client ID are required to enable OIDC.",
        )

    config.updated_by_username = auth.user.username
    record_audit(
        db,
        action="settings.oidc_updated",
        actor=auth.user,
        ip=client_ip(request),
        details={"enabled": config.enabled, "issuer": config.issuer},
    )
    db.commit()
    return _to_out(config)


def _fail(reason: str) -> RedirectResponse:
    """Redirect the browser back to the login screen with an error code."""
    return RedirectResponse(f"{_LOGIN_PATH}?oidc_error={reason}", status_code=status.HTTP_302_FOUND)


def _purge_stale_flows(db: Session) -> None:
    """Delete login-flow rows older than the flow TTL."""
    cutoff = utcnow() - _FLOW_TTL
    for row in db.scalars(select(OidcLoginFlow).where(OidcLoginFlow.created_at < cutoff)):
        db.delete(row)


@login_router.get("/login")
async def oidc_login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """Start the OIDC login: create a flow and redirect to the provider."""
    config = db.get(OidcConfig, OIDC_CONFIG_ID)
    if config is None or not config.enabled or not config.issuer or not config.client_id:
        return _fail("disabled")

    try:
        metadata = await oidc.discover(config.issuer)
    except oidc.OidcError:
        logger.warning("OIDC discovery failed during login start.")
        return _fail("discovery")

    _purge_stale_flows(db)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = oidc.generate_pkce_pair()
    redirect_uri = str(request.url_for("oidc_callback"))
    # Bind the flow to this browser: a random token goes in an HttpOnly cookie and
    # only its hash is stored on the flow, so the callback (which SameSite=Lax
    # allows the cookie on) must come from the same browser that started the login.
    binding = secrets.token_urlsafe(32)
    db.add(
        OidcLoginFlow(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
            browser_binding=_hash_binding(binding),
        )
    )
    db.commit()

    url = oidc.build_authorization_url(
        metadata,
        client_id=config.client_id,
        redirect_uri=redirect_uri,
        scopes=config.scopes,
        state=state,
        nonce=nonce,
        code_challenge=challenge,
    )
    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    cookie_name, cookie_path, cookie_secure = _binding_cookie()
    response.set_cookie(
        cookie_name,
        binding,
        max_age=int(_FLOW_TTL.total_seconds()),
        httponly=True,
        secure=cookie_secure,
        samesite="lax",
        path=cookie_path,
    )
    return response


def _sanitize_username(raw: str, subject: str) -> str:
    """Derive a valid local username from a claim value (fallback to subject)."""
    candidate = _USERNAME_SANITIZE.sub("-", (raw or "").strip().lower()).strip("-.")
    if len(candidate) < 3:
        candidate = f"oidc-{subject}".lower()
        candidate = _USERNAME_SANITIZE.sub("-", candidate).strip("-.")
    return candidate[:64]


def _unique_username(db: Session, base: str, subject: str) -> str:
    """Return a username not already taken (suffixing with the subject if needed)."""
    if service.get_user_by_username(db, base) is None:
        return base
    suffix = _USERNAME_SANITIZE.sub("", subject.lower())[:8] or secrets.token_hex(4)
    candidate = f"{base[:55]}-{suffix}"
    return candidate[:64]


def _groups_claim_present(config: OidcConfig, claims: dict) -> bool:
    """Return True if the configured groups claim is actually present in the token.

    Distinguishes "the IdP did not deliver groups in this token" (claim key
    absent — common, since many IdPs ship groups only via the UserInfo endpoint
    or behind a specific scope) from "the IdP delivered an explicit, possibly
    empty, group set". Only the latter is authoritative for role mapping.
    """
    return bool(config.groups_claim) and config.groups_claim in claims


def _resolve_role(config: OidcConfig, claims: dict) -> Role:
    """Pick the role for a *newly provisioned* user from the admin-group mapping.

    When group mapping isn't configured or the groups claim is absent, this
    falls back to ``default_role`` — safe for a brand-new account (it grants the
    least privilege), but never used to *change* an existing user's role (see
    :func:`_synced_role`, which preserves the current role on an absent claim).
    """
    if config.admin_group and _groups_claim_present(config, claims):
        groups = claims.get(config.groups_claim) or []
        if isinstance(groups, str):
            groups = [groups]
        if config.admin_group in groups:
            return Role.ADMIN
    return config.default_role


def _synced_role(config: OidcConfig, claims: dict) -> Role | None:
    """Return the role an *existing* user should be synced to, or None to preserve.

    Returns ``None`` — meaning "leave the user's current role untouched" — unless
    group→role mapping is configured AND the groups claim is present in this
    token. This prevents an IdP that simply omits groups from the ID token (e.g.
    it exposes them only via UserInfo) from silently demoting an established
    admin to ``default_role`` on their next login.
    """
    if not (config.admin_group and _groups_claim_present(config, claims)):
        return None
    groups = claims.get(config.groups_claim) or []
    if isinstance(groups, str):
        groups = [groups]
    return Role.ADMIN if config.admin_group in groups else config.default_role


def _other_active_admin_exists(db: Session, user: User) -> bool:
    """Return True if an active admin other than ``user`` exists.

    Used as a last-admin guard so an OIDC role sync can never leave the instance
    with zero administrators (a lockout that would require DB surgery to undo).
    """
    count = db.scalar(
        select(func.count())
        .select_from(User)
        .where(User.role == Role.ADMIN, User.is_active.is_(True), User.id != user.id)
    )
    return bool(count)


@login_router.get("/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    db: Session = Depends(get_db),
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Handle the provider redirect: validate, link/provision, start a session."""
    if error:
        return _fail("provider")
    if not state or not code:
        return _fail("invalid_response")

    _purge_stale_flows(db)
    flow = db.get(OidcLoginFlow, state)
    if flow is None:
        return _fail("expired")
    # Enforce the browser binding: the callback must carry the cookie set when the
    # flow was started, so a flow initiated in the attacker's browser cannot be
    # completed in the victim's (OIDC login-CSRF / session fixation).
    cookie_name, cookie_path, _ = _binding_cookie()
    binding_cookie = request.cookies.get(cookie_name)
    binding_ok = (
        bool(flow.browser_binding)
        and bool(binding_cookie)
        and hmac.compare_digest(flow.browser_binding, _hash_binding(binding_cookie or ""))
    )
    redirect_uri = flow.redirect_uri
    nonce = flow.nonce
    verifier = flow.code_verifier
    db.delete(flow)  # one-time use
    db.commit()
    if not binding_ok:
        logger.warning("OIDC callback rejected: browser binding missing or mismatched.")
        failure = _fail("expired")
        failure.delete_cookie(cookie_name, path=cookie_path)
        return failure

    config = db.get(OidcConfig, OIDC_CONFIG_ID)
    if config is None or not config.enabled or not config.issuer or not config.client_id:
        return _fail("disabled")

    client_secret: str | None = None
    if config.client_secret_ciphertext:
        try:
            client_secret = decrypt_secret(
                config.client_secret_ciphertext, aad=AAD_OIDC_CLIENT_SECRET
            )
        except SecretDecryptError:
            return _fail("config")

    try:
        metadata = await oidc.discover(config.issuer)
        tokens = await oidc.exchange_code(
            metadata,
            code=code,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
            client_id=config.client_id,
            client_secret=client_secret,
        )
        claims = await oidc.verify_id_token(
            metadata, tokens["id_token"], client_id=config.client_id, nonce=nonce
        )
    except oidc.OidcError:
        logger.warning("OIDC callback validation failed.")
        return _fail("validation")

    subject = str(claims["sub"])
    issuer = str(claims.get("iss") or config.issuer)
    email = claims.get(config.email_claim)
    identity = db.scalar(
        select(OidcIdentity).where(OidcIdentity.issuer == issuer, OidcIdentity.subject == subject)
    )

    if identity is not None:
        user = db.get(User, identity.user_id)
        if user is None or not user.is_active:
            return _fail("inactive")
        identity.last_login_at = utcnow()
        if email:
            identity.email = str(email)
        # Keep the IdP authoritative for role when group mapping is configured:
        # re-apply the group→role mapping on every login so removing a user from
        # the admin group at the IdP downgrades them here too, instead of leaving
        # a stale admin. `_synced_role` returns None when the groups claim is
        # absent from *this* token, in which case we preserve the current role
        # rather than demoting on a claim the IdP simply did not include here.
        mapped_role = _synced_role(config, claims)
        if mapped_role is not None and user.role != mapped_role:
            demoting_admin = user.role is Role.ADMIN and mapped_role is not Role.ADMIN
            if demoting_admin and not _other_active_admin_exists(db, user):
                # Last-admin guard: never let an OIDC sync remove the final admin
                # (which would lock everyone out of settings/user management).
                logger.warning(
                    "OIDC role sync skipped for user %s: refusing to demote the last admin.",
                    user.id,
                )
            else:
                record_audit(
                    db,
                    action="auth.oidc_role_synced",
                    actor=user,
                    ip=client_ip(request),
                    target_type="user",
                    target_id=str(user.id),
                    details={"from": user.role.value, "to": mapped_role.value},
                )
                user.role = mapped_role
    else:
        if not config.auto_provision:
            return _fail("not_provisioned")
        raw_username = str(claims.get(config.username_claim) or email or subject)
        username = _unique_username(db, _sanitize_username(raw_username, subject), subject)
        role = _resolve_role(config, claims)
        user = User(
            username=username,
            password_hash=hash_password(secrets.token_urlsafe(32)),  # no usable local password
            role=role,
            is_active=True,
        )
        db.add(user)
        db.flush()
        db.add(
            OidcIdentity(
                user_id=user.id,
                issuer=issuer,
                subject=subject,
                email=str(email) if email else None,
                last_login_at=utcnow(),
            )
        )
        record_audit(
            db,
            action="auth.oidc_provisioned",
            actor=user,
            ip=client_ip(request),
            target_type="user",
            target_id=str(user.id),
            details={"role": role.value},
        )

    # ACCEPTED LIMITATION — the mandatory-MFA policy (required_all /
    # required_admin) enforced on the local /auth/login path is intentionally
    # NOT applied here: MFA for OIDC logins is delegated to the identity
    # provider, which performs its own (often stronger) second-factor step
    # before issuing the ID token. Scrye has no local TOTP challenge in the OIDC
    # handshake, and provisioned OIDC accounts carry no usable local password,
    # so there is no second factor to enforce at this layer. Operators who
    # require MFA for OIDC users must enforce it at the IdP. See docs/PLAN.md
    # § Deviations (2026-07-04 post-P6 hotfix) and the README security model.
    token, session = service.create_session(
        db, user, ip=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    user.last_login_at = session.created_at
    record_audit(db, action="auth.oidc_login", actor=user, ip=client_ip(request))
    db.commit()

    response: Response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    set_session_cookies(response, token, session.csrf_token)
    response.delete_cookie(cookie_name, path=cookie_path)
    return response
