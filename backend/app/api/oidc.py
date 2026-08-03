"""OIDC configuration, the authorization-code login flow, and account linking.

(docs/ARCHIVE.md §5 and §14, 2026-08-02 — OIDC account linking.)

Two routers live here:

- ``config_router`` (``/oidc``): admin-only CRUD for the singleton OIDC provider
  configuration. The client secret is write-only and field-encrypted.
- ``login_router`` (``/auth/oidc``): the public ``login`` → ``callback`` flow,
  plus the authenticated ``link`` surface. ``login`` records per-request
  ``state``/``nonce``/PKCE in ``oidc_login_flows`` and redirects to the provider;
  ``callback`` validates the response and then branches on the flow's
  ``purpose``.

Local and OIDC auth run concurrently — enabling OIDC never disables local login.

**Account linking.** An existing local account (above all the first admin) has no
way to acquire an OIDC identity from the login path alone: with auto-provision on
its owner's first OIDC sign-in mints a *duplicate* account, and with it off the
sign-in dead-ends at ``not_provisioned``. The only other option was to determine
the subject by hand at the IdP and write it into ``oidc_identities`` directly —
impossible on Authentik's default hashed subject mode and on Entra ID's pairwise
subjects, where the value exists only inside tokens issued to this client. So
``POST /auth/oidc/link`` runs the *same* handshake while authenticated and binds
the ``(issuer, sub)`` of the verified ID token to the caller's own account.

The security posture of that second terminal action, in one place:

- **The subject is never named by a caller.** It is read only from ``claims["sub"]``
  of a token that passed :func:`app.auth.oidc.verify_id_token`. No request field,
  header, or query parameter carries a subject anywhere in this module, and the
  link-status view never returns one either.
- **The callback demands the session back.** A ``link`` flow completes only when a
  live cookie session's user matches the ``user_id`` captured server-side at
  start; anything else fails closed after the one-time flow row is consumed.
- **Linking is insert-only.** An ``(issuer, subject)`` already bound to some other
  account is refused explicitly, never re-pointed.
- **The link callback mints nothing.** No session, no role assignment, no group
  sync, no auto-provisioning — one identity row and one audit row.
- **A session alone is not enough.** Link and unlink both require fresh full
  re-authentication (see :mod:`app.auth.reauth`), which is what bounds the
  L2/SEC-8 widening linking introduces.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.schemas import PASSWORD_MAX_LENGTH
from app.auth import oidc, service
from app.auth.cookies import session_cookie_would_be_dropped, set_session_cookies
from app.auth.deps import (
    AuthContext,
    client_ip,
    get_optional_auth,
    require_auth,
    require_csrf,
    require_role,
)
from app.auth.passwords import hash_password
from app.auth.reauth import enforce_auth_rate_limit, require_fresh_auth
from app.core.app_settings import MfaPolicy, SettingsService
from app.core.audit import record_audit
from app.core.config import get_settings
from app.core.crypto import SecretDecryptError
from app.core.masking import MaskedSecret, masked_secret
from app.core.secret_store import AAD_OIDC_CLIENT_SECRET, decrypt_secret, encrypt_secret
from app.core.timeutil import utcnow
from app.db.models import (
    FLOW_PURPOSE_LINK,
    FLOW_PURPOSE_LOGIN,
    OIDC_CONFIG_ID,
    OidcConfig,
    OidcIdentity,
    OidcLoginFlow,
    Role,
    User,
)
from app.db.session import get_db

logger = logging.getLogger(__name__)

config_router = APIRouter(prefix="/oidc", tags=["oidc"])
login_router = APIRouter(prefix="/auth/oidc", tags=["oidc"])

_admin = require_role(Role.ADMIN)

#: Login-screen path the callback redirects to on failure (with an error code).
_LOGIN_PATH = "/login"
#: Fixed in-app path a completed **link** flow returns the browser to. Fixed on
#: purpose: no ``return_to`` parameter exists anywhere in the flow, so linking
#: adds no open-redirect surface (A9).
_LINK_RESULT_PATH = "/settings"
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
            config.client_secret_ciphertext = encrypt_secret(
                secret, aad=AAD_OIDC_CLIENT_SECRET, row_id=config.id
            )
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


def _link_result(param: str, value: str) -> RedirectResponse:
    """Redirect the browser back to Settings with a link-flow outcome code.

    ``param`` is ``oidc_link`` on success or ``oidc_link_error`` on failure. The
    path is a compile-time constant — the flow accepts no caller-supplied
    destination at any point.
    """
    return RedirectResponse(
        f"{_LINK_RESULT_PATH}?{param}={value}", status_code=status.HTTP_302_FOUND
    )


def _link_failed(reason: str) -> RedirectResponse:
    """Redirect the browser back to Settings with a link-flow error code."""
    return _link_result("oidc_link_error", reason)


def _purge_stale_flows(db: Session) -> None:
    """Delete flow rows older than the flow TTL (login and link alike)."""
    cutoff = utcnow() - _FLOW_TTL
    for row in db.scalars(select(OidcLoginFlow).where(OidcLoginFlow.created_at < cutoff)):
        db.delete(row)


def _usable_config(db: Session) -> OidcConfig | None:
    """Return the OIDC config only if it is enabled and fully configured."""
    config = db.get(OidcConfig, OIDC_CONFIG_ID)
    if config is None or not config.enabled or not config.issuer or not config.client_id:
        return None
    return config


async def _begin_flow(
    request: Request,
    db: Session,
    config: OidcConfig,
    *,
    purpose: str,
    user_id: int | None,
) -> tuple[str, str]:
    """Create a flow row and return ``(authorization_url, binding_token)``.

    Shared by the login and link starts so both get the identical hardening —
    one-time ``state``, server-side ``nonce``, PKCE ``S256`` verifier, the
    server-derived ``redirect_uri``, the browser binding, and the stale-row
    purge. Only ``purpose`` and ``user_id`` differ between them, and ``user_id``
    comes from the caller's *session*, never from request input (A1).

    Raises:
        oidc.OidcError: If provider discovery fails.
    """
    metadata = await oidc.discover(config.issuer)

    _purge_stale_flows(db)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = oidc.generate_pkce_pair()
    redirect_uri = str(request.url_for("oidc_callback"))
    # Bind the flow to this browser: a random token goes in an HttpOnly cookie and
    # only its hash is stored on the flow, so the callback (which SameSite=Lax
    # allows the cookie on) must come from the same browser that started the flow.
    binding = secrets.token_urlsafe(32)
    db.add(
        OidcLoginFlow(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            redirect_uri=redirect_uri,
            browser_binding=_hash_binding(binding),
            purpose=purpose,
            user_id=user_id,
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
    return url, binding


def _set_binding_cookie(response: Response, binding: str) -> None:
    """Attach the per-flow browser-binding cookie to ``response``."""
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


@login_router.get("/login")
async def oidc_login(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    """Start the OIDC login: create a flow and redirect to the provider."""
    if session_cookie_would_be_dropped(request):
        # Both the flow-binding cookie and the session cookie this handshake ends
        # in are Secure; over plain HTTP the browser drops them and the round trip
        # fails at the callback with a misleading "expired" error. Refuse up front.
        logger.error(
            "OIDC sign-in refused because HTTPS enforcement cannot be satisfied: this "
            "request arrived over %s and the flow-binding and session cookies are marked "
            "Secure, so the browser would discard them. This is NOT an identity-provider "
            "or credential problem. Serve Scrye over HTTPS, or have your TLS-terminating "
            "proxy send X-Forwarded-Proto: https with SCRYE_FORWARDED_ALLOW_IPS set to the "
            "address it connects from, or opt out with SCRYE_SESSION_COOKIE_SECURE=false.",
            request.url.scheme,
        )
        return _fail("insecure_transport")

    config = _usable_config(db)
    if config is None:
        return _fail("disabled")

    try:
        url, binding = await _begin_flow(
            request, db, config, purpose=FLOW_PURPOSE_LOGIN, user_id=None
        )
    except oidc.OidcError:
        logger.warning("OIDC discovery failed during login start.")
        return _fail("discovery")

    response = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
    _set_binding_cookie(response, binding)
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


class _CallbackError(Exception):
    """Internal signal carrying the query-param error code to redirect with."""

    def __init__(self, reason: str) -> None:
        """Store the redirect error code (``oidc_error`` / ``oidc_link_error``)."""
        super().__init__(reason)
        self.reason = reason


async def _verified_claims(
    config: OidcConfig,
    *,
    code: str,
    redirect_uri: str,
    nonce: str,
    verifier: str,
) -> dict:
    """Exchange the authorization code and return the **verified** ID-token claims.

    Identical for login and link flows: this is the single place a subject ever
    enters the system, and it does so only after
    :func:`app.auth.oidc.verify_id_token` has checked the JWKS signature over an
    explicit algorithm allowlist (``none`` stripped even if advertised), ``iss``
    against the discovered issuer, ``aud`` against our client ID, ``exp`` with
    leeway, the per-flow ``nonce``, and the presence of ``sub``.

    The ID token and access token live only in this frame; nothing token-shaped
    is persisted or logged (A12).

    Raises:
        _CallbackError: With ``config`` when the stored client secret cannot be
            decrypted, or ``validation`` when discovery, the code exchange, or
            token verification fails.
    """
    client_secret: str | None = None
    if config.client_secret_ciphertext:
        try:
            client_secret = decrypt_secret(
                config.client_secret_ciphertext, aad=AAD_OIDC_CLIENT_SECRET, row_id=config.id
            )
        except SecretDecryptError:
            raise _CallbackError("config") from None

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
        return await oidc.verify_id_token(
            metadata, tokens["id_token"], client_id=config.client_id, nonce=nonce
        )
    except oidc.OidcError:
        logger.warning("OIDC callback validation failed.")
        raise _CallbackError("validation") from None


@login_router.get("/callback", name="oidc_callback")
async def oidc_callback(
    request: Request,
    db: Session = Depends(get_db),
    state: str | None = None,
    code: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Handle the provider redirect, then branch on the flow's ``purpose``.

    Everything up to and including ID-token verification is shared: one-time
    ``state``, browser binding, PKCE, nonce. Only the terminal action differs —
    ``login`` links-or-provisions and starts a session; ``link`` binds the
    verified subject to the account that started the flow and starts nothing.

    Both purposes use this one registered redirect URI deliberately; a separate
    ``/link/callback`` would make every operator register a second URI at their
    IdP, and providers that enforce exact registration would reject it until
    they did.
    """
    if not state:
        return _fail("provider" if error else "invalid_response")

    _purge_stale_flows(db)
    flow = db.get(OidcLoginFlow, state)
    if flow is None:
        return _fail("expired")

    # The flow row is authoritative for what this callback is allowed to do: the
    # purpose and (for link flows) the owning account were written server-side at
    # start and are never re-read from the request.
    purpose = flow.purpose or FLOW_PURPOSE_LOGIN
    flow_user_id = flow.user_id
    fail = _link_failed if purpose == FLOW_PURPOSE_LINK else _fail

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
        failure = fail("expired")
        failure.delete_cookie(cookie_name, path=cookie_path)
        return failure
    if error:
        return fail("provider")
    if not code:
        return fail("invalid_response")

    config = _usable_config(db)
    if config is None:
        return fail("disabled")

    try:
        claims = await _verified_claims(
            config, code=code, redirect_uri=redirect_uri, nonce=nonce, verifier=verifier
        )
    except _CallbackError as exc:
        return fail(exc.reason)

    if purpose == FLOW_PURPOSE_LINK:
        response = _complete_link(request, db, config, claims, flow_user_id=flow_user_id)
        response.delete_cookie(cookie_name, path=cookie_path)
        return response

    return _complete_oidc_login(request, db, config, claims, binding_cookie_path=cookie_path)


def _complete_link(
    request: Request,
    db: Session,
    config: OidcConfig,
    claims: dict,
    *,
    flow_user_id: int | None,
) -> RedirectResponse:
    """Bind the verified subject to the account that started this link flow.

    This is the whole terminal action for ``purpose='link'``: at most one
    ``oidc_identities`` INSERT plus one audit row. It deliberately does **not**
    create a session, assign a role, run group sync, or auto-provision anything —
    role logic stays exclusively on the login path with its existing guards (A8).

    Fails closed, in order:

    - **A2** — no live cookie session, or a session belonging to a different
      user than the one captured at start. The flow row is already consumed by
      the time we get here, so a rejected callback cannot be retried.
    - **A7** — the ``(issuer, subject)`` already belongs to another account. The
      binding is insert-only; an in-use identity is never re-pointed. Re-linking
      your *own* already-linked identity is a no-op success.
    - The caller already holds a *different* subject for this issuer. Refused
      rather than silently accumulating a second identity, so the stale-link
      runbook (unlink, then re-link) has one unambiguous shape.
    """
    auth = get_optional_auth(request, db)
    ip = client_ip(request)
    subject = str(claims["sub"])
    issuer = str(claims.get("iss") or config.issuer)

    # A2: the completing browser must still hold a session for the *same* account
    # the flow was started under. Bearer-token auth is rejected too (session is
    # None): a link flow is inherently browser-driven.
    if auth is None or auth.session is None or flow_user_id is None or auth.user.id != flow_user_id:
        logger.warning(
            "OIDC link callback rejected: session does not match the account that "
            "started the flow (flow user_id=%s).",
            flow_user_id,
        )
        record_audit(
            db,
            action="auth.oidc_link_denied",
            actor=auth.user if auth is not None else None,
            ip=ip,
            details={"reason": "session_mismatch", "flow_user_id": flow_user_id},
        )
        db.commit()
        return _link_failed("session_mismatch")

    user = auth.user
    existing = db.scalar(
        select(OidcIdentity).where(OidcIdentity.issuer == issuer, OidcIdentity.subject == subject)
    )
    if existing is not None:
        if existing.user_id == user.id:
            return _link_result("oidc_link", "unchanged")  # idempotent re-link
        # A7: never re-point an in-use identity at a second account.
        logger.warning(
            "OIDC link refused: identity %s is already linked to another account.", existing.id
        )
        record_audit(
            db,
            action="auth.oidc_link_denied",
            actor=user,
            ip=ip,
            target_type="oidc_identity",
            target_id=str(existing.id),
            details={"reason": "identity_in_use", "issuer": issuer},
        )
        db.commit()
        return _link_failed("identity_in_use")

    held = db.scalar(
        select(OidcIdentity).where(OidcIdentity.user_id == user.id, OidcIdentity.issuer == issuer)
    )
    if held is not None:
        record_audit(
            db,
            action="auth.oidc_link_denied",
            actor=user,
            ip=ip,
            target_type="oidc_identity",
            target_id=str(held.id),
            details={"reason": "issuer_already_linked", "issuer": issuer},
        )
        db.commit()
        return _link_failed("issuer_already_linked")

    email = claims.get(config.email_claim)
    identity = OidcIdentity(
        user_id=user.id,
        issuer=issuer,
        subject=subject,
        email=str(email) if email else None,
    )
    db.add(identity)
    db.flush()
    # Metadata only — the subject is an opaque identifier and never lands in the
    # audit details or the logs; the row id is what an operator needs anyway.
    record_audit(
        db,
        action="auth.oidc_identity_linked",
        actor=user,
        ip=ip,
        target_type="oidc_identity",
        target_id=str(identity.id),
        details={"issuer": issuer},
    )
    db.commit()
    logger.info("OIDC identity linked to user %s (issuer %s).", user.id, issuer)
    return _link_result("oidc_link", "success")


def _stale_link_match(
    db: Session, config: OidcConfig, claims: dict, *, issuer: str, subject: str
) -> tuple[OidcIdentity, str] | None:
    """Detect a token whose subject changed out from under an existing link.

    A link row is a claim that ``(issuer, sub)`` keeps identifying the same
    person; the IdP can silently break it. An account deleted and recreated gets
    a fresh subject, and flipping Authentik's provider *subject mode* re-keys
    **every** user at once with no warning. The stale row still renders as
    "Linked", so without a distinct signal the next sign-in either mints a
    duplicate account (auto-provision on) or dead-ends at ``not_provisioned`` —
    exactly the bug linking exists to eliminate, with the settings screen
    insisting everything is fine.

    So, on the no-identity branch only, check whether this token's configured
    username/email claims match an account that **already holds a link for this
    issuer under a different subject**.

    This is a **refuse-and-explain heuristic and never a binding**: the caller
    returns ``None`` or an error, never an identity to write. Claim-based
    *binding* is the account-takeover vector deliberately rejected for
    email-match auto-linking, and it stays rejected here. The worst an attacker
    who sets their IdP email to an admin's can extract is a fail-closed error
    instead of a provisioned viewer account — strictly safer than the status quo.

    Returns:
        ``(identity, matched_by)`` for the stale link, or ``None``.
    """
    raw_username = claims.get(config.username_claim)
    username = str(raw_username).strip().lower() if raw_username else None
    raw_email = claims.get(config.email_claim)
    email = str(raw_email).strip().lower() if raw_email else None
    if not username and not email:
        return None

    candidates = db.scalars(
        select(OidcIdentity).where(OidcIdentity.issuer == issuer, OidcIdentity.subject != subject)
    )
    for identity in candidates:
        if email and identity.email and identity.email.strip().lower() == email:
            return identity, "email"
        user = db.get(User, identity.user_id)
        if user is not None and username and user.username.lower() == username:
            return identity, "username"
    return None


def _complete_oidc_login(
    request: Request,
    db: Session,
    config: OidcConfig,
    claims: dict,
    *,
    binding_cookie_path: str,
) -> RedirectResponse:
    """Link-or-provision the account for a verified login token and start a session."""
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
        # §7 stale-link detection, ahead of both the provision and dead-end
        # branches: if this issuer already links an account the token's claims
        # match, the IdP re-keyed the subject rather than sending us a new
        # person. Refuse with a distinct, audited error instead of quietly
        # minting a duplicate account or emitting a generic "not provisioned" —
        # and never rebind, which would be claim-based binding by another name.
        stale = _stale_link_match(db, config, claims, issuer=issuer, subject=subject)
        if stale is not None:
            stale_identity, matched_by = stale
            logger.warning(
                "OIDC sign-in refused: the identity provider presented a new subject for "
                "issuer %s, but this account already holds link row %s for that issuer "
                "(matched on %s). The stored link is stale — the IdP account was most "
                "likely deleted and recreated, or the provider's subject mode changed. "
                "Sign in locally, unlink, then re-link; see the README re-link runbook.",
                issuer,
                stale_identity.id,
                matched_by,
            )
            record_audit(
                db,
                action="auth.oidc_identity_stale",
                actor=db.get(User, stale_identity.user_id),
                ip=client_ip(request),
                target_type="oidc_identity",
                target_id=str(stale_identity.id),
                details={
                    "issuer": issuer,
                    "linked_identity_id": stale_identity.id,
                    "matched_by": matched_by,
                },
            )
            db.commit()
            return _fail("identity_stale")
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
    # require MFA for OIDC users must enforce it at the IdP. See docs/ARCHIVE.md
    # § Deviations (2026-07-04 post-P6 hotfix) and the README security model.
    token, session = service.create_session(
        db, user, ip=client_ip(request), user_agent=request.headers.get("user-agent")
    )
    user.last_login_at = session.created_at
    # Observability for the accepted limitation above (SEC-8): if a mandatory-MFA
    # policy would require a second factor for this role on local login, record on
    # the OIDC login that the second factor was delegated to the IdP — so an
    # operator running mandatory MFA can audit which logins bypassed the local
    # policy and confirm the IdP enforces MFA. Auth behavior is unchanged.
    #
    # Linking widened the population this covers: it used to be reachable only by
    # OIDC-*provisioned* accounts (no usable local password, no local TOTP — so
    # nothing to bypass). A **linked** account can be an MFA-enrolled admin whose
    # local TOTP challenge simply never runs on this path. Hence the fresh
    # full re-auth gate on link/unlink, and this marker mattering more, not less.
    mfa_delegated = _mfa_delegation_applies(db, user)
    record_audit(
        db,
        action="auth.oidc_login",
        actor=user,
        ip=client_ip(request),
        details={"mfa_delegated_to_idp": True} if mfa_delegated else None,
    )
    db.commit()

    response = RedirectResponse("/", status_code=status.HTTP_302_FOUND)
    set_session_cookies(response, token, session.csrf_token)
    response.delete_cookie(_binding_cookie()[0], path=binding_cookie_path)
    return response


def _mfa_delegation_applies(db: Session, user: User) -> bool:
    """Return True when a mandatory-MFA policy would apply to ``user`` locally.

    On the login path this drives the ``mfa_delegated_to_idp`` audit marker; on
    the link path it drives the warning shown before a user creates a login path
    on which their local second factor will not be challenged.
    """
    policy = SettingsService(db).auth().mfa_policy
    return policy is MfaPolicy.REQUIRED_ALL or (
        policy is MfaPolicy.REQUIRED_ADMIN and user.role is Role.ADMIN
    )


# ---------------------------------------------------------------------------
# Account linking (docs/ARCHIVE.md §14, 2026-08-02)
# ---------------------------------------------------------------------------


class OidcLinkStatusOut(BaseModel):
    """The caller's own OIDC link state, plus what the UI needs to act on it.

    Deliberately carries **no subject**. The whole premise of this feature is
    that subjects are opaque values an operator cannot look up or compare, so
    displaying one would be noise at best; and keeping it out of every response
    keeps "the subject only ever comes from a verified ID token" true on the read
    side as well as the write side.
    """

    linked: bool
    issuer: str | None = None
    email: str | None = None
    linked_at: datetime | None = None
    #: When this identity was last used to sign in — ``None`` if it never has.
    #: A link that has not been used since the IdP was reconfigured is the one
    #: hint available that it may have gone stale (see the re-link runbook).
    last_login_at: datetime | None = None
    #: True when OIDC is enabled and fully configured, i.e. a link can be started.
    provider_ready: bool
    display_name: str
    #: True when the caller has TOTP active, so the re-auth form must ask for a code.
    mfa_enrolled: bool
    #: True when linking would create a login path that skips a second factor the
    #: caller otherwise has (enrolled TOTP, or a mandatory policy for their role).
    #: Drives the L2/SEC-8 warning shown before the handshake starts.
    mfa_delegation_warning: bool


class OidcLinkStartIn(BaseModel):
    """Fresh full re-authentication for starting a link (no subject field, by design)."""

    current_password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    #: Required only when the account has TOTP active.
    totp_code: str | None = Field(default=None, max_length=16)


class OidcLinkStartOut(BaseModel):
    """Where the browser must navigate to complete the link handshake."""

    authorization_url: str


class OidcUnlinkIn(OidcLinkStartIn):
    """Fresh full re-authentication for removing the caller's own link."""


def _require_browser_session(auth: AuthContext) -> None:
    """Refuse API-token callers on the link surface.

    Linking is a browser round trip: the start hands back an authorization URL to
    navigate to, and the callback is completed by the browser carrying the
    binding cookie *and* a session for the same account. A bearer token can start
    such a flow but can never finish one, so refusing here turns a confusing
    dead-end into a clear error. It also keeps every link/unlink call inside the
    CSRF-protected cookie surface rather than the CSRF-exempt token surface.
    """
    if auth.session is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="Linking an OIDC identity requires a browser session, not an API token.",
        )


def _own_identity(db: Session, user: User) -> OidcIdentity | None:
    """Return the caller's linked identity, if any."""
    return db.scalar(
        select(OidcIdentity)
        .where(OidcIdentity.user_id == user.id)
        .order_by(OidcIdentity.created_at.desc())
    )


@login_router.get("/link", response_model=OidcLinkStatusOut)
def oidc_link_status(
    auth: AuthContext = Depends(require_auth),
    db: Session = Depends(get_db),
) -> OidcLinkStatusOut:
    """Report the caller's own OIDC link state (never anyone else's)."""
    config = db.get(OidcConfig, OIDC_CONFIG_ID)
    identity = _own_identity(db, auth.user)
    ready = _usable_config(db) is not None
    return OidcLinkStatusOut(
        linked=identity is not None,
        issuer=identity.issuer if identity else None,
        email=identity.email if identity else None,
        linked_at=identity.created_at if identity else None,
        last_login_at=identity.last_login_at if identity else None,
        provider_ready=ready,
        display_name=config.display_name if config else "OIDC",
        mfa_enrolled=auth.user.mfa_enabled,
        mfa_delegation_warning=auth.user.mfa_enabled or _mfa_delegation_applies(db, auth.user),
    )


@login_router.post("/link", response_model=OidcLinkStartOut)
async def oidc_link_start(
    payload: OidcLinkStartIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> Response:
    """Start a link flow for the **caller's own** account and return where to go.

    A POST, not the GET the public login start uses, and that difference is
    deliberate: login binds no identity, so a cross-site request that starts one
    achieves nothing; a link *does* bind an identity, so the start sits behind
    ``require_csrf`` and cannot be initiated from an attacker's page (A3).

    Gates, in order — each one fails the request outright:

    1. An authenticated **cookie session** (A1: no session, no flow; and the
       flow's owner is read from that session, never from the payload).
    2. The CSRF double-submit token (A3).
    3. The shared per-IP auth rate limiter (A10), so this surface is no cheaper
       to brute-force than ``/auth/login``.
    4. Transport that can actually keep the ``Secure`` cookies this flow needs
       (A11).
    5. **Fresh full re-authentication** — current password, plus a current TOTP
       code when enrolled. This is the control that bounds the L2/SEC-8 widening:
       a stolen session alone can never create a new login path for the account.

    Only then is a ``purpose='link'`` flow row written and an authorization URL
    handed back for the browser to navigate to.
    """
    _require_browser_session(auth)
    enforce_auth_rate_limit(request)
    if session_cookie_would_be_dropped(request):
        logger.error(
            "OIDC link refused because HTTPS enforcement cannot be satisfied: this request "
            "arrived over %s and the flow-binding cookie is marked Secure, so the browser "
            "would discard it and the callback would fail as 'expired'. Serve Scrye over "
            "HTTPS, or have your TLS-terminating proxy send X-Forwarded-Proto: https with "
            "SCRYE_FORWARDED_ALLOW_IPS set to the address it connects from.",
            request.url.scheme,
        )
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Linking an OIDC identity requires HTTPS on this deployment.",
        )

    config = _usable_config(db)
    if config is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="OIDC is not enabled and fully configured on this instance.",
        )

    require_fresh_auth(
        db,
        auth.user,
        password=payload.current_password,
        totp_code=payload.totp_code,
        ip=client_ip(request),
        operation="oidc_link",
    )

    try:
        url, binding = await _begin_flow(
            request,
            db,
            config,
            purpose=FLOW_PURPOSE_LINK,
            # Captured from the *session*, never from request input (A1/A6).
            user_id=auth.user.id,
        )
    except oidc.OidcError:
        logger.warning("OIDC discovery failed during link start.")
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            detail="Could not reach the identity provider.",
        ) from None

    response: Response = JSONResponse(
        OidcLinkStartOut(authorization_url=url).model_dump(),
        status_code=status.HTTP_200_OK,
    )
    _set_binding_cookie(response, binding)
    return response


@login_router.delete("/link", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def oidc_unlink(
    payload: OidcUnlinkIn,
    request: Request,
    auth: AuthContext = Depends(require_csrf),
    db: Session = Depends(get_db),
) -> None:
    """Remove the caller's **own** OIDC identity, behind the same fresh-auth gate.

    Unlinking is gated exactly like linking, for the mirror-image reason: link
    creates a login path, unlink destroys one, and neither should be reachable
    from a stolen session alone.

    **Stranding guard.** An account must retain a way in. Two checks cover that,
    and between them an account can never unlink its way to no login path:

    - *Local login disabled instance-wide.* Then the OIDC link is the caller's
      only route in and removing it locks them out — refused with an explanation
      rather than a 403 they would misread as a typo.
    - *No usable local password.* An OIDC-provisioned account holds a random
      argon2 hash nobody knows (see the provisioning branch above), so it cannot
      satisfy the fresh-password gate and is refused there by construction. That
      is the guard, not an accident of it: there is no separate "unusable
      password" flag on ``users`` to test, and adding one was outside the
      sanctioned schema change for this feature.
    """
    _require_browser_session(auth)
    enforce_auth_rate_limit(request)

    identity = _own_identity(db, auth.user)
    if identity is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, detail="No OIDC identity is linked to your account."
        )

    if not SettingsService(db).auth().local_login_enabled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=(
                "Local login is disabled on this instance, so unlinking would leave your "
                "account with no way to sign in. Re-enable local login first."
            ),
        )

    require_fresh_auth(
        db,
        auth.user,
        password=payload.current_password,
        totp_code=payload.totp_code,
        ip=client_ip(request),
        operation="oidc_unlink",
    )

    identity_id = identity.id
    issuer = identity.issuer
    db.delete(identity)
    record_audit(
        db,
        action="auth.oidc_identity_unlinked",
        actor=auth.user,
        ip=client_ip(request),
        target_type="oidc_identity",
        target_id=str(identity_id),
        details={"issuer": issuer},
    )
    db.commit()
    logger.info("OIDC identity %s unlinked from user %s.", identity_id, auth.user.id)
