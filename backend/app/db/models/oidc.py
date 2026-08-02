"""OIDC configuration and identity models (docs/ARCHIVE.md §5).

Scrye supports generic OIDC (Authlib) alongside local auth. A single
:class:`OidcConfig` row holds the provider settings; the client secret is
**field-encrypted** and write-only like every other stored secret. Successful
logins are linked to a local account through :class:`OidcIdentity`, keyed by
``(issuer, subject)``. :class:`OidcLoginFlow` holds the short-lived per-login
state/nonce/PKCE so the authorization-code callback can be validated without a
server-side session middleware.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base
from app.db.models.user import Role

#: The fixed primary key of the singleton OIDC configuration row.
OIDC_CONFIG_ID = 1


class OidcConfig(Base):
    """Singleton OIDC provider configuration (id is always ``OIDC_CONFIG_ID``)."""

    __tablename__ = "oidc_config"

    id: Mapped[int] = mapped_column(primary_key=True)
    #: Master switch; when false the OIDC login path is disabled.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    #: Button label shown on the login screen (e.g. ``"Pocket ID"``).
    display_name: Mapped[str] = mapped_column(String(64), default="OIDC")
    #: OIDC issuer URL; discovery uses ``<issuer>/.well-known/openid-configuration``.
    issuer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Encrypted client secret (ciphertext token only; never plaintext).
    client_secret_ciphertext: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    secret_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    #: Space-separated scope list requested at authorization time.
    scopes: Mapped[str] = mapped_column(String(255), default="openid profile email")
    #: Claim carrying the username (Pocket ID: ``preferred_username``).
    username_claim: Mapped[str] = mapped_column(String(64), default="preferred_username")
    #: Claim carrying the email address.
    email_claim: Mapped[str] = mapped_column(String(64), default="email")
    #: Optional claim carrying group/role membership.
    groups_claim: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Optional group value that grants the admin role on provision/login.
    admin_group: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Auto-create a local account on first OIDC login.
    auto_provision: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Role assigned to auto-provisioned users (unless ``admin_group`` matches).
    default_role: Mapped[Role] = mapped_column(
        Enum(
            Role,
            native_enum=False,
            length=16,
            values_callable=lambda e: [m.value for m in e],
        ),
        default=Role.VIEWER,
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by_username: Mapped[str | None] = mapped_column(String(64), nullable=True)


class OidcIdentity(Base):
    """Links an external OIDC subject to a local :class:`~app.db.models.user.User`."""

    __tablename__ = "oidc_identities"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_oidc_identity_iss_sub"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(512))
    subject: Mapped[str] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


#: ``OidcLoginFlow.purpose`` values. ``login`` runs the sign-in terminal action
#: (link-or-provision + session); ``link`` binds the verified subject to an
#: already-authenticated account and mints nothing. ``NULL`` reads as ``login``
#: so rows written before the column existed keep their meaning.
FLOW_PURPOSE_LOGIN = "login"
FLOW_PURPOSE_LINK = "link"


class OidcLoginFlow(Base):
    """Short-lived state for an in-progress authorization-code flow.

    Rows are created when the flow is initiated and deleted (or expired) once
    the callback is processed, so a stolen ``state`` cannot be replayed.

    The same handshake serves two purposes (see ``purpose`` below). Both share
    the one registered redirect URI deliberately: a second callback path would
    force every operator to register an extra redirect URI at their IdP, and
    several providers reject unregistered ones outright.
    """

    __tablename__ = "oidc_login_flows"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    redirect_uri: Mapped[str] = mapped_column(String(512))
    #: SHA-256 hash of a random token stored in an HttpOnly cookie on the browser
    #: that started the flow. The callback must present the matching cookie, so a
    #: flow (state/code) cannot be completed in a *different* browser — this binds
    #: the flow to its initiator and defeats OIDC login-CSRF / session fixation.
    browser_binding: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: ``login`` or ``link`` (see the module constants). Nullable so the column
    #: could be added without rewriting in-flight rows; ``None`` means ``login``.
    purpose: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: **Link flows only.** The account the callback is permitted to bind an
    #: identity to, captured server-side from the initiating session — never from
    #: request input. The callback additionally requires a live session for this
    #: same user, so possessing the flow's ``state`` is not sufficient to complete
    #: it. ``NULL`` on every login flow.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
