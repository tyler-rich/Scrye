# Feature scoping — OIDC identity auto-retrieval (account linking via the OAuth flow)

> **Status: SCOPING (2026-07-29). No code has been written.** This document is the handoff for a
> future implementation PR, following the pattern of the Python 3.14 upgrade scoping
> (`docs/upgrades/python-3.14.md`, since retired). Per the cleanup decision recorded in
> `docs/ARCHIVE.md` §14 (2026-07-26 — review documents retired): when this work lands, the durable
> record goes into a dated §14 entry and **this file is deleted** — it is a working document, not
> a permanent one.
>
> **Cross-references:** `backend/app/api/oidc.py` (both routers), `backend/app/auth/oidc.py`
> (protocol client), `backend/app/db/models/oidc.py` (`OidcConfig` / `OidcIdentity` /
> `OidcLoginFlow`), and the §14 entries of 2026-07-03 (P5 OIDC), 2026-07-04 (browser binding,
> role-sync guard, SEC-8 acceptance), and 2026-07-13 (L2/SEC-8 audit visibility). No tracking
> issue exists yet (searched 2026-07-29); open one when this is scheduled.

## The request — and a premise correction that reshapes it

**Request as received:** rather than making an admin manually determine and paste their OIDC
subject / user ID during setup, run an OAuth flow that retrieves it automatically — removing the
"what ID do I use and how do I get it" problem.

**Premise correction:** Scrye's OIDC setup has **no subject field anywhere** — not in the API
(`OidcConfigUpdateIn`), not in the UI (`AuthenticationPanel`), not in the users area. What the
admin enters by hand today is provider-level configuration only: issuer URL, client ID, client
secret, scopes, the claim-name mapping (`username_claim`, `email_claim`, `groups_claim`,
`admin_group`), the auto-provision toggle, and the default role. Identity binding is fully
automatic: on a successful OIDC login the callback reads `sub` from the **verified** ID token and
looks up / creates the link in `oidc_identities`, keyed `(issuer, subject)` with a unique
constraint.

So where does "paste your subject" come from? From the one real gap the automatic flow leaves:
**an existing local account — above all the first admin — cannot be linked to an OIDC identity.**
Today the options are all bad:

1. **`auto_provision` on** → the admin's first OIDC login creates a *duplicate* account (e.g.
   `tyler` the local admin plus a fresh `tyler-a1b2c3d4` at `default_role`). Their existing
   account, history, and role are not linked.
2. **`auto_provision` off** → the OIDC login dead-ends at `oidc_error=not_provisioned`, and there
   is no mechanism to pre-provision a link.
3. **DB surgery** → manually `INSERT INTO oidc_identities (user_id, issuer, subject, …)`, which
   requires the admin to *determine their `sub` by hand at the IdP*. This is the workflow the
   request is actually describing, and it is exactly what the feature should eliminate.

The feature therefore scopes as: **an authenticated "link my OIDC identity" flow** that runs the
existing authorization-code handshake while logged in and binds the `(issuer, sub)` from the
verified ID token to the *current session's* account. The subject is never typed, seen, or chosen
by anyone.

## 1. Why manual subject determination is genuinely hard (per-provider survey)

Per the OIDC spec, `sub` is the only identifier that is guaranteed stable and unique per issuer.
`email` and `preferred_username` are neither (both re-assignable; email often unverified). What
`sub` actually *is* — and whether an admin can even look it up — varies sharply:

| Provider | What `sub` is | Can the admin read it out of the IdP UI? |
|---|---|---|
| **Pocket ID** (reference target) | The account's UUID | Yes — visible in the admin UI |
| **Keycloak** | The user's UUID within the realm | Yes — user detail page in the admin console |
| **Authentik** | Depends on the provider's **subject mode**; the default is a *hash* (based on the user ID), with options for ID / UUID / username / email / UPN | **No** for the default hashed mode — it is not displayed anywhere; changing subject mode later silently re-keys every user |
| **Entra ID** | A **pairwise** opaque string, unique per (user, app registration) — deliberately not the directory object ID (`oid`) | **No** — the pairwise `sub` is not shown in the portal at all; it only exists inside tokens issued to that app |

For two of the four surveyed providers the subject *cannot be read out of the UI*; it can only be
observed from an actual token issued to Scrye's client. Auto-retrieval via a real flow is not a
convenience — it is the only generally correct way to obtain the value. (The same survey feeds
the claim-mapping docs: Entra's `preferred_username` is the UPN and its `email` claim may be
absent; Entra group claims are GUIDs rather than names, so `admin_group` must be a GUID there;
Keycloak needs a client mapper before a groups claim appears at all. Worth a README table in the
implementation PR, but not this feature's core.)

## 2. Proposed flow — reuse, not a parallel implementation

The existing machinery already does everything hard: `oidc.discover()` (cached metadata),
`generate_pkce_pair()`, `build_authorization_url()` (state + nonce + PKCE S256),
`exchange_code()`, and `verify_id_token()` (JWKS signature, algorithm allowlist with `none`
stripped, `iss`/`aud`/`exp` with leeway, nonce match, `sub` presence). The link flow is the same
handshake with a different *purpose* and a different terminal action — so it should be the same
code path, branched, not a second implementation.

Sketch:

- **Schema** (Alembic migration, two nullable columns on `oidc_login_flows`):
  `purpose` (`'login'` default / `'link'`) and `user_id` (FK → `users.id`, set only for link
  flows). Flow rows remain one-time-use with the existing 10-minute TTL and purge.
- **Start — `POST /api/auth/oidc/link`** (authenticated + `require_csrf`; POST because it is
  state-changing, unlike the public login GET). Re-verifies fresh credentials (see §4), then
  creates the flow row with `purpose='link'` and `user_id=<session user>`, sets the same
  `__Host-` browser-binding cookie, and returns the authorization URL as JSON for the frontend to
  navigate to. Refuses up front on insecure transport (same
  `session_cookie_would_be_dropped()` check as login) and when OIDC is disabled/unconfigured.
- **Callback — the existing `GET /api/auth/oidc/callback`**, branched on `flow.purpose`.
  Reusing the registered redirect URI is deliberate: a separate `/link/callback` path would force
  every operator to register a second redirect URI at their IdP (and Entra/Keycloak reject
  unregistered ones), turning a UX feature into a reconfiguration chore. For a `link` flow the
  callback: validates state + browser binding exactly as today, requires a **live session whose
  user matches `flow.user_id`**, runs the full token exchange + ID-token verification, checks the
  `(issuer, sub)` collision rules, inserts the `OidcIdentity` row, records an
  `auth.oidc_identity_linked` audit event, and redirects to a **fixed** settings path with a
  success/error query param. It does **not** create a session, does **not** run auto-provisioning,
  and does **not** touch roles.
- **Unlink — `DELETE /api/auth/oidc/link`** (authenticated + CSRF + fresh re-auth): removes the
  caller's own identity row, refused when the account has no usable local password (an
  OIDC-provisioned account would be stranded with no login path). Small, and it completes the
  lifecycle; include it.
- **Frontend:** a "Linked identity" status + Link/Unlink control. Primary placement: Settings →
  Authentication, surfaced as a call-to-action right after an enabled OIDC config is saved
  ("Link *your* account now so you can sign in with <display_name>"). No new pages.

**Explicitly out of scope:** an admin binding an identity to *another* user. Retrieving someone
else's `sub` requires that person to authenticate at the IdP — it cannot be auto-retrieved — and a
type-in-a-subject fallback would reintroduce both the manual-determination problem and an
arbitrary-binding surface (see A7 below). If demand appears, the future shape is an invite-link
flow (admin generates a one-time link token; the target user completes the OIDC handshake under
it); noted for `docs/ROADMAP.md`, not built here.

## 3. Security surface — abuse cases and their prevention

This is an identity-binding primitive: a bug here converts directly into account takeover of the
admin account. Every case below needs a regression test in the implementation PR.

| # | Abuse case | Prevention |
|---|---|---|
| A1 | **Unauthenticated caller starts a link** | Start endpoint requires an authenticated session (401 otherwise). A link flow row can never exist without a real `user_id` captured server-side from the session — never from request input. |
| A2 | **Unauthenticated / different-user caller completes a link** (e.g. attacker obtains or forges a callback URL) | Callback for `purpose='link'` requires a live session **and** `session.user_id == flow.user_id`; any mismatch or absent session fails closed (flow row already deleted — one-time use), with an audit record. |
| A3 | **CSRF on link start** — attacker's page makes the victim's browser initiate a link | Start is a POST behind `require_csrf` (double-submit token), so a cross-site request cannot initiate a flow. This is stricter than the login GET, correctly: login binds no identity; link does. |
| A4 | **Cross-browser completion / session fixation** — attacker starts a link flow (under any session) and gets the victim's browser to complete it, or replays a captured `state` | The existing browser-binding mechanism: a random token in an HttpOnly `__Host-` cookie set at start, its hash stored on the flow row, compared (`hmac.compare_digest`) at callback. A flow started in one browser cannot be completed in another. Plus: one-time `state` (row deleted before validation results are acted on), 10-minute TTL, purge of stale rows. |
| A5 | **Binding an attacker-controlled IdP identity to the victim's account** (attacker completes *their* IdP login inside the victim's flow — "login CSRF" inverted) | Composition of A2 + A4: the callback's ID token is bound to this flow by `nonce` (minted at start, stored server-side, must appear in the verified token) and PKCE `S256` (verifier stored server-side, required at code exchange), so a token/code from a different flow cannot be substituted; and the flow itself is bound to the victim's browser *and* the victim's session. The attacker would need the victim's browser, session cookie, and CSRF token simultaneously — at which point they already own the session. |
| A6 | **Attacker-supplied subject** — any input path where a caller names the subject to bind | None exists, by construction. The subject is read **only** from `claims["sub"]` of an ID token that passed `verify_id_token()`: JWKS signature over an explicit algorithm allowlist (`none` stripped even if advertised), `iss` == discovered issuer, `aud` == our client ID, `exp` with 60 s leeway, nonce match, non-empty `sub`. No request field, header, or query param carries a subject anywhere in the design. |
| A7 | **Rebinding an already-linked identity** — attacker links an in-use `(issuer, sub)` to a second account, or re-points it | The `uq_oidc_identity_iss_sub` unique constraint already forbids two rows; the link handler additionally checks first and returns an explicit error ("this identity is already linked") rather than surfacing a constraint violation. Linking is insert-only — the flow never updates an existing row's `user_id`. Re-linking your own already-linked identity is a no-op success. |
| A8 | **Privilege escalation through the link path** | The link callback assigns no role, runs no group sync, and creates no session — it writes one `oidc_identities` row and an audit event. Role logic remains exclusively on the login path with its existing guards (absent-claim preservation, last-admin guard). |
| A9 | **Redirect-URI manipulation** | Unchanged from login: `redirect_uri` is derived server-side (`request.url_for`), stored on the flow row, and replayed identically at token exchange (the IdP enforces exact-match against its registration). The post-link browser redirect is a **fixed** app path — no `return_to` parameter, so no open-redirect surface. |
| A10 | **Flow-row flooding** | Start is authenticated and joins the existing auth rate limiter; stale-flow purge already runs on every start/callback. (The §14-noted SEC-5 info finding — unauthenticated login start creates rows — is not worsened; the link start is strictly harder to reach.) |
| A11 | **Insecure transport** | Same up-front `session_cookie_would_be_dropped()` refusal as login (the binding cookie and session cookie are both Secure; the flow cannot survive plain HTTP anyway). |
| A12 | **Token/secret leakage** | No new secrets. The ID token and access token are used in-memory in the callback and discarded; nothing token-shaped is persisted or logged (existing redaction filter untouched). The client secret continues to be decrypted only inside the callback via the existing field-encryption path. |

One small design note: the login and link flows share the binding-cookie name, so starting a link
overwrites a pending login flow's cookie in the same browser. That is an acceptable
last-write-wins (both flows are per-browser and short-lived); scoping the cookie name by purpose
is a cosmetic alternative, not a security requirement.

## 4. Interaction with L2/SEC-8 (MFA not locally enforced on the OIDC path)

The accepted limitation: mandatory-MFA policies are enforced on **local** login only; OIDC logins
delegate the second factor to the IdP, and Scrye records `mfa_delegated_to_idp` in the audit log
when a mandatory policy would otherwise have applied (§14, 2026-07-04 and 2026-07-13; README
security model).

**Auto-linking does widen this — be explicit about it.** Today SEC-8's practical blast radius is
OIDC-*provisioned* accounts, which carry no usable local password and no local TOTP enrollment —
there is nothing to bypass. A linked account is different: a local admin with TOTP enrolled who
links their OIDC identity acquires a login path on which their local TOTP challenge never runs.
Their effective second factor becomes *whatever the IdP enforces*. SEC-8 grows from "provisioned
accounts" to "any linked account, including MFA-enrolled admins".

Mitigations (first two are requirements of the implementation PR, not suggestions):

1. **Gate the link act itself behind fresh full authentication.** Starting a link (and an unlink)
   requires re-entering the current password *and*, if enrolled, a current TOTP code — the same
   posture as the existing MFA re-enroll gate (`/auth/mfa/enroll` requires the password whenever a
   secret exists; §14, 2026-07-04). A stolen session alone can then never create a new login path
   for the account. This is the single most important control in this feature.
2. **Warn at link time.** When the linking user has TOTP enrolled, or a mandatory-MFA policy
   applies to their role, the UI states plainly: "Signing in with <display_name> will not ask for
   your Scrye MFA code — your identity provider's MFA (if configured) applies instead."
3. **Audit visibility is already in place** — the `mfa_delegated_to_idp` marker on OIDC logins
   under a mandatory policy applies to linked accounts automatically; no change needed. The new
   `auth.oidc_identity_linked` / `auth.oidc_identity_unlinked` events make the *creation* of the
   bypass path auditable too.
4. **Document** in the README security model and the landing §14 entry that linking extends the
   SEC-8 accepted limitation to linked accounts, with the fresh-auth gate as the compensating
   control.

**Rejected:** refusing to link MFA-enrolled accounts (guts the feature for exactly its target
user — the security-conscious admin whose IdP runs passkeys/MFA that is likely *stronger* than
Scrye's TOTP), and adding a local TOTP step inside the OIDC handshake (already rejected when
SEC-8 was accepted — it would lock out provisioned accounts and second-guess the IdP).

## 5. First-admin setup, and configuring OIDC after an admin exists

- **`/auth/setup` is unchanged.** The first admin is created locally before OIDC can even be
  configured — the OIDC config endpoints are admin-only, so an OIDC-first bootstrap is impossible
  by construction. This feature adds nothing to, and takes nothing from, the setup flow.
- **OIDC configured after an admin exists is the primary target scenario**, not an edge case:
  local admin exists → admin configures + enables OIDC → Settings surfaces "Link your account" →
  one OAuth round-trip binds their identity → both login paths work for the same account, no
  duplicate. The duplicate-account trap (option 1 in the premise correction) still exists if the
  admin skips the link and OIDC-logs-in anyway with `auto_provision` on — existing behavior,
  unchanged — but the CTA makes the right path the easy path.
- **Rejected alternative — match-by-email link-on-login** (auto-link an OIDC login to an existing
  local account with the same email): classic account-takeover vector. Email is not a verified,
  stable identifier; an IdP that lets users self-set an unverified email (or an admin typo) turns
  "same email" into "attacker controls the admin account". Not built, not configurable, noted
  here so it isn't re-proposed later.

## 6. Scope, deliverables, and estimate

One focused PR into `dev` (schema change ⇒ per CLAUDE.md § When to ask vs. decide, this scoping
doc is the sign-off request for the data-model touch):

1. Alembic migration: `oidc_login_flows.purpose` + `oidc_login_flows.user_id` (both nullable,
   backward-compatible; existing rows read as login flows).
2. Backend: link start (POST, auth + CSRF + fresh full re-auth), callback branch, unlink
   (DELETE, same gates + no-local-password guard), audit events. Estimated ~200 lines plus the
   shared fresh-re-auth helper.
3. Frontend: linked-identity status + Link/Unlink in Settings → Authentication, the post-save
   CTA, and callback result handling. Typed client additions in `frontend/src/api/oidc.ts`.
4. Tests: one per abuse case A1–A12 (most are cheap variations of the existing callback tests),
   plus the SEC-8 gate (link refused without fresh password/TOTP) and the unlink stranding guard.
5. Docs: README § Configuring OIDC gains the link walkthrough and the per-provider claim/subject
   table from §1; security model paragraph extended per §4; dated §14 entry; **this file
   deleted** in the same PR.

Definition of done per CLAUDE.md applies unchanged (lint, tests, CI green, compose up healthy,
identity/footer verification).

## Recommendation

**Build it, at the minimal scope above.** The premise of the request was slightly off — Scrye
never asks anyone to paste a subject — but the pain underneath it is real: linking an existing
admin account to OIDC currently requires hand-determining a `sub` (impossible to even look up on
Authentik's default mode and on Entra ID) and writing it into the database by hand. The fix
reuses the existing, already-hardened authorization-code machinery end-to-end, adds two nullable
columns and no new protocol surface, and its security story reduces to controls Scrye already has
(state + nonce + PKCE + browser binding + verified-token-only subjects) plus two new ones
(session-match at callback, fresh full re-auth to link). The one genuine cost — widening the
L2/SEC-8 MFA delegation to linked accounts — is bounded by the fresh-auth gate and is the
explicit, documented trade the linking user is choosing.

Skip (and record in `docs/ROADMAP.md` if wanted later): admin-binds-other-user / invite links,
email-based auto-linking (rejected outright, see §5), and any subject text-entry field anywhere.
