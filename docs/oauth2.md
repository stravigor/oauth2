# OAuth2

The OAuth2 module (`@stravigor/oauth2`) turns your Strav application into a full OAuth2 authorization server. Third-party (and first-party) applications can obtain scoped access tokens via standard OAuth2 grants, and your users can issue personal access tokens for API usage.

Supports **Authorization Code + PKCE** (RFC 7636), **Client Credentials**, **Refresh Token rotation**, **Token Revocation** (RFC 7009), and **Token Introspection** (RFC 7662).

Built on top of the [auth](./auth.md) and [session](./session.md) modules from `@stravigor/core`.

## Installation

```bash
bun add @stravigor/oauth2
bun strav install oauth2
```

The `install` command copies four things into your project:

- `config/oauth2.ts` — token lifetimes, scopes, rate limits.
- `database/schemas/oauth_client.ts`, `oauth_token.ts`, `oauth_auth_code.ts` — the three database schemas.
- `actions/oauth2.ts` — the actions contract (how your User model works).

All files are yours to edit. If a file already exists, the command skips it (use `--force` to overwrite).

## Setup

### 1. Implement the actions contract

Edit `actions/oauth2.ts` and fill in the two required functions:

```typescript
// actions/oauth2.ts
import { defineActions } from '@stravigor/oauth2'
import User from '../models/user'

export default defineActions<User>({
  async findById(id) {
    return await User.find(id)
  },

  identifierOf(user) {
    return user.email
  },
})
```

The `defineActions<TUser>()` helper is a typed identity function — it provides full autocompletion and type safety.

Only two methods are required:

| Method | Signature | Description |
|--------|-----------|-------------|
| `findById` | `(id: string \| number) => Promise<TUser \| null>` | Look up a user by primary key. Used to load the resource owner for token-protected routes. |
| `identifierOf` | `(user: TUser) => string` | Return the user's display identifier. Shown on the consent screen for third-party clients. |

One method is optional:

| Method | Signature | Description |
|--------|-----------|-------------|
| `renderAuthorization` | `(ctx, client, scopes) => Promise<Response>` | Render a custom consent screen for third-party clients. When omitted, the handler returns a JSON payload for SPA-based consent. |

### 2. Register the provider

Add to `start/providers.ts`:

```typescript
import { OAuth2Provider } from '@stravigor/oauth2'
import actions from './actions/oauth2'

new OAuth2Provider(actions),
```

The `OAuth2Provider` depends on: `auth`, `session`, `encryption`, `database`. It registers `OAuth2Manager` as a singleton, creates the database tables, and registers all routes automatically.

### 3. Run initial setup

```bash
bun strav oauth2:setup
```

This creates the OAuth2 tables and a default personal access client. Copy the printed client ID into `config/oauth2.ts`:

```typescript
personalAccessClient: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx',
```

### 4. Create your first client

```bash
bun strav oauth2:client --name "Mobile App" --redirect "myapp://callback" --public
```

Store the client secret securely — it is shown only once.

## Configuration

Edit `config/oauth2.ts`:

```typescript
import { env } from '@stravigor/core/helpers'

export default {
  // Token lifetimes (in minutes)
  accessTokenLifetime: 60,            // 1 hour
  refreshTokenLifetime: 43_200,       // 30 days
  authCodeLifetime: 10,               // 10 minutes
  personalAccessTokenLifetime: 525_600, // 1 year

  // Route prefix for all OAuth2 endpoints
  prefix: '/oauth',

  // Available scopes
  scopes: {
    'read': 'Read access to your data',
    'write': 'Write access to your data',
    'repos:read': 'Read your repositories',
    'repos:write': 'Create and update repositories',
  },

  // Scopes granted when none are explicitly requested
  defaultScopes: [] as string[],

  // Client ID for personal access tokens (created by oauth2:setup)
  personalAccessClient: env('OAUTH2_PERSONAL_CLIENT') ?? null,

  // Rate limiting
  rateLimit: {
    authorize: { max: 30, window: 60 },
    token: { max: 20, window: 60 },
  },

  // Cleanup: delete revoked tokens older than this many days
  pruneRevokedAfterDays: 7,
}
```

### Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `accessTokenLifetime` | `60` | Access token lifetime in minutes. |
| `refreshTokenLifetime` | `43200` | Refresh token lifetime in minutes (30 days). |
| `authCodeLifetime` | `10` | Authorization code lifetime in minutes. |
| `personalAccessTokenLifetime` | `525600` | Personal access token lifetime in minutes (1 year). |
| `prefix` | `'/oauth'` | Route prefix for all OAuth2 endpoints. |
| `scopes` | `{}` | Available scopes as `{ name: description }` pairs. |
| `defaultScopes` | `[]` | Scopes granted when the client requests none. |
| `personalAccessClient` | `null` | Client ID for personal access tokens. Created by `oauth2:setup`. |
| `rateLimit.authorize` | `{ max: 30, window: 60 }` | Rate limit for the authorize endpoint. `window` is in seconds. |
| `rateLimit.token` | `{ max: 20, window: 60 }` | Rate limit for the token endpoint. |
| `pruneRevokedAfterDays` | `7` | Delete revoked tokens older than this many days during purge. |

## Routes

All routes are registered automatically by `OAuth2Provider`. They are prefixed with `config.prefix` (`/oauth` by default).

| Method | Path | Middleware | Description |
|--------|------|-----------|-------------|
| GET | `/oauth/authorize` | `auth()`, rate limit | Start authorization code flow |
| POST | `/oauth/authorize` | `auth()`, `csrf()` | Approve or deny authorization |
| POST | `/oauth/token` | rate limit | Exchange grant for tokens |
| POST | `/oauth/revoke` | — | Revoke a token (RFC 7009) |
| POST | `/oauth/introspect` | — | Introspect a token (RFC 7662) |
| GET | `/oauth/clients` | `auth()` | List clients |
| POST | `/oauth/clients` | `auth()` | Create a client |
| DELETE | `/oauth/clients/:id` | `auth()` | Delete a client |
| POST | `/oauth/personal-tokens` | `auth()` | Create a personal access token |
| GET | `/oauth/personal-tokens` | `auth()` | List personal access tokens |
| DELETE | `/oauth/personal-tokens/:id` | `auth()` | Revoke a personal access token |

## Grant flows

### Authorization Code + PKCE

The standard flow for web and mobile apps. PKCE is required for public clients.

#### Step 1: Redirect the user

```
GET /oauth/authorize?response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=https://example.com/callback
  &scope=read write
  &state=random-csrf-string
  &code_challenge=BASE64URL_SHA256_HASH
  &code_challenge_method=S256
```

For **first-party clients** (`firstParty: true`), consent is auto-approved and the user is redirected immediately with an authorization code.

For **third-party clients**, the handler returns a JSON payload for SPA-based consent (or calls `renderAuthorization` if you provided one):

```json
{
  "authorization_required": true,
  "client": { "id": "...", "name": "Third Party App" },
  "scopes": [
    { "name": "read", "description": "Read access to your data" },
    { "name": "write", "description": "Write access to your data" }
  ],
  "state": "random-csrf-string"
}
```

#### Step 2: User approves

```
POST /oauth/authorize
Content-Type: application/json

{ "approved": true }
```

Redirects the user to `redirect_uri?code=AUTH_CODE&state=random-csrf-string`.

#### Step 3: Exchange the code for tokens

```
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "AUTH_CODE",
  "redirect_uri": "https://example.com/callback",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "code_verifier": "ORIGINAL_RANDOM_STRING"
}
```

Confidential clients authenticate with `client_secret`. Public clients authenticate with `code_verifier` (PKCE).

Response:

```json
{
  "access_token": "a1b2c3d4...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "e5f6g7h8...",
  "scope": "read write"
}
```

### Client Credentials

Machine-to-machine authentication with no user context.

```
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "read"
}
```

Requirements:
- Client must be confidential (has a secret).
- `client_credentials` must be in the client's allowed `grantTypes`.

Response includes an access token but **no refresh token** and no user association.

### Refresh Token

Exchange a refresh token for a new access + refresh token pair. The old pair is revoked (rotation).

```
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": "e5f6g7h8...",
  "client_id": "CLIENT_ID",
  "client_secret": "CLIENT_SECRET",
  "scope": "read"
}
```

Scopes can be narrowed on refresh but not widened beyond the original grant.

### Token Revocation (RFC 7009)

```
POST /oauth/revoke
Content-Type: application/json

{ "token": "a1b2c3d4..." }
```

Always returns `200` regardless of whether the token was found (per RFC 7009). Works with both access tokens and refresh tokens.

### Token Introspection (RFC 7662)

```
POST /oauth/introspect
Content-Type: application/json

{ "token": "a1b2c3d4..." }
```

Response for a valid token:

```json
{
  "active": true,
  "scope": "read write",
  "client_id": "CLIENT_ID",
  "sub": "USER_ID",
  "exp": 1700000000,
  "iat": 1699996400
}
```

Returns `{ "active": false }` for invalid, expired, or revoked tokens.

## Personal access tokens

Users can create long-lived tokens for API access (like GitHub PATs).

### Create

```
POST /oauth/personal-tokens
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "name": "CLI Tool",
  "scopes": ["read", "write"]
}
```

Response:

```json
{
  "token": "a1b2c3d4...",
  "accessToken": {
    "id": "...",
    "name": "CLI Tool",
    "scopes": ["read", "write"],
    "expires_at": "...",
    "created_at": "..."
  }
}
```

> The plain-text token is shown only once. Store it securely.

### List

```
GET /oauth/personal-tokens
```

Returns all active personal access tokens for the authenticated user. Token hashes are never exposed.

### Revoke

```
DELETE /oauth/personal-tokens/:id
```

## Middleware

### oauth()

Validate the `Authorization: Bearer <token>` header, load the associated user, and set `oauth_token` and `oauth_client` on the context.

```typescript
import { router } from '@stravigor/core/http'
import { oauth } from '@stravigor/oauth2'

router.group({ prefix: '/api', middleware: [oauth()] }, r => {
  r.get('/me', ctx => {
    const user = ctx.get('user')
    return ctx.json({ user })
  })
})
```

After `oauth()` runs, three values are available on the context:

| Key | Type | Description |
|-----|------|-------------|
| `user` | `TUser` | The resource owner. Not set for `client_credentials` tokens. |
| `oauth_token` | `OAuthTokenData` | The validated token metadata (scopes, expiry, etc.). |
| `oauth_client` | `OAuthClientData` | The client that issued the token. |

Returns `401` with `{ error: 'unauthenticated' }` if the header is missing, or `{ error: 'invalid_token' }` if the token is invalid, expired, or revoked.

### scopes(...required)

Enforce that the token has specific scopes. Must be used after `oauth()`.

```typescript
import { oauth, scopes } from '@stravigor/oauth2'
import { compose } from '@stravigor/core/http/middleware'

router.group({ prefix: '/api', middleware: [oauth()] }, r => {
  r.get('/repos', compose([scopes('repos:read')], listRepos))
  r.post('/repos', compose([scopes('repos:write')], createRepo))
  r.delete('/repos/:id', compose([scopes('repos:read', 'repos:write')], deleteRepo))
})
```

Returns `403` with `{ error: 'insufficient_scope' }` and lists the missing scopes.

## Events

Every significant action emits an event via the core `Emitter`:

```typescript
import Emitter from '@stravigor/core/events'
import { OAuth2Events } from '@stravigor/oauth2'

Emitter.on(OAuth2Events.TOKEN_ISSUED, async ({ ctx, userId, clientId, grantType }) => {
  console.log(`Token issued for user ${userId} via ${grantType}`)
})

Emitter.on(OAuth2Events.ACCESS_DENIED, async ({ ctx, clientId }) => {
  console.log(`User denied access to client ${clientId}`)
})
```

| Constant | Event string | Emitted when |
|----------|-------------|--------------|
| `TOKEN_ISSUED` | `oauth2:token-issued` | An access token is issued (any grant) |
| `TOKEN_REVOKED` | `oauth2:token-revoked` | A token is revoked |
| `TOKEN_REFRESHED` | `oauth2:token-refreshed` | A token is refreshed (rotation) |
| `CODE_ISSUED` | `oauth2:code-issued` | An authorization code is issued |
| `CLIENT_CREATED` | `oauth2:client-created` | A new client is created |
| `CLIENT_REVOKED` | `oauth2:client-revoked` | A client is soft-revoked |
| `ACCESS_DENIED` | `oauth2:access-denied` | The user denies consent |

## oauth2 helper

The `oauth2` helper provides a convenience API for common operations:

```typescript
import { oauth2 } from '@stravigor/oauth2'

// Client management
const { client, plainSecret } = await oauth2.createClient({
  name: 'My App',
  redirectUris: ['https://example.com/callback'],
})
const clients = await oauth2.listClients()
await oauth2.revokeClient(client.id)

// Personal access tokens
const { token, tokenData } = await oauth2.createPersonalToken(user, 'CLI Tool', ['read'])

// Token operations
await oauth2.revokeToken(tokenData.id)
await oauth2.revokeAllFor(user)
const data = await oauth2.validateToken(plainToken)

// Scopes
oauth2.defineScopes({ admin: 'Full admin access' })
const descriptions = oauth2.scopeDescriptions(['read', 'write'])
```

| Method | Description |
|--------|-------------|
| `createClient(data)` | Create a new OAuth client. Returns the client and plain-text secret. |
| `findClient(id)` | Find a client by ID. |
| `listClients()` | List all non-revoked clients. |
| `revokeClient(id)` | Soft-revoke a client. |
| `createPersonalToken(user, name, scopes?)` | Issue a personal access token. Token is shown once. |
| `revokeToken(tokenId)` | Revoke a specific token by ID. |
| `revokeAllFor(user)` | Revoke all tokens for a user. |
| `defineScopes(scopes)` | Register additional scopes at runtime. |
| `scopeDescriptions(names?)` | Get descriptions for scopes. Returns all if no names given. |
| `validateToken(plainToken)` | Validate a plain-text token and return its data, or null. |

## CLI commands

### oauth2:setup

Create the OAuth2 tables and a default personal access client:

```bash
bun strav oauth2:setup
```

### oauth2:client

Create a new OAuth2 client:

```bash
# Confidential client (default)
bun strav oauth2:client --name "Web App" --redirect "https://app.com/callback"

# Public client (SPA / mobile)
bun strav oauth2:client --name "Mobile App" --redirect "myapp://callback" --public

# First-party (skip consent)
bun strav oauth2:client --name "Admin Dashboard" --redirect "https://admin.com/callback" --first-party

# Machine-to-machine
bun strav oauth2:client --name "Worker Service" --credentials
```

| Flag | Description |
|------|-------------|
| `--name <name>` | Client name (required). |
| `--redirect <uris...>` | Redirect URIs. |
| `--public` | Create a public (non-confidential) client. |
| `--first-party` | Mark as a first-party client (skip consent screen). |
| `--credentials` | Enable the `client_credentials` grant type. |

### oauth2:purge

Delete expired tokens and used authorization codes:

```bash
bun strav oauth2:purge
bun strav oauth2:purge --days 30
```

## Clients

### Confidential vs. public

**Confidential clients** have a secret and can authenticate with `client_id` + `client_secret`. Use for server-side apps.

**Public clients** have no secret and must use PKCE for the authorization code flow. Use for SPAs and mobile apps.

### First-party vs. third-party

**First-party clients** (`firstParty: true`) skip the consent screen — the authorization is auto-approved. Use for your own frontends and internal tools.

**Third-party clients** show a consent screen where the user approves or denies the requested scopes.

### Scopes per client

Restrict a client to specific scopes:

```typescript
const { client } = await oauth2.createClient({
  name: 'Limited App',
  redirectUris: ['https://example.com/callback'],
  scopes: ['read'],  // can only request 'read' scope
})
```

When `scopes` is `null` (default), the client can request any registered scope.

## Database tables

The package creates three tables:

| Table | Archetype | Description |
|-------|-----------|-------------|
| `_strav_oauth_clients` | Entity | OAuth clients (apps) |
| `_strav_oauth_tokens` | Component | Access + refresh tokens |
| `_strav_oauth_auth_codes` | Event | Authorization codes (single-use) |

Tables are created automatically by `OAuth2Provider` on boot or by `strav oauth2:setup`.

## Error handling

All errors follow the RFC 6749 error format:

```json
{
  "error": "invalid_grant",
  "error_description": "The provided authorization grant is invalid, expired, or revoked."
}
```

Error classes:

| Class | Error code | Status | Description |
|-------|-----------|--------|-------------|
| `OAuth2Error` | `server_error` | 400 | Base error |
| `InvalidRequestError` | `invalid_request` | 400 | Missing or malformed parameter |
| `InvalidClientError` | `invalid_client` | 401 | Client authentication failed |
| `InvalidGrantError` | `invalid_grant` | 400 | Grant is invalid, expired, or revoked |
| `InvalidScopeError` | `invalid_scope` | 400 | Unknown or disallowed scope |
| `UnsupportedGrantError` | `unsupported_grant_type` | 400 | Grant type not supported |
| `AccessDeniedError` | `access_denied` | 403 | User denied the authorization request |

```typescript
import { OAuth2Error, InvalidGrantError } from '@stravigor/oauth2'

// Errors expose .toJSON() for RFC-compliant responses
const error = new InvalidGrantError('Authorization code expired.')
console.log(error.toJSON())
// { error: 'invalid_grant', error_description: 'Authorization code expired.' }
```

## Security

- **Token hashing**: All tokens (access, refresh, authorization codes) are stored as SHA-256 hashes. Plain-text tokens are returned only once at creation time.
- **Timing-safe comparison**: Token lookups use `crypto.timingSafeEqual` to prevent timing attacks.
- **PKCE (RFC 7636)**: Public clients must use PKCE with `S256` or `plain` code challenge methods. The code verifier is validated against the stored challenge before issuing tokens.
- **Code replay prevention**: Authorization codes are single-use. Once consumed, the `used_at` timestamp prevents reuse.
- **Refresh token rotation**: On refresh, the old token pair is revoked and a new pair is issued. Compromised refresh tokens cannot be reused.
- **Scope narrowing only**: Refreshed tokens can narrow scopes but never widen them beyond the original grant.
- **Redirect URI validation**: The `redirect_uri` must exactly match one of the client's registered URIs.
- **CSRF protection**: The authorize POST endpoint uses `csrf()` middleware. The authorization code flow supports the `state` parameter.
- **Rate limiting**: Both the authorize and token endpoints are rate-limited by default.
- **Client secret hashing**: Client secrets are stored as bcrypt hashes via `Bun.password.hash`.

## Integration with existing auth

- **Works alongside Jina**: The authorize endpoint uses `auth()` middleware from `@stravigor/core`. Jina handles the login flow — OAuth2 picks up from the authenticated session.
- **Separate from AccessToken**: OAuth2 tokens are stored in `_strav_oauth_tokens`, not `_strav_access_tokens`. They are a different system with scopes, clients, and refresh tokens.
- **Coexistence**: Use `oauth()` for OAuth2-protected API routes and `auth()` for session-based routes. They can coexist on different route groups.
- **Session-aware**: The authorize flow uses sessions (CSRF, consent state). Token endpoints are stateless.

## Full example

```typescript
import { router } from '@stravigor/core/http'
import { session } from '@stravigor/core/session'
import { auth } from '@stravigor/core/auth'
import { compose } from '@stravigor/core/http/middleware'
import { OAuth2Provider, oauth, scopes, oauth2 } from '@stravigor/oauth2'
import actions from './actions/oauth2'

// In start/providers.ts
new OAuth2Provider(actions),

// Define scopes (also configurable in config/oauth2.ts)
oauth2.defineScopes({
  'repos:read': 'Read your repositories',
  'repos:write': 'Create and update repositories',
  'user:email': 'Read your email address',
})

// Session-based routes (your web app)
router.group({ middleware: [session(), auth()] }, r => {
  r.get('/dashboard', dashboardHandler)
})

// OAuth2-protected API routes
router.group({ prefix: '/api/v1', middleware: [oauth()] }, r => {
  // Any valid token can access
  r.get('/user', ctx => {
    return ctx.json({ user: ctx.get('user') })
  })

  // Requires specific scopes
  r.get('/repos', compose([scopes('repos:read')], async ctx => {
    const repos = await Repo.query().where('user_id', ctx.get('user').id).get()
    return ctx.json({ repos })
  }))

  r.post('/repos', compose([scopes('repos:write')], async ctx => {
    const data = await ctx.body()
    const repo = await Repo.create({ ...data, userId: ctx.get('user').id })
    return ctx.json({ repo }, 201)
  }))
})
```
