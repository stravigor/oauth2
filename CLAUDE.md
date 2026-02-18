# @stravigor/oauth2

OAuth2 authorization server implementation. Turns a Strav application into a full OAuth2 provider. Supports Authorization Code + PKCE, Client Credentials, Refresh Token rotation, Token Revocation, and Token Introspection.

## Dependencies
- @stravigor/kernel (peer)
- @stravigor/http (peer)
- @stravigor/database (peer)
- @stravigor/cli (peer)

## Commands
- bun test
- bun run build

## Architecture
- src/oauth2_manager.ts — main manager class
- src/oauth2_provider.ts — service provider registration
- src/handlers/ — grant type handlers
- src/middleware/ — OAuth2 middleware (token validation, scopes)
- src/client.ts — OAuth2 client management
- src/token.ts — token generation and validation
- src/auth_code.ts — authorization code flow
- src/scopes.ts — scope definitions and checking
- src/actions.ts — reusable OAuth2 actions
- src/commands/ — CLI commands
- src/types.ts — type definitions
- src/errors.ts — package-specific errors

## Conventions
- Each grant type is a separate handler in src/handlers/
- PKCE is enforced by default for authorization code grants
- Token rotation is automatic for refresh tokens
