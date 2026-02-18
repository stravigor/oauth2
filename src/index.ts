// Manager & provider
export { default, default as OAuth2Manager } from './oauth2_manager.ts'
export { default as OAuth2Provider } from './oauth2_provider.ts'

// Helper
export { oauth2 } from './helpers.ts'

// Actions
export { defineActions } from './actions.ts'

// Middleware
export { oauth } from './middleware/oauth.ts'
export { scopes } from './middleware/scopes.ts'

// Data helpers
export { default as OAuthClient } from './client.ts'
export { default as OAuthToken } from './token.ts'
export { default as AuthCode } from './auth_code.ts'

// Scope registry
export { default as ScopeRegistry } from './scopes.ts'

// Handlers (for manual route registration)
export { authorizeHandler, approveHandler } from './handlers/authorize.ts'
export { tokenHandler } from './handlers/token.ts'
export { revokeHandler } from './handlers/revoke.ts'
export { introspectHandler } from './handlers/introspect.ts'
export { listClientsHandler, createClientHandler, deleteClientHandler } from './handlers/clients.ts'
export {
  createPersonalTokenHandler,
  listPersonalTokensHandler,
  revokePersonalTokenHandler,
} from './handlers/personal_tokens.ts'

// Errors
export {
  OAuth2Error,
  UnsupportedGrantError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  AccessDeniedError,
} from './errors.ts'

// Types
export type {
  GrantType,
  OAuth2Actions,
  OAuth2Config,
  OAuth2Event,
  OAuthClientData,
  OAuthTokenData,
  OAuthAuthCodeData,
  ScopeDescription,
  CreateClientInput,
  RateLimitConfig,
} from './types.ts'
export { OAuth2Events } from './types.ts'
