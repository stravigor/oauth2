import { env } from '@stravigor/kernel'

export default {
  // Token lifetimes (in minutes)
  accessTokenLifetime: 60, // 1 hour
  refreshTokenLifetime: 43_200, // 30 days
  authCodeLifetime: 10, // 10 minutes
  personalAccessTokenLifetime: 525_600, // 1 year

  // Route prefix for all OAuth2 endpoints
  prefix: '/oauth',

  // Available scopes — define your app's scopes here
  scopes: {
    // 'read': 'Read access to your data',
    // 'write': 'Write access to your data',
    // 'repos:read': 'Read your repositories',
    // 'repos:write': 'Create and update repositories',
  },

  // Scopes granted when none are explicitly requested
  defaultScopes: [] as string[],

  // Client ID for personal access tokens (created by `strav oauth2:setup`)
  personalAccessClient: env('OAUTH2_PERSONAL_CLIENT') ?? null,

  // Rate limiting
  rateLimit: {
    authorize: { max: 30, window: 60 }, // 30 requests per 60 seconds
    token: { max: 20, window: 60 }, // 20 requests per 60 seconds
  },

  // Cleanup: delete revoked tokens older than this many days
  pruneRevokedAfterDays: 7,
}
