import OAuth2Manager from './oauth2_manager.ts'
import { getUserId } from './utils.ts'
import OAuthClient from './client.ts'
import OAuthToken from './token.ts'
import ScopeRegistry from './scopes.ts'
import type {
  OAuthClientData,
  OAuthTokenData,
  CreateClientInput,
  ScopeDescription,
} from './types.ts'

/**
 * OAuth2 helper — convenience API for common OAuth2 server operations.
 *
 * @example
 * import { oauth2 } from '@stravigor/oauth2'
 *
 * const { client, plainSecret } = await oauth2.createClient({ name: 'My App', redirectUris: ['...'] })
 * const { token } = await oauth2.createPersonalToken(user, 'CLI Tool', ['read'])
 * await oauth2.revokeToken(tokenId)
 */
export const oauth2 = {
  /** Create a new OAuth client. Returns the client and plain-text secret (if confidential). */
  async createClient(
    data: CreateClientInput
  ): Promise<{ client: OAuthClientData; plainSecret: string | null }> {
    return OAuthClient.create(data)
  },

  /** Find a client by ID. */
  async findClient(id: string): Promise<OAuthClientData | null> {
    return OAuthClient.find(id)
  },

  /** List all non-revoked clients. */
  async listClients(): Promise<OAuthClientData[]> {
    return OAuthClient.all()
  },

  /** Soft-revoke a client. */
  async revokeClient(id: string): Promise<void> {
    return OAuthClient.revoke(id)
  },

  /** Issue a personal access token for a user. Token is shown once. */
  async createPersonalToken(
    user: unknown,
    name: string,
    scopes: string[] = []
  ): Promise<{ token: string; tokenData: OAuthTokenData }> {
    const config = OAuth2Manager.config
    if (!config.personalAccessClient) {
      throw new Error(
        'No personal access client configured. Run "strav oauth2:setup" or set oauth2.personalAccessClient in config.'
      )
    }

    const userId = getUserId(user)
    const { accessToken, tokenData } = await OAuthToken.create({
      userId,
      clientId: config.personalAccessClient,
      scopes,
      name,
      includeRefreshToken: false,
      accessTokenLifetime: config.personalAccessTokenLifetime,
    })

    return { token: accessToken, tokenData }
  },

  /** Revoke a specific token by ID. */
  async revokeToken(tokenId: string): Promise<void> {
    return OAuthToken.revoke(tokenId)
  },

  /** Revoke all tokens for a user. */
  async revokeAllFor(user: unknown): Promise<void> {
    const userId = getUserId(user)
    return OAuthToken.revokeAllFor(userId)
  },

  /** Register available scopes. */
  defineScopes(scopes: Record<string, string>): void {
    ScopeRegistry.define(scopes)
  },

  /** Get descriptions for registered scopes. */
  scopeDescriptions(names?: string[]): ScopeDescription[] {
    if (names) return ScopeRegistry.describe(names)
    return ScopeRegistry.all()
  },

  /** Validate a plain-text access token and return its data. */
  async validateToken(plainToken: string): Promise<OAuthTokenData | null> {
    return OAuthToken.validate(plainToken)
  },
}
