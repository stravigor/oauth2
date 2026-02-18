import type { Context } from '@stravigor/http'
import { Emitter } from '@stravigor/kernel'
import OAuthClient from '../client.ts'
import OAuthToken from '../token.ts'
import { OAuth2Events } from '../types.ts'
import { InvalidClientError } from '../errors.ts'

/**
 * POST /oauth/revoke (RFC 7009)
 *
 * Revokes an access token or refresh token.
 * Always returns 200 regardless of whether the token existed
 * (to prevent information leakage).
 */
export async function revokeHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{
    token?: string
    token_type_hint?: string
    client_id?: string
    client_secret?: string
  }>()

  const { token, client_id, client_secret } = body

  if (!token) {
    return ctx.json(
      { error: 'invalid_request', error_description: 'The token parameter is required.' },
      400
    )
  }

  // Authenticate the client if credentials are provided
  if (client_id) {
    const client = await OAuthClient.find(client_id)
    if (!client || client.revoked) {
      return ctx.json(new InvalidClientError().toJSON(), 401)
    }

    if (client.confidential && client_secret) {
      const valid = await OAuthClient.verifySecret(client, client_secret)
      if (!valid) {
        return ctx.json(new InvalidClientError().toJSON(), 401)
      }
    }
  }

  // Try revoking as access token first, then as refresh token
  const tokenData = await OAuthToken.validate(token)
  if (tokenData) {
    await OAuthToken.revoke(tokenData.id)

    if (Emitter.listenerCount(OAuth2Events.TOKEN_REVOKED) > 0) {
      Emitter.emit(OAuth2Events.TOKEN_REVOKED, { ctx, tokenId: tokenData.id }).catch(() => {})
    }

    return ctx.json({})
  }

  // Try as refresh token
  const refreshData = await OAuthToken.validateRefreshToken(token)
  if (refreshData) {
    await OAuthToken.revoke(refreshData.id)

    if (Emitter.listenerCount(OAuth2Events.TOKEN_REVOKED) > 0) {
      Emitter.emit(OAuth2Events.TOKEN_REVOKED, { ctx, tokenId: refreshData.id }).catch(() => {})
    }
  }

  // RFC 7009: Always respond with 200 even if token not found
  return ctx.json({})
}
