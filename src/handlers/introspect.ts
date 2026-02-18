import type { Context } from '@stravigor/http'
import OAuthClient from '../client.ts'
import OAuthToken from '../token.ts'
import { InvalidClientError } from '../errors.ts'

/**
 * POST /oauth/introspect (RFC 7662)
 *
 * Returns metadata about a token. Used by resource servers to validate
 * tokens without needing direct database access.
 */
export async function introspectHandler(ctx: Context): Promise<Response> {
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

  // Authenticate the requesting client
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

  // Validate the token
  const tokenData = await OAuthToken.validate(token)
  if (!tokenData) {
    // Inactive token — return minimal response per RFC 7662
    return ctx.json({ active: false })
  }

  // Active token — return metadata
  return ctx.json({
    active: true,
    scope: tokenData.scopes.join(' '),
    client_id: tokenData.clientId,
    token_type: 'Bearer',
    exp: Math.floor(tokenData.expiresAt.getTime() / 1000),
    iat: Math.floor(tokenData.createdAt.getTime() / 1000),
    sub: tokenData.userId ?? undefined,
  })
}
