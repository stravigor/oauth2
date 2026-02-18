import type { Middleware } from '@stravigor/http'
import OAuth2Manager from '../oauth2_manager.ts'
import OAuthClient from '../client.ts'
import OAuthToken from '../token.ts'

/**
 * OAuth2 Bearer token authentication middleware.
 *
 * Validates the `Authorization: Bearer <token>` header, loads the
 * associated user (if any), and sets `oauth_token` and `oauth_client`
 * on the context state bag.
 *
 * @example
 * import { oauth } from '@stravigor/oauth2'
 *
 * router.group({ prefix: '/api', middleware: [oauth()] }, r => {
 *   r.get('/me', (ctx) => ctx.json({ user: ctx.get('user') }))
 * })
 */
export function oauth(): Middleware {
  return async (ctx, next) => {
    const header = ctx.header('authorization')
    if (!header || !header.startsWith('Bearer ')) {
      return ctx.json(
        { error: 'unauthenticated', error_description: 'Bearer token required.' },
        401
      )
    }

    const plain = header.slice(7)
    const tokenData = await OAuthToken.validate(plain)
    if (!tokenData) {
      return ctx.json(
        { error: 'invalid_token', error_description: 'The access token is invalid or expired.' },
        401
      )
    }

    // Load user for user-bound tokens (not client_credentials)
    if (tokenData.userId) {
      const user = await OAuth2Manager.actions.findById(tokenData.userId)
      if (!user) {
        return ctx.json(
          { error: 'invalid_token', error_description: 'The token owner no longer exists.' },
          401
        )
      }
      ctx.set('user', user)
    }

    // Set token and client on context for downstream use
    ctx.set('oauth_token', tokenData)

    const client = await OAuthClient.find(tokenData.clientId)
    if (client) {
      ctx.set('oauth_client', client)
    }

    return next()
  }
}
