import type { Middleware } from '@stravigor/http'
import type { OAuthTokenData } from '../types.ts'

/**
 * Scope enforcement middleware.
 *
 * Checks that the current OAuth token has all the required scopes.
 * Must be used after `oauth()` middleware.
 *
 * @example
 * import { oauth, scopes } from '@stravigor/oauth2'
 * import { compose } from '@stravigor/http/http/middleware'
 *
 * r.get('/repos', compose([oauth(), scopes('repos:read')], handler))
 * r.post('/repos', compose([oauth(), scopes('repos:read', 'repos:write')], handler))
 */
export function scopes(...required: string[]): Middleware {
  return (ctx, next) => {
    const token = ctx.get<OAuthTokenData>('oauth_token')
    if (!token) {
      return ctx.json({ error: 'unauthenticated', error_description: 'OAuth token required.' }, 401)
    }

    const missing = required.filter(s => !token.scopes.includes(s))
    if (missing.length > 0) {
      return ctx.json(
        {
          error: 'insufficient_scope',
          error_description: `Missing required scopes: ${missing.join(', ')}`,
        },
        403
      )
    }

    return next()
  }
}
