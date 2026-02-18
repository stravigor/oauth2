import type { Context } from '@stravigor/http'
import { Emitter } from '@stravigor/kernel'
import { getUserId } from '../utils.ts'
import OAuth2Manager from '../oauth2_manager.ts'
import OAuthToken from '../token.ts'
import ScopeRegistry from '../scopes.ts'
import { OAuth2Events } from '../types.ts'

/**
 * POST /oauth/personal-tokens
 *
 * Issue a personal access token for the authenticated user.
 * Returns the plain-text token (shown once).
 */
export async function createPersonalTokenHandler(ctx: Context): Promise<Response> {
  const config = OAuth2Manager.config

  if (!config.personalAccessClient) {
    return ctx.json(
      { message: 'No personal access client configured. Run "strav oauth2:setup" first.' },
      500
    )
  }

  const body = await ctx.body<{ name?: string; scopes?: string[] }>()

  if (!body.name) {
    return ctx.json({ message: 'The name field is required.' }, 422)
  }

  // Validate scopes if provided
  const scopes = body.scopes ?? []
  if (scopes.length > 0) {
    for (const scope of scopes) {
      if (!ScopeRegistry.has(scope)) {
        return ctx.json({ message: `Unknown scope: "${scope}".` }, 422)
      }
    }
  }

  const user = ctx.get('user')
  const userId = getUserId(user)

  const { accessToken, tokenData } = await OAuthToken.create({
    userId,
    clientId: config.personalAccessClient,
    scopes,
    name: body.name,
    includeRefreshToken: false,
    accessTokenLifetime: config.personalAccessTokenLifetime,
  })

  if (Emitter.listenerCount(OAuth2Events.TOKEN_ISSUED) > 0) {
    Emitter.emit(OAuth2Events.TOKEN_ISSUED, {
      ctx,
      userId,
      clientId: config.personalAccessClient,
      grantType: 'personal_access_token',
    }).catch(() => {})
  }

  return ctx.json(
    {
      token: accessToken,
      accessToken: {
        id: tokenData.id,
        name: tokenData.name,
        scopes: tokenData.scopes,
        expires_at: tokenData.expiresAt,
        created_at: tokenData.createdAt,
      },
    },
    201
  )
}

/**
 * GET /oauth/personal-tokens
 *
 * List all active personal access tokens for the authenticated user.
 */
export async function listPersonalTokensHandler(ctx: Context): Promise<Response> {
  const user = ctx.get('user')
  const userId = getUserId(user)

  const tokens = await OAuthToken.personalTokensFor(userId)

  return ctx.json({
    tokens: tokens.map(t => ({
      id: t.id,
      name: t.name,
      scopes: t.scopes,
      last_used_at: t.lastUsedAt,
      expires_at: t.expiresAt,
      created_at: t.createdAt,
    })),
  })
}

/**
 * DELETE /oauth/personal-tokens/:id
 *
 * Revoke a specific personal access token.
 */
export async function revokePersonalTokenHandler(ctx: Context): Promise<Response> {
  const tokenId = ctx.params.id!

  await OAuthToken.revoke(tokenId)

  if (Emitter.listenerCount(OAuth2Events.TOKEN_REVOKED) > 0) {
    Emitter.emit(OAuth2Events.TOKEN_REVOKED, { ctx, tokenId }).catch(() => {})
  }

  return ctx.json({ message: 'Token revoked.' })
}
