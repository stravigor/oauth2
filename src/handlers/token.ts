import type { Context } from '@stravigor/http'
import { Emitter } from '@stravigor/kernel'
import OAuth2Manager from '../oauth2_manager.ts'
import OAuthClient from '../client.ts'
import OAuthToken from '../token.ts'
import AuthCode from '../auth_code.ts'
import ScopeRegistry from '../scopes.ts'
import { OAuth2Events } from '../types.ts'
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  UnsupportedGrantError,
} from '../errors.ts'

/**
 * POST /oauth/token
 *
 * Token endpoint — handles all grant types:
 * - authorization_code (+ PKCE)
 * - client_credentials
 * - refresh_token
 */
export async function tokenHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<Record<string, string>>()
  const grantType = body.grant_type

  if (!grantType) {
    return errorResponse(ctx, new InvalidRequestError('The grant_type parameter is required.'))
  }

  switch (grantType) {
    case 'authorization_code':
      return handleAuthorizationCode(ctx, body)
    case 'client_credentials':
      return handleClientCredentials(ctx, body)
    case 'refresh_token':
      return handleRefreshToken(ctx, body)
    default:
      return errorResponse(ctx, new UnsupportedGrantError())
  }
}

// ---------------------------------------------------------------------------
// Authorization Code Grant
// ---------------------------------------------------------------------------

async function handleAuthorizationCode(
  ctx: Context,
  body: Record<string, string>
): Promise<Response> {
  const { code, redirect_uri, client_id, client_secret, code_verifier } = body

  if (!code || !redirect_uri || !client_id) {
    return errorResponse(
      ctx,
      new InvalidRequestError('The code, redirect_uri, and client_id parameters are required.')
    )
  }

  // Look up client
  const client = await OAuthClient.find(client_id)
  if (!client || client.revoked) {
    return errorResponse(ctx, new InvalidClientError())
  }

  // Authenticate client
  if (client.confidential) {
    if (!client_secret) {
      return errorResponse(
        ctx,
        new InvalidClientError('Client secret is required for confidential clients.')
      )
    }
    const valid = await OAuthClient.verifySecret(client, client_secret)
    if (!valid) {
      return errorResponse(ctx, new InvalidClientError())
    }
  }

  // Consume auth code (validates expiry, redirect_uri, PKCE)
  const codeData = await AuthCode.consume(code, client_id, redirect_uri, code_verifier)
  if (!codeData) {
    return errorResponse(ctx, new InvalidGrantError())
  }

  // Issue tokens
  const { accessToken, refreshToken, tokenData } = await OAuthToken.create({
    userId: codeData.userId,
    clientId: client_id,
    scopes: codeData.scopes,
    includeRefreshToken: client.grantTypes.includes('refresh_token'),
  })

  if (Emitter.listenerCount(OAuth2Events.TOKEN_ISSUED) > 0) {
    Emitter.emit(OAuth2Events.TOKEN_ISSUED, {
      ctx,
      userId: codeData.userId,
      clientId: client_id,
      grantType: 'authorization_code',
    }).catch(() => {})
  }

  return tokenResponse(ctx, accessToken, refreshToken, tokenData.scopes, tokenData.expiresAt)
}

// ---------------------------------------------------------------------------
// Client Credentials Grant
// ---------------------------------------------------------------------------

async function handleClientCredentials(
  ctx: Context,
  body: Record<string, string>
): Promise<Response> {
  const { client_id, client_secret, scope } = body

  if (!client_id || !client_secret) {
    return errorResponse(
      ctx,
      new InvalidRequestError('The client_id and client_secret parameters are required.')
    )
  }

  const client = await OAuthClient.find(client_id)
  if (!client || client.revoked) {
    return errorResponse(ctx, new InvalidClientError())
  }

  if (!client.confidential) {
    return errorResponse(
      ctx,
      new InvalidClientError('Client credentials grant requires a confidential client.')
    )
  }

  if (!client.grantTypes.includes('client_credentials')) {
    return errorResponse(
      ctx,
      new InvalidGrantError('This client does not support the client_credentials grant.')
    )
  }

  const valid = await OAuthClient.verifySecret(client, client_secret)
  if (!valid) {
    return errorResponse(ctx, new InvalidClientError())
  }

  // Validate scopes
  const requestedScopes = scope ? scope.split(' ').filter(Boolean) : []
  let scopes: string[]
  try {
    scopes = ScopeRegistry.validate(
      requestedScopes,
      client.scopes,
      OAuth2Manager.config.defaultScopes
    )
  } catch (err) {
    return errorResponse(ctx, err as Error)
  }

  // Issue access token only (no refresh token, no user)
  const { accessToken, tokenData } = await OAuthToken.create({
    userId: null,
    clientId: client_id,
    scopes,
    includeRefreshToken: false,
  })

  if (Emitter.listenerCount(OAuth2Events.TOKEN_ISSUED) > 0) {
    Emitter.emit(OAuth2Events.TOKEN_ISSUED, {
      ctx,
      clientId: client_id,
      grantType: 'client_credentials',
    }).catch(() => {})
  }

  return tokenResponse(ctx, accessToken, null, tokenData.scopes, tokenData.expiresAt)
}

// ---------------------------------------------------------------------------
// Refresh Token Grant
// ---------------------------------------------------------------------------

async function handleRefreshToken(ctx: Context, body: Record<string, string>): Promise<Response> {
  const { refresh_token, client_id, client_secret, scope } = body

  if (!refresh_token || !client_id) {
    return errorResponse(
      ctx,
      new InvalidRequestError('The refresh_token and client_id parameters are required.')
    )
  }

  const client = await OAuthClient.find(client_id)
  if (!client || client.revoked) {
    return errorResponse(ctx, new InvalidClientError())
  }

  // Authenticate confidential clients
  if (client.confidential) {
    if (!client_secret) {
      return errorResponse(
        ctx,
        new InvalidClientError('Client secret is required for confidential clients.')
      )
    }
    const valid = await OAuthClient.verifySecret(client, client_secret)
    if (!valid) {
      return errorResponse(ctx, new InvalidClientError())
    }
  }

  // Validate refresh token
  const oldToken = await OAuthToken.validateRefreshToken(refresh_token)
  if (!oldToken || oldToken.clientId !== client_id) {
    return errorResponse(ctx, new InvalidGrantError())
  }

  // Optionally narrow scopes (cannot widen)
  let scopes = oldToken.scopes
  if (scope) {
    const requested = scope.split(' ').filter(Boolean)
    const widened = requested.filter(s => !oldToken.scopes.includes(s))
    if (widened.length > 0) {
      return errorResponse(
        ctx,
        new InvalidRequestError(
          `Cannot widen scopes on refresh. Unknown scopes: ${widened.join(', ')}`
        )
      )
    }
    scopes = requested
  }

  // Revoke old token (rotation)
  await OAuthToken.revoke(oldToken.id)

  // Issue new token pair
  const { accessToken, refreshToken, tokenData } = await OAuthToken.create({
    userId: oldToken.userId,
    clientId: client_id,
    scopes,
    includeRefreshToken: true,
  })

  if (Emitter.listenerCount(OAuth2Events.TOKEN_REFRESHED) > 0) {
    Emitter.emit(OAuth2Events.TOKEN_REFRESHED, {
      ctx,
      userId: oldToken.userId,
      clientId: client_id,
    }).catch(() => {})
  }

  return tokenResponse(ctx, accessToken, refreshToken, tokenData.scopes, tokenData.expiresAt)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function tokenResponse(
  ctx: Context,
  accessToken: string,
  refreshToken: string | null,
  scopes: string[],
  expiresAt: Date
): Response {
  const expiresIn = Math.floor((expiresAt.getTime() - Date.now()) / 1000)

  const payload: Record<string, unknown> = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: expiresIn,
    scope: scopes.join(' '),
  }

  if (refreshToken) {
    payload.refresh_token = refreshToken
  }

  return ctx.json(payload)
}

function errorResponse(ctx: Context, error: Error): Response {
  if ('toJSON' in error && typeof error.toJSON === 'function') {
    const statusCode = (error as any).statusCode ?? 400
    return ctx.json(error.toJSON(), statusCode)
  }
  return ctx.json({ error: 'server_error', error_description: error.message }, 500)
}
