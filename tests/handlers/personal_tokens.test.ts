import { test, expect, describe, beforeEach } from 'bun:test'
import {
  bootOAuth2,
  resetStores,
  resetUserStore,
  createMockUser,
  mockAuthenticatedContext,
  getTokenStore,
} from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import OAuthToken from '../../src/token.ts'
import ScopeRegistry from '../../src/scopes.ts'
import {
  createPersonalTokenHandler,
  listPersonalTokensHandler,
  revokePersonalTokenHandler,
} from '../../src/handlers/personal_tokens.ts'

let patClientId: string

beforeEach(async () => {
  resetStores()
  resetUserStore()

  // Boot with scopes
  bootOAuth2({ scopes: { read: 'Read', write: 'Write' } })

  // Create and register PAT client
  const { client } = await OAuthClient.create({
    name: 'Personal Access',
    redirectUris: [],
    firstParty: true,
    grantTypes: [],
  })
  patClientId = client.id

  // Update config with PAT client ID
  const mgr = (await import('../../src/oauth2_manager.ts')).default
  ;(mgr as any)._config.personalAccessClient = patClientId
})

describe('createPersonalTokenHandler (POST /oauth/personal-tokens)', () => {
  test('creates a personal access token', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/personal-tokens',
      body: { name: 'CLI Tool', scopes: ['read'] },
    })

    const res = await createPersonalTokenHandler(ctx)
    expect(res.status).toBe(201)

    const body = await res.json()
    expect(body.token).toBeDefined()
    expect(body.token.length).toBe(80)
    expect(body.accessToken.name).toBe('CLI Tool')
    expect(body.accessToken.scopes).toEqual(['read'])
  })

  test('rejects missing name', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/personal-tokens',
      body: { scopes: ['read'] },
    })

    const res = await createPersonalTokenHandler(ctx)
    expect(res.status).toBe(422)
  })

  test('rejects unknown scope', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/personal-tokens',
      body: { name: 'Test', scopes: ['admin'] },
    })

    const res = await createPersonalTokenHandler(ctx)
    expect(res.status).toBe(422)
  })

  test('creates token with no scopes', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/personal-tokens',
      body: { name: 'Basic Token' },
    })

    const res = await createPersonalTokenHandler(ctx)
    expect(res.status).toBe(201)

    const body = await res.json()
    expect(body.accessToken.scopes).toEqual([])
  })
})

describe('listPersonalTokensHandler (GET /oauth/personal-tokens)', () => {
  test('lists personal access tokens for user', async () => {
    const user = createMockUser()

    // Create PATs directly
    await OAuthToken.create({
      userId: String(user.id),
      clientId: patClientId,
      scopes: ['read'],
      name: 'Token 1',
      includeRefreshToken: false,
    })
    await OAuthToken.create({
      userId: String(user.id),
      clientId: patClientId,
      scopes: ['write'],
      name: 'Token 2',
      includeRefreshToken: false,
    })

    const { ctx } = mockAuthenticatedContext(user, {
      path: '/oauth/personal-tokens',
    })

    const res = await listPersonalTokensHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.tokens).toHaveLength(2)
    expect(body.tokens[0].name).toBeDefined()
    // Should not expose the token hash
    expect(body.tokens[0].token).toBeUndefined()
  })
})

describe('revokePersonalTokenHandler (DELETE /oauth/personal-tokens/:id)', () => {
  test('revokes a personal access token', async () => {
    const user = createMockUser()

    const { tokenData } = await OAuthToken.create({
      userId: String(user.id),
      clientId: patClientId,
      scopes: [],
      name: 'To Revoke',
      includeRefreshToken: false,
    })

    const { ctx } = mockAuthenticatedContext(user, {
      method: 'DELETE',
      path: `/oauth/personal-tokens/${tokenData.id}`,
      params: { id: tokenData.id },
    })

    const res = await revokePersonalTokenHandler(ctx)
    expect(res.status).toBe(200)

    const stored = getTokenStore()[0]!
    expect(stored.revoked_at).not.toBeNull()
  })
})
