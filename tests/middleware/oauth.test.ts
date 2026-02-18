import { test, expect, describe, beforeEach } from 'bun:test'
import { bootOAuth2, resetStores, resetUserStore, createMockUser, mockContext } from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import OAuthToken from '../../src/token.ts'
import { oauth } from '../../src/middleware/oauth.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('oauth() middleware', () => {
  test('authenticates with valid Bearer token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { accessToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: ['read'],
    })

    const ctx = mockContext({
      headers: { authorization: `Bearer ${accessToken}` },
    })

    let nextCalled = false
    const mw = oauth()
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(true)
    expect(res.status).toBe(200)

    // User should be set on context
    const contextUser = ctx.get<MockUser>('user')
    expect(contextUser).toBeDefined()
    expect(contextUser.id).toBe(user.id)

    // Token data should be set
    const tokenData = ctx.get('oauth_token')
    expect(tokenData).toBeDefined()

    // Client should be set
    const clientData = ctx.get('oauth_client')
    expect(clientData).toBeDefined()
  })

  test('rejects missing Authorization header', async () => {
    const ctx = mockContext({})

    let nextCalled = false
    const mw = oauth()
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(false)
    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('unauthenticated')
  })

  test('rejects non-Bearer authorization', async () => {
    const ctx = mockContext({
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    })

    const mw = oauth()
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)
  })

  test('rejects invalid token', async () => {
    const ctx = mockContext({
      headers: { authorization: 'Bearer invalid-token' },
    })

    const mw = oauth()
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)

    const body = await res.json()
    expect(body.error).toBe('invalid_token')
  })

  test('rejects expired token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { accessToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: [],
      accessTokenLifetime: -1, // expired
    })

    const ctx = mockContext({
      headers: { authorization: `Bearer ${accessToken}` },
    })

    const mw = oauth()
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)
  })

  test('rejects revoked token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { accessToken, tokenData } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: [],
    })

    await OAuthToken.revoke(tokenData.id)

    const ctx = mockContext({
      headers: { authorization: `Bearer ${accessToken}` },
    })

    const mw = oauth()
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)
  })

  test('authenticates client_credentials token (no user)', async () => {
    const { client } = await OAuthClient.create({
      name: 'Machine',
      redirectUris: [],
      grantTypes: ['client_credentials'],
    })

    const { accessToken } = await OAuthToken.create({
      userId: null,
      clientId: client.id,
      scopes: ['read'],
      includeRefreshToken: false,
    })

    const ctx = mockContext({
      headers: { authorization: `Bearer ${accessToken}` },
    })

    let nextCalled = false
    const mw = oauth()
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(true)
    // No user should be set for client_credentials
    expect(ctx.get('user')).toBeUndefined()
  })

  test('rejects token whose user no longer exists', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })

    // Create token for user ID 999 which doesn't exist in store
    const { accessToken } = await OAuthToken.create({
      userId: '999',
      clientId: client.id,
      scopes: [],
    })

    const ctx = mockContext({
      headers: { authorization: `Bearer ${accessToken}` },
    })

    const mw = oauth()
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)
  })
})
