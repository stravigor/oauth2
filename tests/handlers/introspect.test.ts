import { test, expect, describe, beforeEach } from 'bun:test'
import { bootOAuth2, resetStores, resetUserStore, createMockUser, mockContext } from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import OAuthToken from '../../src/token.ts'
import { introspectHandler } from '../../src/handlers/introspect.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('introspectHandler (POST /oauth/introspect)', () => {
  test('returns active=true for valid token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { accessToken, tokenData } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: ['read', 'write'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/introspect',
      body: { token: accessToken },
    })

    const res = await introspectHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.active).toBe(true)
    expect(body.scope).toBe('read write')
    expect(body.client_id).toBe(client.id)
    expect(body.token_type).toBe('Bearer')
    expect(body.sub).toBe(String(user.id))
    expect(body.exp).toBeDefined()
    expect(body.iat).toBeDefined()
  })

  test('returns active=false for invalid token', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/introspect',
      body: { token: 'invalid-token' },
    })

    const res = await introspectHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.active).toBe(false)
    expect(body.scope).toBeUndefined()
  })

  test('returns active=false for revoked token', async () => {
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
      method: 'POST',
      path: '/oauth/introspect',
      body: { token: accessToken },
    })

    const res = await introspectHandler(ctx)
    const body = await res.json()
    expect(body.active).toBe(false)
  })

  test('rejects missing token parameter', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/introspect',
      body: {},
    })

    const res = await introspectHandler(ctx)
    expect(res.status).toBe(400)
  })

  test('omits sub for client_credentials tokens', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Machine',
      redirectUris: [],
      grantTypes: ['client_credentials'],
    })

    const { accessToken } = await OAuthToken.create({
      userId: null,
      clientId: client.id,
      scopes: [],
      includeRefreshToken: false,
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/introspect',
      body: { token: accessToken },
    })

    const res = await introspectHandler(ctx)
    const body = await res.json()
    expect(body.active).toBe(true)
    expect(body.sub).toBeUndefined()
  })
})
