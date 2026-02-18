import { test, expect, describe, beforeEach } from 'bun:test'
import {
  bootOAuth2,
  resetStores,
  resetUserStore,
  createMockUser,
  mockContext,
  getTokenStore,
} from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import OAuthToken from '../../src/token.ts'
import { revokeHandler } from '../../src/handlers/revoke.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('revokeHandler (POST /oauth/revoke)', () => {
  test('revokes a valid access token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { accessToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: [],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/revoke',
      body: { token: accessToken },
    })

    const res = await revokeHandler(ctx)
    expect(res.status).toBe(200)

    // Token should be revoked in store
    const stored = getTokenStore()[0]!
    expect(stored.revoked_at).not.toBeNull()
  })

  test('revokes a valid refresh token', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { refreshToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: [],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/revoke',
      body: { token: refreshToken },
    })

    const res = await revokeHandler(ctx)
    expect(res.status).toBe(200)

    const stored = getTokenStore()[0]!
    expect(stored.revoked_at).not.toBeNull()
  })

  test('returns 200 even for non-existent token (RFC 7009)', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/revoke',
      body: { token: 'nonexistent-token' },
    })

    const res = await revokeHandler(ctx)
    expect(res.status).toBe(200)
  })

  test('rejects missing token parameter', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/revoke',
      body: {},
    })

    const res = await revokeHandler(ctx)
    expect(res.status).toBe(400)
  })

  test('validates client credentials when provided', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/revoke',
      body: {
        token: 'some-token',
        client_id: client.id,
        client_secret: 'wrong-secret',
      },
    })

    const res = await revokeHandler(ctx)
    expect(res.status).toBe(401)
  })
})
