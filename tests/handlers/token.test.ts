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
import AuthCode from '../../src/auth_code.ts'
import ScopeRegistry from '../../src/scopes.ts'
import { tokenHandler } from '../../src/handlers/token.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2({ scopes: { read: 'Read', write: 'Write' } })
})

describe('tokenHandler — authorization_code grant', () => {
  test('exchanges code for tokens', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { code } = await AuthCode.create({
      clientId: client.id,
      userId: String(user.id),
      redirectUri: 'https://example.com/callback',
      scopes: ['read'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://example.com/callback',
        client_id: client.id,
        client_secret: plainSecret,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.access_token).toBeDefined()
    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBeGreaterThan(0)
    expect(body.refresh_token).toBeDefined()
    expect(body.scope).toBe('read')
  })

  test('rejects missing required parameters', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: { grant_type: 'authorization_code' },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)

    const body = await res.json()
    expect(body.error).toBe('invalid_request')
  })

  test('rejects invalid client credentials', async () => {
    const { client } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })
    const user = createMockUser()

    const { code } = await AuthCode.create({
      clientId: client.id,
      userId: String(user.id),
      redirectUri: 'https://example.com/callback',
      scopes: [],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://example.com/callback',
        client_id: client.id,
        client_secret: 'wrong-secret',
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(401)
  })

  test('rejects invalid authorization code', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'authorization_code',
        code: 'invalid-code',
        redirect_uri: 'https://example.com/callback',
        client_id: client.id,
        client_secret: plainSecret,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)

    const body = await res.json()
    expect(body.error).toBe('invalid_grant')
  })

  test('exchanges code with PKCE (no client secret)', async () => {
    const { client } = await OAuthClient.create({
      name: 'Public App',
      redirectUris: ['https://example.com/callback'],
      confidential: false,
    })
    const user = createMockUser()

    const verifier = 'my-code-verifier-string-that-is-long-enough'
    const challenge = new Bun.CryptoHasher('sha256').update(verifier).digest('base64url')

    const { code } = await AuthCode.create({
      clientId: client.id,
      userId: String(user.id),
      redirectUri: 'https://example.com/callback',
      scopes: ['read'],
      codeChallenge: challenge,
      codeChallengeMethod: 'S256',
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://example.com/callback',
        client_id: client.id,
        code_verifier: verifier,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.access_token).toBeDefined()
  })
})

describe('tokenHandler — client_credentials grant', () => {
  test('issues token for confidential client', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Machine Client',
      redirectUris: [],
      grantTypes: ['client_credentials'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'client_credentials',
        client_id: client.id,
        client_secret: plainSecret,
        scope: 'read',
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.access_token).toBeDefined()
    expect(body.token_type).toBe('Bearer')
    expect(body.refresh_token).toBeUndefined()
    expect(body.scope).toBe('read')

    // Should not have a user
    const store = getTokenStore()
    const token = store[store.length - 1]!
    expect(token.user_id).toBeNull()
  })

  test('rejects public client', async () => {
    const { client } = await OAuthClient.create({
      name: 'Public',
      redirectUris: [],
      confidential: false,
      grantTypes: ['client_credentials'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'client_credentials',
        client_id: client.id,
        client_secret: 'none',
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(401)
  })

  test('rejects client without client_credentials grant', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Web App',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'client_credentials',
        client_id: client.id,
        client_secret: plainSecret,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('invalid_grant')
  })

  test('rejects wrong secret', async () => {
    const { client } = await OAuthClient.create({
      name: 'Machine',
      redirectUris: [],
      grantTypes: ['client_credentials'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'client_credentials',
        client_id: client.id,
        client_secret: 'wrong',
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(401)
  })
})

describe('tokenHandler — refresh_token grant', () => {
  test('rotates tokens on refresh', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
    })
    const user = createMockUser()

    const { refreshToken: oldRefresh } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: ['read', 'write'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'refresh_token',
        refresh_token: oldRefresh,
        client_id: client.id,
        client_secret: plainSecret,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.access_token).toBeDefined()
    expect(body.refresh_token).toBeDefined()
    expect(body.scope).toBe('read write')

    // Old token should be revoked
    const store = getTokenStore()
    expect(store[0]!.revoked_at).not.toBeNull()
  })

  test('allows narrowing scopes on refresh', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
    })
    const user = createMockUser()

    const { refreshToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: ['read', 'write'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: client.id,
        client_secret: plainSecret,
        scope: 'read', // narrowed
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.scope).toBe('read')
  })

  test('rejects widening scopes on refresh', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['authorization_code', 'refresh_token'],
    })
    const user = createMockUser()

    const { refreshToken } = await OAuthToken.create({
      userId: String(user.id),
      clientId: client.id,
      scopes: ['read'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: client.id,
        client_secret: plainSecret,
        scope: 'read write', // wider than original
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)

    const body = await res.json()
    expect(body.error).toBe('invalid_request')
  })

  test('rejects invalid refresh token', async () => {
    const { client, plainSecret } = await OAuthClient.create({
      name: 'Test',
      redirectUris: ['https://example.com/callback'],
    })

    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {
        grant_type: 'refresh_token',
        refresh_token: 'invalid',
        client_id: client.id,
        client_secret: plainSecret,
      },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)
    const body = await res.json()
    expect(body.error).toBe('invalid_grant')
  })
})

describe('tokenHandler — unsupported grant', () => {
  test('rejects unknown grant_type', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: { grant_type: 'password' },
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)

    const body = await res.json()
    expect(body.error).toBe('unsupported_grant_type')
  })

  test('rejects missing grant_type', async () => {
    const ctx = mockContext({
      method: 'POST',
      path: '/oauth/token',
      body: {},
    })

    const res = await tokenHandler(ctx)
    expect(res.status).toBe(400)

    const body = await res.json()
    expect(body.error).toBe('invalid_request')
  })
})
