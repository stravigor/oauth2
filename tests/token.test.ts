import { test, expect, describe, beforeEach } from 'bun:test'
import {
  bootOAuth2,
  resetStores,
  resetUserStore,
  createMockUser,
  getTokenStore,
} from './helpers.ts'
import OAuthClient from '../src/client.ts'
import OAuthToken from '../src/token.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('OAuthToken', () => {
  async function createTestClient() {
    const { client } = await OAuthClient.create({
      name: 'Test App',
      redirectUris: ['https://example.com/callback'],
    })
    return client
  }

  describe('create', () => {
    test('creates access token and refresh token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { accessToken, refreshToken, tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: ['read', 'write'],
      })

      expect(accessToken).toBeDefined()
      expect(accessToken.length).toBe(80) // 40 bytes = 80 hex chars
      expect(refreshToken).toBeDefined()
      expect(refreshToken!.length).toBe(80)

      expect(tokenData.userId).toBe(String(user.id))
      expect(tokenData.clientId).toBe(client.id)
      expect(tokenData.scopes).toEqual(['read', 'write'])
      expect(tokenData.revokedAt).toBeNull()

      // Token in store should be hashed, not plaintext
      const stored = getTokenStore()[0]!
      expect(stored.token).not.toBe(accessToken)
    })

    test('creates token without refresh token when disabled', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { refreshToken } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
        includeRefreshToken: false,
      })

      expect(refreshToken).toBeNull()
    })

    test('creates client_credentials token (no user, no refresh)', async () => {
      const client = await createTestClient()

      const { accessToken, refreshToken, tokenData } = await OAuthToken.create({
        userId: null,
        clientId: client.id,
        scopes: ['read'],
        includeRefreshToken: false,
      })

      expect(accessToken).toBeDefined()
      expect(refreshToken).toBeNull()
      expect(tokenData.userId).toBeNull()
    })

    test('respects custom token lifetime', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
        accessTokenLifetime: 5, // 5 minutes
      })

      const expectedExpiry = Date.now() + 5 * 60_000
      const diff = Math.abs(tokenData.expiresAt.getTime() - expectedExpiry)
      expect(diff).toBeLessThan(1000) // within 1 second
    })

    test('sets name for personal access tokens', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
        name: 'CLI Tool',
        includeRefreshToken: false,
      })

      expect(tokenData.name).toBe('CLI Tool')
    })
  })

  describe('validate', () => {
    test('validates a valid access token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { accessToken } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: ['read'],
      })

      const validated = await OAuthToken.validate(accessToken)
      expect(validated).not.toBeNull()
      expect(validated!.scopes).toEqual(['read'])
      expect(validated!.userId).toBe(String(user.id))
    })

    test('returns null for non-existent token', async () => {
      const validated = await OAuthToken.validate('nonexistent')
      expect(validated).toBeNull()
    })

    test('returns null for expired token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { accessToken } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
        accessTokenLifetime: -1, // expired
      })

      const validated = await OAuthToken.validate(accessToken)
      expect(validated).toBeNull()
    })

    test('returns null for revoked token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { accessToken, tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
      })

      await OAuthToken.revoke(tokenData.id)

      const validated = await OAuthToken.validate(accessToken)
      expect(validated).toBeNull()
    })
  })

  describe('validateRefreshToken', () => {
    test('validates a valid refresh token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { refreshToken } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: ['read'],
      })

      const validated = await OAuthToken.validateRefreshToken(refreshToken!)
      expect(validated).not.toBeNull()
      expect(validated!.userId).toBe(String(user.id))
    })

    test('returns null for revoked refresh token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { refreshToken, tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
      })

      await OAuthToken.revoke(tokenData.id)

      const validated = await OAuthToken.validateRefreshToken(refreshToken!)
      expect(validated).toBeNull()
    })
  })

  describe('revoke', () => {
    test('soft-revokes a token', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      const { tokenData } = await OAuthToken.create({
        userId: String(user.id),
        clientId: client.id,
        scopes: [],
      })

      await OAuthToken.revoke(tokenData.id)

      const stored = getTokenStore()[0]!
      expect(stored.revoked_at).not.toBeNull()
    })
  })

  describe('revokeAllFor', () => {
    test('revokes all tokens for a user', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      await OAuthToken.create({ userId: String(user.id), clientId: client.id, scopes: [] })
      await OAuthToken.create({ userId: String(user.id), clientId: client.id, scopes: [] })

      await OAuthToken.revokeAllFor(String(user.id))

      const store = getTokenStore()
      expect(store.every(t => t.revoked_at !== null)).toBe(true)
    })
  })

  describe('allForUser', () => {
    test('lists active tokens for a user', async () => {
      const client = await createTestClient()
      const user = createMockUser()

      await OAuthToken.create({ userId: String(user.id), clientId: client.id, scopes: [] })
      await OAuthToken.create({ userId: String(user.id), clientId: client.id, scopes: [] })

      const tokens = await OAuthToken.allForUser(String(user.id))
      expect(tokens).toHaveLength(2)
    })
  })

  describe('personalTokensFor', () => {
    test('returns empty when no PAT client configured', async () => {
      const user = createMockUser()
      const tokens = await OAuthToken.personalTokensFor(String(user.id))
      expect(tokens).toEqual([])
    })
  })
})
