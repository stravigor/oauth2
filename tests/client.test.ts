import { test, expect, describe, beforeEach } from 'bun:test'
import { bootOAuth2, resetStores, getClientStore } from './helpers.ts'
import OAuthClient from '../src/client.ts'

beforeEach(() => {
  resetStores()
  bootOAuth2()
})

describe('OAuthClient', () => {
  describe('create', () => {
    test('creates a confidential client with hashed secret', async () => {
      const { client, plainSecret } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      expect(client.name).toBe('Test App')
      expect(client.redirectUris).toEqual(['https://example.com/callback'])
      expect(client.confidential).toBe(true)
      expect(client.firstParty).toBe(false)
      expect(client.revoked).toBe(false)
      expect(client.grantTypes).toEqual(['authorization_code', 'refresh_token'])
      expect(plainSecret).not.toBeNull()
      expect(plainSecret!.length).toBe(64) // 32 bytes = 64 hex chars

      // Secret should be hashed in store
      const stored = getClientStore()[0]!
      expect(stored.secret).not.toBe(plainSecret)
      expect(stored.secret).not.toBeNull()
    })

    test('creates a public client with no secret', async () => {
      const { client, plainSecret } = await OAuthClient.create({
        name: 'SPA App',
        redirectUris: ['http://localhost:3000/callback'],
        confidential: false,
      })

      expect(client.confidential).toBe(false)
      expect(plainSecret).toBeNull()

      const stored = getClientStore()[0]!
      expect(stored.secret).toBeNull()
    })

    test('creates a first-party client', async () => {
      const { client } = await OAuthClient.create({
        name: 'Admin Dashboard',
        redirectUris: ['https://admin.example.com'],
        firstParty: true,
      })

      expect(client.firstParty).toBe(true)
    })

    test('supports custom grant types', async () => {
      const { client } = await OAuthClient.create({
        name: 'Machine Client',
        redirectUris: [],
        grantTypes: ['client_credentials'],
      })

      expect(client.grantTypes).toEqual(['client_credentials'])
    })

    test('supports restricted scopes', async () => {
      const { client } = await OAuthClient.create({
        name: 'Limited App',
        redirectUris: ['https://example.com/callback'],
        scopes: ['read'],
      })

      expect(client.scopes).toEqual(['read'])
    })
  })

  describe('find', () => {
    test('finds a client by ID', async () => {
      const { client: created } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      const found = await OAuthClient.find(created.id)
      expect(found).not.toBeNull()
      expect(found!.id).toBe(created.id)
      expect(found!.name).toBe('Test App')
    })

    test('returns null for non-existent client', async () => {
      const found = await OAuthClient.find('non-existent')
      expect(found).toBeNull()
    })
  })

  describe('verifySecret', () => {
    test('verifies correct secret', async () => {
      const { client, plainSecret } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      const valid = await OAuthClient.verifySecret(client, plainSecret!)
      expect(valid).toBe(true)
    })

    test('rejects wrong secret', async () => {
      const { client } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      const valid = await OAuthClient.verifySecret(client, 'wrong-secret')
      expect(valid).toBe(false)
    })

    test('returns false for public clients', async () => {
      const { client } = await OAuthClient.create({
        name: 'Public App',
        redirectUris: ['https://example.com/callback'],
        confidential: false,
      })

      const valid = await OAuthClient.verifySecret(client, 'anything')
      expect(valid).toBe(false)
    })
  })

  describe('all', () => {
    test('lists non-revoked clients', async () => {
      await OAuthClient.create({ name: 'App 1', redirectUris: ['https://a.com'] })
      const { client: app2 } = await OAuthClient.create({
        name: 'App 2',
        redirectUris: ['https://b.com'],
      })
      await OAuthClient.create({ name: 'App 3', redirectUris: ['https://c.com'] })

      // Revoke one
      await OAuthClient.revoke(app2.id)

      const all = await OAuthClient.all()
      expect(all).toHaveLength(2)
      expect(all.find(c => c.name === 'App 2')).toBeUndefined()
    })
  })

  describe('revoke', () => {
    test('soft-revokes a client', async () => {
      const { client } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      await OAuthClient.revoke(client.id)

      const stored = getClientStore()[0]!
      expect(stored.revoked).toBe(true)
    })
  })

  describe('findIncludingRevoked', () => {
    test('finds revoked clients', async () => {
      const { client } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      await OAuthClient.revoke(client.id)

      const found = await OAuthClient.findIncludingRevoked(client.id)
      expect(found).not.toBeNull()
      expect(found!.revoked).toBe(true)
    })
  })

  describe('destroy', () => {
    test('hard-deletes a client', async () => {
      const { client } = await OAuthClient.create({
        name: 'Test App',
        redirectUris: ['https://example.com/callback'],
      })

      await OAuthClient.destroy(client.id)

      expect(getClientStore()).toHaveLength(0)
    })
  })
})
