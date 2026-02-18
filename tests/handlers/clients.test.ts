import { test, expect, describe, beforeEach } from 'bun:test'
import {
  bootOAuth2,
  resetStores,
  resetUserStore,
  createMockUser,
  mockContext,
  mockAuthenticatedContext,
} from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import {
  listClientsHandler,
  createClientHandler,
  deleteClientHandler,
} from '../../src/handlers/clients.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('listClientsHandler (GET /oauth/clients)', () => {
  test('lists all non-revoked clients', async () => {
    await OAuthClient.create({ name: 'App 1', redirectUris: ['https://a.com'] })
    await OAuthClient.create({ name: 'App 2', redirectUris: ['https://b.com'] })

    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, { path: '/oauth/clients' })

    const res = await listClientsHandler(ctx)
    expect(res.status).toBe(200)

    const body = await res.json()
    expect(body.clients).toHaveLength(2)
    expect(body.clients[0].name).toBeDefined()
    // Should not include the secret
    expect(body.clients[0].secret).toBeUndefined()
  })
})

describe('createClientHandler (POST /oauth/clients)', () => {
  test('creates a new client', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/clients',
      body: {
        name: 'New App',
        redirect_uris: ['https://newapp.com/callback'],
      },
    })

    const res = await createClientHandler(ctx)
    expect(res.status).toBe(201)

    const body = await res.json()
    expect(body.client.name).toBe('New App')
    expect(body.client.id).toBeDefined()
    expect(body.secret).not.toBeNull() // confidential by default
  })

  test('rejects missing name', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/clients',
      body: { redirect_uris: ['https://example.com'] },
    })

    const res = await createClientHandler(ctx)
    expect(res.status).toBe(422)
  })

  test('rejects missing redirect_uris', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/clients',
      body: { name: 'Test' },
    })

    const res = await createClientHandler(ctx)
    expect(res.status).toBe(422)
  })

  test('creates public client', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'POST',
      path: '/oauth/clients',
      body: {
        name: 'SPA',
        redirect_uris: ['http://localhost:3000'],
        confidential: false,
      },
    })

    const res = await createClientHandler(ctx)
    const body = await res.json()
    expect(body.client.confidential).toBe(false)
    expect(body.secret).toBeNull()
  })
})

describe('deleteClientHandler (DELETE /oauth/clients/:id)', () => {
  test('revokes a client', async () => {
    const { client } = await OAuthClient.create({
      name: 'To Delete',
      redirectUris: ['https://example.com'],
    })
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'DELETE',
      path: `/oauth/clients/${client.id}`,
      params: { id: client.id },
    })

    const res = await deleteClientHandler(ctx)
    expect(res.status).toBe(200)

    const found = await OAuthClient.findIncludingRevoked(client.id)
    expect(found!.revoked).toBe(true)
  })

  test('returns 404 for non-existent client', async () => {
    const user = createMockUser()
    const { ctx } = mockAuthenticatedContext(user, {
      method: 'DELETE',
      path: '/oauth/clients/nonexistent',
      params: { id: 'nonexistent' },
    })

    const res = await deleteClientHandler(ctx)
    expect(res.status).toBe(404)
  })
})
