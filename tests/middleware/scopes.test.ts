import { test, expect, describe, beforeEach } from 'bun:test'
import { bootOAuth2, resetStores, resetUserStore, createMockUser, mockContext } from '../helpers.ts'
import OAuthClient from '../../src/client.ts'
import OAuthToken from '../../src/token.ts'
import { scopes } from '../../src/middleware/scopes.ts'
import type { OAuthTokenData } from '../../src/types.ts'

beforeEach(() => {
  resetStores()
  resetUserStore()
  bootOAuth2()
})

describe('scopes() middleware', () => {
  function mockContextWithToken(tokenScopes: string[]) {
    const ctx = mockContext()
    ctx.set('oauth_token', {
      id: 'tok-1',
      userId: '1',
      clientId: 'cli-1',
      name: null,
      scopes: tokenScopes,
      expiresAt: new Date(Date.now() + 3600_000),
      refreshExpiresAt: null,
      lastUsedAt: null,
      revokedAt: null,
      createdAt: new Date(),
    } satisfies OAuthTokenData)
    return ctx
  }

  test('passes when token has all required scopes', async () => {
    const ctx = mockContextWithToken(['read', 'write', 'admin'])

    let nextCalled = false
    const mw = scopes('read', 'write')
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(true)
    expect(res.status).toBe(200)
  })

  test('rejects when token is missing required scopes', async () => {
    const ctx = mockContextWithToken(['read'])

    let nextCalled = false
    const mw = scopes('read', 'write')
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(false)
    expect(res.status).toBe(403)

    const body = await res.json()
    expect(body.error).toBe('insufficient_scope')
    expect(body.error_description).toContain('write')
  })

  test('rejects when no oauth_token on context', async () => {
    const ctx = mockContext()

    const mw = scopes('read')
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    expect(res.status).toBe(401)
  })

  test('passes with single required scope', async () => {
    const ctx = mockContextWithToken(['read'])

    let nextCalled = false
    const mw = scopes('read')
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(true)
  })

  test('passes when no scopes are required', async () => {
    const ctx = mockContextWithToken([])

    let nextCalled = false
    const mw = scopes()
    const res = await mw(ctx, async () => {
      nextCalled = true
      return ctx.json({ ok: true })
    })

    expect(nextCalled).toBe(true)
  })

  test('lists all missing scopes in error message', async () => {
    const ctx = mockContextWithToken([])

    const mw = scopes('read', 'write', 'admin')
    const res = await mw(ctx, async () => ctx.json({ ok: true }))

    const body = await res.json()
    expect(body.error_description).toContain('read')
    expect(body.error_description).toContain('write')
    expect(body.error_description).toContain('admin')
  })
})
