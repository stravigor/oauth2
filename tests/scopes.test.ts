import { test, expect, describe, beforeEach } from 'bun:test'
import ScopeRegistry from '../src/scopes.ts'
import { InvalidScopeError } from '../src/errors.ts'

beforeEach(() => {
  ScopeRegistry.reset()
})

describe('ScopeRegistry', () => {
  test('define and check scopes', () => {
    ScopeRegistry.define({ read: 'Read access', write: 'Write access' })

    expect(ScopeRegistry.has('read')).toBe(true)
    expect(ScopeRegistry.has('write')).toBe(true)
    expect(ScopeRegistry.has('admin')).toBe(false)
  })

  test('all returns registered scopes', () => {
    ScopeRegistry.define({ read: 'Read access', write: 'Write access' })

    const all = ScopeRegistry.all()
    expect(all).toHaveLength(2)
    expect(all).toContainEqual({ name: 'read', description: 'Read access' })
    expect(all).toContainEqual({ name: 'write', description: 'Write access' })
  })

  test('describe returns descriptions for scope names', () => {
    ScopeRegistry.define({ read: 'Read access', write: 'Write access' })

    const descs = ScopeRegistry.describe(['read'])
    expect(descs).toEqual([{ name: 'read', description: 'Read access' }])
  })

  test('describe falls back to scope name when not registered', () => {
    const descs = ScopeRegistry.describe(['unknown'])
    expect(descs).toEqual([{ name: 'unknown', description: 'unknown' }])
  })

  test('validate returns requested scopes when valid', () => {
    ScopeRegistry.define({ read: 'Read', write: 'Write' })

    const scopes = ScopeRegistry.validate(['read', 'write'], null, [])
    expect(scopes).toEqual(['read', 'write'])
  })

  test('validate returns default scopes when none requested', () => {
    ScopeRegistry.define({ read: 'Read', write: 'Write' })

    const scopes = ScopeRegistry.validate([], null, ['read'])
    expect(scopes).toEqual(['read'])
  })

  test('validate returns empty when no scopes requested and no defaults', () => {
    const scopes = ScopeRegistry.validate([], null, [])
    expect(scopes).toEqual([])
  })

  test('validate throws for unknown scopes', () => {
    ScopeRegistry.define({ read: 'Read' })

    expect(() => ScopeRegistry.validate(['admin'], null, [])).toThrow(InvalidScopeError)
  })

  test('validate throws when scope is not allowed for client', () => {
    ScopeRegistry.define({ read: 'Read', write: 'Write', admin: 'Admin' })

    expect(() => ScopeRegistry.validate(['admin'], ['read', 'write'], [])).toThrow(
      InvalidScopeError
    )
  })

  test('validate succeeds when scope is allowed for client', () => {
    ScopeRegistry.define({ read: 'Read', write: 'Write' })

    const scopes = ScopeRegistry.validate(['read'], ['read', 'write'], [])
    expect(scopes).toEqual(['read'])
  })

  test('reset clears all scopes', () => {
    ScopeRegistry.define({ read: 'Read' })
    expect(ScopeRegistry.has('read')).toBe(true)

    ScopeRegistry.reset()
    expect(ScopeRegistry.has('read')).toBe(false)
    expect(ScopeRegistry.all()).toHaveLength(0)
  })

  test('define merges with existing scopes', () => {
    ScopeRegistry.define({ read: 'Read' })
    ScopeRegistry.define({ write: 'Write' })

    expect(ScopeRegistry.has('read')).toBe(true)
    expect(ScopeRegistry.has('write')).toBe(true)
  })
})
