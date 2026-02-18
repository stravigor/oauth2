import { InvalidScopeError } from './errors.ts'
import type { ScopeDescription } from './types.ts'

/**
 * Scope registry — manages available OAuth2 scopes and their descriptions.
 *
 * Scopes are loaded from config on boot and can be extended at runtime.
 */
export default class ScopeRegistry {
  private static _scopes = new Map<string, string>()

  /** Register scopes from a name→description record. */
  static define(scopes: Record<string, string>): void {
    for (const [name, description] of Object.entries(scopes)) {
      ScopeRegistry._scopes.set(name, description)
    }
  }

  /** Check if a scope is registered. */
  static has(name: string): boolean {
    return ScopeRegistry._scopes.has(name)
  }

  /** Get all registered scopes. */
  static all(): ScopeDescription[] {
    return Array.from(ScopeRegistry._scopes.entries()).map(([name, description]) => ({
      name,
      description,
    }))
  }

  /** Get descriptions for a list of scope names. */
  static describe(names: string[]): ScopeDescription[] {
    return names.map(name => ({
      name,
      description: ScopeRegistry._scopes.get(name) ?? name,
    }))
  }

  /**
   * Validate requested scopes against registered scopes and client-allowed scopes.
   *
   * - If no scopes are requested, returns defaultScopes.
   * - Throws InvalidScopeError if a scope is not registered.
   * - Throws InvalidScopeError if a scope is not allowed for the client.
   */
  static validate(
    requested: string[],
    clientAllowed: string[] | null,
    defaultScopes: string[]
  ): string[] {
    const scopes = requested.length > 0 ? requested : defaultScopes
    if (scopes.length === 0) return []

    for (const scope of scopes) {
      if (!ScopeRegistry._scopes.has(scope)) {
        throw new InvalidScopeError(`Unknown scope: "${scope}".`)
      }
    }

    // If client has restricted scopes, ensure all requested are allowed
    if (clientAllowed !== null) {
      for (const scope of scopes) {
        if (!clientAllowed.includes(scope)) {
          throw new InvalidScopeError(`Scope "${scope}" is not allowed for this client.`)
        }
      }
    }

    return scopes
  }

  /** Clear all registered scopes. For testing. */
  static reset(): void {
    ScopeRegistry._scopes.clear()
  }
}
