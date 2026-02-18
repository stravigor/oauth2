/**
 * Extract a user ID from any user object.
 *
 * Unlike `extractUserId` from `@stravigor/database/helpers/identity` which requires a
 * BaseModel instance, this helper works with plain objects (e.g. `{ id: 1 }`)
 * so that `@stravigor/oauth2` stays user-type agnostic.
 */
export function getUserId(user: unknown): string {
  if (typeof user === 'string') return user
  if (typeof user === 'number') return String(user)
  if (user && typeof user === 'object' && 'id' in user) {
    return String((user as Record<string, unknown>).id)
  }
  throw new Error('Cannot extract user ID: user must have an "id" property or be a string/number.')
}
