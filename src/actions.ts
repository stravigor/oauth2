import type { OAuth2Actions } from './types.ts'

/**
 * Type-safe identity function for defining OAuth2 actions.
 * Zero runtime cost — just provides autocompletion and type checking.
 *
 * @example
 * import { defineActions } from '@stravigor/oauth2'
 * import { User } from '../models/user'
 *
 * export default defineActions<User>({
 *   findById: (id) => User.find(id),
 *   identifierOf: (user) => user.email,
 * })
 */
export function defineActions<TUser = unknown>(
  actions: OAuth2Actions<TUser>
): OAuth2Actions<TUser> {
  return actions
}
