import { defineActions } from '@stravigor/oauth2'
// import { User } from '../models/user'

export default defineActions({
  /**
   * Find a user by their primary key.
   * Used to load the resource owner for token-protected routes.
   */
  async findById(id) {
    // return User.find(id)
    throw new Error('Implement findById in actions/oauth2.ts')
  },

  /**
   * Return the user's display identifier.
   * Shown on the consent screen for third-party clients.
   */
  identifierOf(user) {
    // return user.email
    throw new Error('Implement identifierOf in actions/oauth2.ts')
  },

  // ─── Optional: Custom consent screen ─────────────────────────────────
  //
  // renderAuthorization(ctx, client, scopes) {
  //   return ctx.view('oauth/authorize', { client, scopes })
  // },
})
