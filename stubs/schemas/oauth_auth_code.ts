import { defineSchema, t, Archetype } from '@stravigor/database'

export default defineSchema('oauth_auth_code', {
  archetype: Archetype.Event,
  fields: {
    clientId: t.uuid().required().index(),
    userId: t.varchar(255).required().index(),
    code: t.varchar(255).required().unique(),
    redirectUri: t.varchar(2048).required(),
    scopes: t.jsonb().required(),
    codeChallenge: t.varchar(255).nullable(),
    codeChallengeMethod: t.varchar(10).nullable(),
    expiresAt: t.timestamptz().required(),
    usedAt: t.timestamptz().nullable(),
  },
})
