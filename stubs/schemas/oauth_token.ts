import { defineSchema, t, Archetype } from '@stravigor/database'

export default defineSchema('oauth_token', {
  archetype: Archetype.Component,
  parents: ['user'],
  fields: {
    clientId: t.uuid().required().index(),
    name: t.varchar(255).nullable(),
    scopes: t.jsonb().required(),
    token: t.varchar(255).required().unique(),
    refreshToken: t.varchar(255).nullable().unique(),
    expiresAt: t.timestamptz().required(),
    refreshExpiresAt: t.timestamptz().nullable(),
    lastUsedAt: t.timestamptz().nullable(),
    revokedAt: t.timestamptz().nullable(),
  },
})
