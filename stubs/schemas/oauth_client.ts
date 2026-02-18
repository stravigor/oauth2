import { defineSchema, t, Archetype } from '@stravigor/database'

export default defineSchema('oauth_client', {
  archetype: Archetype.Entity,
  fields: {
    name: t.varchar(255).required(),
    secret: t.varchar(255).nullable(),
    redirectUris: t.jsonb().required(),
    scopes: t.jsonb().nullable(),
    grantTypes: t.jsonb().required(),
    confidential: t.boolean().required(),
    firstParty: t.boolean().required(),
    revoked: t.boolean().required(),
  },
})
