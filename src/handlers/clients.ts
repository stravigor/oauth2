import type { Context } from '@stravigor/http'
import { Emitter } from '@stravigor/kernel'
import OAuthClient from '../client.ts'
import { OAuth2Events } from '../types.ts'
import type { GrantType } from '../types.ts'

/**
 * GET /oauth/clients
 *
 * List all non-revoked OAuth clients.
 */
export async function listClientsHandler(ctx: Context): Promise<Response> {
  const clients = await OAuthClient.all()

  return ctx.json({
    clients: clients.map(c => ({
      id: c.id,
      name: c.name,
      redirect_uris: c.redirectUris,
      grant_types: c.grantTypes,
      confidential: c.confidential,
      first_party: c.firstParty,
      created_at: c.createdAt,
    })),
  })
}

/**
 * POST /oauth/clients
 *
 * Create a new OAuth client. Returns the client record and plain secret.
 */
export async function createClientHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{
    name?: string
    redirect_uris?: string[]
    confidential?: boolean
    first_party?: boolean
    scopes?: string[] | null
    grant_types?: GrantType[]
  }>()

  if (!body.name) {
    return ctx.json({ message: 'The name field is required.' }, 422)
  }

  if (!body.redirect_uris || body.redirect_uris.length === 0) {
    return ctx.json({ message: 'At least one redirect_uri is required.' }, 422)
  }

  const { client, plainSecret } = await OAuthClient.create({
    name: body.name,
    redirectUris: body.redirect_uris,
    confidential: body.confidential,
    firstParty: body.first_party,
    scopes: body.scopes,
    grantTypes: body.grant_types,
  })

  if (Emitter.listenerCount(OAuth2Events.CLIENT_CREATED) > 0) {
    Emitter.emit(OAuth2Events.CLIENT_CREATED, { ctx, client }).catch(() => {})
  }

  return ctx.json(
    {
      client: {
        id: client.id,
        name: client.name,
        redirect_uris: client.redirectUris,
        grant_types: client.grantTypes,
        confidential: client.confidential,
        first_party: client.firstParty,
        created_at: client.createdAt,
      },
      secret: plainSecret,
    },
    201
  )
}

/**
 * DELETE /oauth/clients/:id
 *
 * Soft-revoke an OAuth client and all its tokens.
 */
export async function deleteClientHandler(ctx: Context): Promise<Response> {
  const id = ctx.params.id!

  const client = await OAuthClient.findIncludingRevoked(id)
  if (!client) {
    return ctx.json({ message: 'Client not found.' }, 404)
  }

  await OAuthClient.revoke(id)

  if (Emitter.listenerCount(OAuth2Events.CLIENT_REVOKED) > 0) {
    Emitter.emit(OAuth2Events.CLIENT_REVOKED, { ctx, clientId: id }).catch(() => {})
  }

  return ctx.json({ message: 'Client revoked.' })
}
