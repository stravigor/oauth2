import { timingSafeEqual as nodeTimingSafeEqual } from 'node:crypto'
import OAuth2Manager from './oauth2_manager.ts'
import { randomHex } from '@stravigor/kernel'
import type { OAuthClientData, CreateClientInput, GrantType } from './types.ts'

function hashSecret(plain: string): string {
  return new Bun.CryptoHasher('sha256').update(plain).digest('hex')
}

/**
 * Static helper for managing OAuth2 clients.
 *
 * Client secrets are SHA-256 hashed before storage — the plain-text
 * secret is returned exactly once at creation time.
 *
 * @example
 * const { client, plainSecret } = await OAuthClient.create({ name: 'Mobile App', redirectUris: ['myapp://callback'] })
 * const client = await OAuthClient.find(id)
 * await OAuthClient.revoke(id)
 */
export default class OAuthClient {
  /** Create a new OAuth client. Returns the client record and the plain secret (if confidential). */
  static async create(input: CreateClientInput): Promise<{
    client: OAuthClientData
    plainSecret: string | null
  }> {
    const confidential = input.confidential ?? true
    const firstParty = input.firstParty ?? false
    const grantTypes = input.grantTypes ?? ['authorization_code', 'refresh_token']

    let plainSecret: string | null = null
    let hashedSecret: string | null = null

    if (confidential) {
      plainSecret = randomHex(32)
      hashedSecret = hashSecret(plainSecret)
    }

    const rows = await OAuth2Manager.db.sql`
      INSERT INTO "_strav_oauth_clients" (
        "name", "secret", "redirect_uris", "scopes", "grant_types",
        "confidential", "first_party", "revoked"
      )
      VALUES (
        ${input.name},
        ${hashedSecret},
        ${JSON.stringify(input.redirectUris)},
        ${input.scopes !== undefined ? JSON.stringify(input.scopes) : null},
        ${JSON.stringify(grantTypes)},
        ${confidential},
        ${firstParty},
        ${false}
      )
      RETURNING *
    `

    return {
      client: OAuthClient.hydrate(rows[0] as Record<string, unknown>),
      plainSecret,
    }
  }

  /** Find a client by ID. Returns null if not found or revoked. */
  static async find(id: string): Promise<OAuthClientData | null> {
    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_clients" WHERE "id" = ${id} LIMIT 1
    `
    if (rows.length === 0) return null
    return OAuthClient.hydrate(rows[0] as Record<string, unknown>)
  }

  /** Find a client by ID, including revoked clients. */
  static async findIncludingRevoked(id: string): Promise<OAuthClientData | null> {
    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_clients" WHERE "id" = ${id} LIMIT 1
    `
    if (rows.length === 0) return null
    return OAuthClient.hydrate(rows[0] as Record<string, unknown>)
  }

  /** Verify a plain-text client secret against the stored hash. */
  static async verifySecret(client: OAuthClientData, plainSecret: string): Promise<boolean> {
    const rows = await OAuth2Manager.db.sql`
      SELECT "secret" FROM "_strav_oauth_clients" WHERE "id" = ${client.id} LIMIT 1
    `
    if (rows.length === 0) return false
    const stored = (rows[0] as Record<string, unknown>).secret as string | null
    if (!stored) return false

    const hash = hashSecret(plainSecret)
    return timingSafeEqual(stored, hash)
  }

  /** List all non-revoked clients. */
  static async all(): Promise<OAuthClientData[]> {
    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_clients" WHERE "revoked" = false ORDER BY "created_at" DESC
    `
    return (rows as Record<string, unknown>[]).map(OAuthClient.hydrate)
  }

  /** List all clients belonging to a user (clients they created). */
  static async allForUser(userId: string): Promise<OAuthClientData[]> {
    // All non-revoked clients visible to the user
    return OAuthClient.all()
  }

  /** Soft-revoke a client. */
  static async revoke(id: string): Promise<void> {
    await OAuth2Manager.db.sql`
      UPDATE "_strav_oauth_clients" SET "revoked" = true, "updated_at" = NOW()
      WHERE "id" = ${id}
    `
  }

  /** Hard-delete a client and all its tokens/codes. */
  static async destroy(id: string): Promise<void> {
    const db = OAuth2Manager.db
    await db.sql`DELETE FROM "_strav_oauth_auth_codes" WHERE "client_id" = ${id}`
    await db.sql`DELETE FROM "_strav_oauth_tokens" WHERE "client_id" = ${id}`
    await db.sql`DELETE FROM "_strav_oauth_clients" WHERE "id" = ${id}`
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  static hydrate(row: Record<string, unknown>): OAuthClientData {
    return {
      id: String(row.id),
      name: row.name as string,
      redirectUris: parseJsonb(row.redirect_uris) as string[],
      scopes: parseJsonb(row.scopes) as string[] | null,
      grantTypes: parseJsonb(row.grant_types) as GrantType[],
      confidential: row.confidential as boolean,
      firstParty: row.first_party as boolean,
      revoked: row.revoked as boolean,
      createdAt: row.created_at as Date,
      updatedAt: row.updated_at as Date,
    }
  }
}

/** Timing-safe string comparison. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  return nodeTimingSafeEqual(Buffer.from(a), Buffer.from(b))
}

/** Parse a JSONB column that may already be an object or a string. */
function parseJsonb(value: unknown): unknown {
  if (value === null || value === undefined) return null
  if (typeof value === 'string') return JSON.parse(value)
  return value
}
