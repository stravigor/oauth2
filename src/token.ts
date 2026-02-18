import OAuth2Manager from './oauth2_manager.ts'
import { randomHex } from '@stravigor/kernel'
import type { OAuthTokenData } from './types.ts'

function hashToken(plain: string): string {
  return new Bun.CryptoHasher('sha256').update(plain).digest('hex')
}

/**
 * Static helper for managing OAuth2 tokens.
 *
 * Access tokens and refresh tokens are SHA-256 hashed before storage.
 * The plain-text tokens are returned exactly once at creation time.
 *
 * @example
 * const { accessToken, refreshToken, tokenData } = await OAuthToken.create({ ... })
 * const record = await OAuthToken.validate(plainAccessToken)
 * await OAuthToken.revoke(tokenId)
 */
export default class OAuthToken {
  /**
   * Issue a new access token (and optionally a refresh token).
   * Returns plain-text tokens (shown once) and the database record.
   */
  static async create(params: {
    userId: string | null
    clientId: string
    scopes: string[]
    name?: string | null
    includeRefreshToken?: boolean
    accessTokenLifetime?: number // minutes
    refreshTokenLifetime?: number // minutes
  }): Promise<{
    accessToken: string
    refreshToken: string | null
    tokenData: OAuthTokenData
  }> {
    const config = OAuth2Manager.config

    const plainAccess = randomHex(40)
    const hashedAccess = hashToken(plainAccess)

    const accessLifetime = params.accessTokenLifetime ?? config.accessTokenLifetime
    const expiresAt = new Date(Date.now() + accessLifetime * 60_000)

    let plainRefresh: string | null = null
    let hashedRefresh: string | null = null
    let refreshExpiresAt: Date | null = null

    if (params.includeRefreshToken !== false && params.userId !== null) {
      const refreshLifetime = params.refreshTokenLifetime ?? config.refreshTokenLifetime
      plainRefresh = randomHex(40)
      hashedRefresh = hashToken(plainRefresh)
      refreshExpiresAt = new Date(Date.now() + refreshLifetime * 60_000)
    }

    const rows = await OAuth2Manager.db.sql`
      INSERT INTO "_strav_oauth_tokens" (
        "user_id", "client_id", "name", "scopes", "token",
        "refresh_token", "expires_at", "refresh_expires_at"
      )
      VALUES (
        ${params.userId},
        ${params.clientId},
        ${params.name ?? null},
        ${JSON.stringify(params.scopes)},
        ${hashedAccess},
        ${hashedRefresh},
        ${expiresAt},
        ${refreshExpiresAt}
      )
      RETURNING *
    `

    return {
      accessToken: plainAccess,
      refreshToken: plainRefresh,
      tokenData: OAuthToken.hydrate(rows[0] as Record<string, unknown>),
    }
  }

  /**
   * Validate a plain-text access token.
   * Returns the token record if valid, null if invalid/expired/revoked.
   * Updates `last_used_at` (fire-and-forget).
   */
  static async validate(plainToken: string): Promise<OAuthTokenData | null> {
    const hash = hashToken(plainToken)

    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_tokens"
      WHERE "token" = ${hash} LIMIT 1
    `
    if (rows.length === 0) return null

    const record = OAuthToken.hydrate(rows[0] as Record<string, unknown>)

    // Reject revoked tokens
    if (record.revokedAt) return null

    // Reject expired tokens
    if (record.expiresAt.getTime() < Date.now()) return null

    // Update last_used_at (fire-and-forget)
    OAuth2Manager.db.sql`
      UPDATE "_strav_oauth_tokens"
      SET "last_used_at" = NOW()
      WHERE "id" = ${record.id}
    `.then(
      () => {},
      () => {}
    )

    return record
  }

  /**
   * Validate a plain-text refresh token.
   * Returns the token record if valid, null if invalid/expired/revoked.
   */
  static async validateRefreshToken(plainRefresh: string): Promise<OAuthTokenData | null> {
    const hash = hashToken(plainRefresh)

    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_tokens"
      WHERE "refresh_token" = ${hash} LIMIT 1
    `
    if (rows.length === 0) return null

    const record = OAuthToken.hydrate(rows[0] as Record<string, unknown>)

    // Reject revoked tokens
    if (record.revokedAt) return null

    // Reject expired refresh tokens
    if (record.refreshExpiresAt && record.refreshExpiresAt.getTime() < Date.now()) return null

    return record
  }

  /** Revoke a token by ID (soft-revoke with timestamp). */
  static async revoke(id: string): Promise<void> {
    await OAuth2Manager.db.sql`
      UPDATE "_strav_oauth_tokens"
      SET "revoked_at" = NOW()
      WHERE "id" = ${id}
    `
  }

  /** Revoke all tokens for a user. */
  static async revokeAllFor(userId: string): Promise<void> {
    await OAuth2Manager.db.sql`
      UPDATE "_strav_oauth_tokens"
      SET "revoked_at" = NOW()
      WHERE "user_id" = ${userId} AND "revoked_at" IS NULL
    `
  }

  /** Revoke all tokens for a user on a specific client. */
  static async revokeAllForClient(userId: string, clientId: string): Promise<void> {
    await OAuth2Manager.db.sql`
      UPDATE "_strav_oauth_tokens"
      SET "revoked_at" = NOW()
      WHERE "user_id" = ${userId} AND "client_id" = ${clientId} AND "revoked_at" IS NULL
    `
  }

  /** List all active tokens for a user. */
  static async allForUser(userId: string): Promise<OAuthTokenData[]> {
    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_tokens"
      WHERE "user_id" = ${userId} AND "revoked_at" IS NULL AND "expires_at" > NOW()
      ORDER BY "created_at" DESC
    `
    return (rows as Record<string, unknown>[]).map(OAuthToken.hydrate)
  }

  /** List personal access tokens for a user. */
  static async personalTokensFor(userId: string): Promise<OAuthTokenData[]> {
    const patClientId = OAuth2Manager.config.personalAccessClient
    if (!patClientId) return []

    const rows = await OAuth2Manager.db.sql`
      SELECT * FROM "_strav_oauth_tokens"
      WHERE "user_id" = ${userId}
        AND "client_id" = ${patClientId}
        AND "revoked_at" IS NULL
        AND "expires_at" > NOW()
      ORDER BY "created_at" DESC
    `
    return (rows as Record<string, unknown>[]).map(OAuthToken.hydrate)
  }

  /** Prune expired and old revoked tokens. Returns the number of deleted rows. */
  static async prune(revokedOlderThanDays: number): Promise<number> {
    const cutoff = new Date(Date.now() - revokedOlderThanDays * 86_400_000)

    const result = await OAuth2Manager.db.sql`
      DELETE FROM "_strav_oauth_tokens"
      WHERE ("expires_at" < NOW() AND "refresh_expires_at" IS NULL)
        OR ("refresh_expires_at" IS NOT NULL AND "refresh_expires_at" < NOW())
        OR ("revoked_at" IS NOT NULL AND "revoked_at" < ${cutoff})
    `
    return result.count ?? 0
  }

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  static hydrate(row: Record<string, unknown>): OAuthTokenData {
    return {
      id: String(row.id),
      userId: row.user_id as string | null,
      clientId: String(row.client_id),
      name: (row.name as string) ?? null,
      scopes: parseJsonb(row.scopes) as string[],
      expiresAt: row.expires_at as Date,
      refreshExpiresAt: (row.refresh_expires_at as Date) ?? null,
      lastUsedAt: (row.last_used_at as Date) ?? null,
      revokedAt: (row.revoked_at as Date) ?? null,
      createdAt: row.created_at as Date,
    }
  }
}

function parseJsonb(value: unknown): unknown {
  if (value === null || value === undefined) return []
  if (typeof value === 'string') return JSON.parse(value)
  return value
}
