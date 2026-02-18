import type { Command } from 'commander'
import chalk from 'chalk'
import { bootstrap, shutdown } from '@stravigor/cli'
import OAuth2Manager from '../oauth2_manager.ts'
import OAuthClient from '../client.ts'
import OAuthToken from '../token.ts'
import AuthCode from '../auth_code.ts'

export function register(program: Command): void {
  // ── oauth2:setup ────────────────────────────────────────────────────

  program
    .command('oauth2:setup')
    .description('Create OAuth2 tables and a default personal access client')
    .action(async () => {
      let db
      try {
        const { db: database, config } = await bootstrap()
        db = database

        new OAuth2Manager(db, config)

        console.log(chalk.dim('Creating OAuth2 tables...'))
        await OAuth2Manager.ensureTables()
        console.log(chalk.green('OAuth2 tables created successfully.'))

        // Create personal access client if not already configured
        const patClientId = OAuth2Manager.config.personalAccessClient
        if (!patClientId) {
          console.log(chalk.dim('Creating personal access client...'))
          const { client } = await OAuthClient.create({
            name: 'Personal Access Client',
            redirectUris: [],
            confidential: true,
            firstParty: true,
            grantTypes: [],
          })
          console.log(chalk.green(`Personal access client created: ${chalk.bold(client.id)}`))
          console.log(
            chalk.yellow(
              `\nAdd this to your config/oauth2.ts:\n  personalAccessClient: '${client.id}'`
            )
          )
        } else {
          console.log(chalk.dim(`Personal access client already configured: ${patClientId}`))
        }
      } catch (err) {
        console.error(chalk.red(`Error: ${err instanceof Error ? err.message : err}`))
        process.exit(1)
      } finally {
        if (db) await shutdown(db)
      }
    })

  // ── oauth2:client ───────────────────────────────────────────────────

  program
    .command('oauth2:client')
    .description('Create a new OAuth2 client')
    .requiredOption('--name <name>', 'Client name')
    .option('--redirect <uris...>', 'Redirect URIs', [])
    .option('--public', 'Create a public (non-confidential) client', false)
    .option('--first-party', 'Mark as a first-party (trusted) client', false)
    .option('--credentials', 'Enable client_credentials grant', false)
    .action(
      async (options: {
        name: string
        redirect: string[]
        public: boolean
        firstParty: boolean
        credentials: boolean
      }) => {
        let db
        try {
          const { db: database, config } = await bootstrap()
          db = database

          new OAuth2Manager(db, config)
          await OAuth2Manager.ensureTables()

          const grantTypes = ['authorization_code', 'refresh_token'] as (
            | 'authorization_code'
            | 'client_credentials'
            | 'refresh_token'
          )[]
          if (options.credentials) {
            grantTypes.push('client_credentials')
          }

          const { client, plainSecret } = await OAuthClient.create({
            name: options.name,
            redirectUris: options.redirect,
            confidential: !options.public,
            firstParty: options.firstParty,
            grantTypes,
          })

          console.log(chalk.green('\nOAuth2 client created successfully.\n'))
          console.log(`  ${chalk.dim('Client ID:')}     ${chalk.bold(client.id)}`)

          if (plainSecret) {
            console.log(`  ${chalk.dim('Client Secret:')} ${chalk.bold(plainSecret)}`)
            console.log(chalk.yellow('\n  Store the secret securely — it will not be shown again.'))
          } else {
            console.log(`  ${chalk.dim('Type:')}          Public (no secret)`)
          }

          console.log(
            `  ${chalk.dim('Redirect URIs:')} ${client.redirectUris.join(', ') || '(none)'}`
          )
          console.log(`  ${chalk.dim('Grant Types:')}   ${client.grantTypes.join(', ')}`)
          console.log(`  ${chalk.dim('First Party:')}   ${client.firstParty}`)
        } catch (err) {
          console.error(chalk.red(`Error: ${err instanceof Error ? err.message : err}`))
          process.exit(1)
        } finally {
          if (db) await shutdown(db)
        }
      }
    )

  // ── oauth2:purge ────────────────────────────────────────────────────

  program
    .command('oauth2:purge')
    .description('Purge expired tokens and used authorization codes')
    .option('--days <days>', 'Delete revoked tokens older than N days', '7')
    .action(async (options: { days: string }) => {
      let db
      try {
        const { db: database, config } = await bootstrap()
        db = database

        new OAuth2Manager(db, config)

        const days = parseInt(options.days, 10)

        console.log(chalk.dim('Purging expired tokens...'))
        const tokenCount = await OAuthToken.prune(days)
        console.log(chalk.green(`  ${tokenCount} token(s) pruned.`))

        console.log(chalk.dim('Purging used/expired authorization codes...'))
        const codeCount = await AuthCode.prune()
        console.log(chalk.green(`  ${codeCount} authorization code(s) pruned.`))
      } catch (err) {
        console.error(chalk.red(`Error: ${err instanceof Error ? err.message : err}`))
        process.exit(1)
      } finally {
        if (db) await shutdown(db)
      }
    })
}
