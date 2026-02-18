import { ServiceProvider } from '@stravigor/kernel'
import type { Application } from '@stravigor/kernel'
import { Router } from '@stravigor/http'
import OAuth2Manager from './oauth2_manager.ts'
import type { OAuth2Actions } from './types.ts'

export default class OAuth2Provider extends ServiceProvider {
  readonly name = 'oauth2'
  override readonly dependencies = ['auth', 'session', 'encryption', 'database']

  constructor(private actions: OAuth2Actions) {
    super()
  }

  override register(app: Application): void {
    app.singleton(OAuth2Manager)
  }

  override async boot(app: Application): Promise<void> {
    app.resolve(OAuth2Manager)
    OAuth2Manager.useActions(this.actions)
    await OAuth2Manager.ensureTables()
    OAuth2Manager.routes(app.resolve(Router))
  }

  override shutdown(): void {
    OAuth2Manager.reset()
  }
}
