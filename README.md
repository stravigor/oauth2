# @stravigor/oauth2

OAuth2 server for the [Strav](https://www.npmjs.com/package/@stravigor/core) framework. Authorization Code + PKCE, Client Credentials, Refresh Token rotation, Token Revocation (RFC 7009), Token Introspection (RFC 7662), personal access tokens, and scoped API access.

## Install

```bash
bun add @stravigor/oauth2
bun strav install oauth2
```

Requires `@stravigor/core` as a peer dependency.

## Setup

```ts
import { defineActions } from '@stravigor/oauth2'
import User from './models/user'

const actions = defineActions<User>({
  async findById(id) { return User.find(id) },
  identifierOf(user) { return user.email },
})
```

```ts
import { OAuth2Provider } from '@stravigor/oauth2'

app.use(new OAuth2Provider(actions))
```

```bash
bun strav oauth2:setup    # Create tables + personal access client
bun strav oauth2:client --name "My App" --redirect "https://app.com/callback"
```

## Middleware

```ts
import { oauth, scopes } from '@stravigor/oauth2'
import { compose } from '@stravigor/core/http/middleware'

router.group({ prefix: '/api', middleware: [oauth()] }, r => {
  r.get('/user', ctx => ctx.json({ user: ctx.get('user') }))
  r.get('/repos', compose([scopes('repos:read')], listRepos))
  r.post('/repos', compose([scopes('repos:write')], createRepo))
})
```

## Personal Access Tokens

```ts
import { oauth2 } from '@stravigor/oauth2'

const { token } = await oauth2.createPersonalToken(user, 'CLI Tool', ['read', 'write'])
```

## CLI

```bash
bun strav oauth2:setup     # Create tables and personal access client
bun strav oauth2:client    # Create a new OAuth2 client
bun strav oauth2:purge     # Clean up expired tokens and codes
```

## Documentation

See the full [OAuth2 guide](../../guides/oauth2.md).

## License

MIT
