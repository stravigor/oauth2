import { StravError } from '@stravigor/kernel'

/** Base error for all OAuth2 errors. */
export class OAuth2Error extends StravError {
  constructor(
    message: string,
    public readonly errorCode: string = 'server_error',
    public readonly statusCode: number = 400
  ) {
    super(message)
  }

  /** Build a JSON response matching RFC 6749 error format. */
  toJSON(): Record<string, string> {
    return {
      error: this.errorCode,
      error_description: this.message,
    }
  }
}

/** The authorization grant type is not supported. */
export class UnsupportedGrantError extends OAuth2Error {
  constructor() {
    super('The authorization grant type is not supported.', 'unsupported_grant_type')
  }
}

/** Client authentication failed. */
export class InvalidClientError extends OAuth2Error {
  constructor(message = 'Client authentication failed.') {
    super(message, 'invalid_client', 401)
  }
}

/** The provided authorization grant is invalid or expired. */
export class InvalidGrantError extends OAuth2Error {
  constructor(message = 'The provided authorization grant is invalid, expired, or revoked.') {
    super(message, 'invalid_grant')
  }
}

/** The request is missing a required parameter or is malformed. */
export class InvalidRequestError extends OAuth2Error {
  constructor(message = 'The request is missing a required parameter.') {
    super(message, 'invalid_request')
  }
}

/** The requested scope is invalid or unknown. */
export class InvalidScopeError extends OAuth2Error {
  constructor(message = 'The requested scope is invalid or unknown.') {
    super(message, 'invalid_scope')
  }
}

/** The resource owner denied the authorization request. */
export class AccessDeniedError extends OAuth2Error {
  constructor(message = 'The resource owner denied the request.') {
    super(message, 'access_denied', 403)
  }
}
