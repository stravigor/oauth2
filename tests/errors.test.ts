import { test, expect, describe } from 'bun:test'
import {
  OAuth2Error,
  UnsupportedGrantError,
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  AccessDeniedError,
} from '../src/errors.ts'

describe('OAuth2Error', () => {
  test('creates error with defaults', () => {
    const err = new OAuth2Error('Something went wrong')
    expect(err.message).toBe('Something went wrong')
    expect(err.errorCode).toBe('server_error')
    expect(err.statusCode).toBe(400)
  })

  test('toJSON returns RFC 6749 format', () => {
    const err = new OAuth2Error('Something went wrong', 'custom_error', 422)
    expect(err.toJSON()).toEqual({
      error: 'custom_error',
      error_description: 'Something went wrong',
    })
  })
})

describe('UnsupportedGrantError', () => {
  test('has correct error code', () => {
    const err = new UnsupportedGrantError()
    expect(err.errorCode).toBe('unsupported_grant_type')
    expect(err.statusCode).toBe(400)
  })
})

describe('InvalidClientError', () => {
  test('has correct error code and status', () => {
    const err = new InvalidClientError()
    expect(err.errorCode).toBe('invalid_client')
    expect(err.statusCode).toBe(401)
  })

  test('accepts custom message', () => {
    const err = new InvalidClientError('Secret mismatch')
    expect(err.message).toBe('Secret mismatch')
  })
})

describe('InvalidGrantError', () => {
  test('has correct error code', () => {
    const err = new InvalidGrantError()
    expect(err.errorCode).toBe('invalid_grant')
  })
})

describe('InvalidRequestError', () => {
  test('has correct error code', () => {
    const err = new InvalidRequestError()
    expect(err.errorCode).toBe('invalid_request')
  })
})

describe('InvalidScopeError', () => {
  test('has correct error code', () => {
    const err = new InvalidScopeError()
    expect(err.errorCode).toBe('invalid_scope')
  })
})

describe('AccessDeniedError', () => {
  test('has correct error code and status', () => {
    const err = new AccessDeniedError()
    expect(err.errorCode).toBe('access_denied')
    expect(err.statusCode).toBe(403)
  })
})
