import { describe, it, expect } from 'vitest'
import { sanitizeUrl } from './index'

describe('sanitizeUrl', () => {
  describe('should allow valid URLs', () => {
    const testCases = [
      { input: 'http://example.com', expected: 'http://example.com/' },
      { input: 'https://www.google.com', expected: 'https://www.google.com/' },
      { input: 'http://test.com/path/to/resource', expected: 'http://test.com/path/to/resource' },
      { input: 'https://api.github.com/users/octocat', expected: 'https://api.github.com/users/octocat' },
      {
        input: 'https://subdomain.example.com/page?param=value#section',
        expected: 'https://subdomain.example.com/page?param=value#section',
      },
      { input: 'http://localhost:3000', expected: 'http://localhost:3000/' },
      { input: 'https://127.0.0.1:8080', expected: 'https://127.0.0.1:8080/' },
    ]

    testCases.forEach(({ input, expected }) => {
      it(`should sanitize: ${input}`, () => {
        const result = sanitizeUrl(input)
        expect(result).toBe(expected)
      })
    })
  })

  describe('should reject invalid protocols', () => {
    const invalidProtocolUrls = [
      'ftp://example.com/test',
      'ssh://test.com/whoami',
      'telnet://malicious.com/dir',
      'file:///C:/Windows/System32/calc.exe',
      'file://localhost/etc/passwd',
      'file://c:/windows/system32/calc.exe',
      'javascript:alert("XSS")',
      'javascript:eval("malicious code")',
      'javascript:$(calc.exe)?response_type=code.....',
      'javascript:$(cmd /c whoami > c:\\temp\\pwned.txt)',
      'data:text/html,<script>alert("XSS")</script>',
    ]

    invalidProtocolUrls.forEach((url) => {
      it(`should reject: ${url}`, () => {
        expect(() => sanitizeUrl(url)).toThrow('Invalid url to pass to open()')
      })
    })
  })

  describe('should reject malicious hosts', () => {
    const invalidProtocolUrls = [
      'https://www.$(calc.exe).com/foo',
      'https://www.example.com:$(calc.exe)/foo',
    ]

    invalidProtocolUrls.forEach((url) => {
      it(`should reject: ${url}`, () => {
        expect(() => sanitizeUrl(url)).toThrow('Invalid url to pass to open()')
      })
    })
  })

  describe('should properly encode URL components', () => {
    it('should reject URLs with spaces in hostname', () => {
      // URLs with spaces in hostname are invalid
      expect(() => sanitizeUrl('https://exam ple.com')).toThrow()
    })

    it('should encode special characters in pathname', () => {
      const result = sanitizeUrl('https://example.com/path with spaces')
      expect(result).toBe('https://example.com/path%2520with%2520spaces')
    })

    it('should encode query parameters', () => {
      const result = sanitizeUrl('https://example.com?key=value with spaces&another=test')
      expect(result).toBe('https://example.com/?key=value%20with%20spaces&another=test')
    })

    it('should encode hash fragments', () => {
      const result = sanitizeUrl('https://example.com#section with spaces')
      expect(result).toBe('https://example.com/#section%2520with%2520spaces')
    })

    it('should handle empty query parameter values', () => {
      const result = sanitizeUrl('https://example.com?empty&hasvalue=test')
      expect(result).toBe('https://example.com/?empty&hasvalue=test')
    })

    it('should encode basic auth', () => {
      const result = sanitizeUrl('http://user$(calc)r:pass$(calc)word@domain.com')
      expect(result).toBe('http://user%24(calc)r:pass%24(calc)word@domain.com/')
    })
  })

  describe('should handle complex URLs', () => {
    it('should handle URL with all components', () => {
      const complexUrl = 'https://user:pass@example.com:8080/path/to/resource?param=value&other=test#fragment'
      const result = sanitizeUrl(complexUrl)
      expect(result).toBe('https://user:pass@example.com:8080/path/to/resource?param=value&other=test#fragment')
    })

    it('should preserve valid URL structure', () => {
      const url = 'https://api.example.com/v1/users?limit=10&offset=0#results'
      const result = sanitizeUrl(url)
      expect(result).toBe('https://api.example.com/v1/users?limit=10&offset=0#results')
    })
  })

  describe('should handle edge cases', () => {
    it('should handle URLs with port numbers', () => {
      const result = sanitizeUrl('http://localhost:3000/api')
      expect(result).toBe('http://localhost:3000/api')
    })

    it('should handle URLs with authentication info', () => {
      const result = sanitizeUrl('https://user:pass@example.com/secure')
      expect(result).toBe('https://user:pass@example.com/secure')
    })

    it('should handle minimal URLs', () => {
      const result = sanitizeUrl('http://a.com')
      expect(result).toBe('http://a.com/')
    })
  })
})
