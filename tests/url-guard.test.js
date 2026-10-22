import { describe, test, expect } from '@jest/globals';
import { isRequestAllowed, assertNavigableUrl } from '../lib/url-guard.js';

describe('url guard — literal checks (sync)', () => {
  const cases = [
    ['https://www.google.com/search?q=x', true],
    ['http://example.com', true],
    ['https://8.8.8.8/', true],
    ['http://127.0.0.1:9377/health', false],
    ['http://localhost/', false],
    ['http://192.168.247.185/', false],
    ['http://10.0.0.1/', false],
    ['http://172.16.0.1/', false],
    ['http://172.32.0.1/', true],
    ['http://169.254.169.254/latest/meta-data/', false], // cloud metadata
    ['http://100.64.0.1/', false], // CGNAT
    ['http://0.0.0.0/', false],
    ['file:///etc/passwd', false],
    ['ftp://example.com', false],
    ['http://user:pass@example.com/', false],
    ['http://automatacrumb.local/', false],
    ['http://169.254.169.254/', false],
    ['http://[::1]/', false],
    ['http://[fe80::1]/', false],
    ['http://[fd00::1]/', false],
    ['http://[::ffff:192.168.1.1]/', false],
    ['http://[2606:4700:4700::1111]/', true],
  ];
  test.each(cases)('%s -> %s', (url, expected) => {
    expect(isRequestAllowed(url)).toBe(expected);
  });

  test('allowlist exempts a blocked host', () => {
    expect(isRequestAllowed('http://192.168.247.185/', { allowHosts: ['192.168.247.185'] })).toBe(true);
  });

  test('allowlist is exact match only (10.0.0.1 does not open 10.0.0.10)', () => {
    expect(isRequestAllowed('http://10.0.0.1/', { allowHosts: ['10.0.0.1'] })).toBe(true);
    expect(isRequestAllowed('http://10.0.0.10/', { allowHosts: ['10.0.0.1'] })).toBe(false);
  });
});

describe('url guard — DNS checks (async)', () => {
  test('public hostname passes', async () => {
    expect(await assertNavigableUrl('https://www.google.com/')).toBeNull();
  });

  test('unresolvable hostname is refused', async () => {
    const err = await assertNavigableUrl('http://this-host-does-not-exist-9x7q.example.invalid/');
    expect(err).toBe('hostname does not resolve');
  });

  test('literal IPs skip DNS', async () => {
    expect(await assertNavigableUrl('http://1.1.1.1/')).toBeNull();
    expect(await assertNavigableUrl('http://127.0.0.1/')).toBe('blocked target: 127.0.0.1 (non-public IPv4)');
  });
});
