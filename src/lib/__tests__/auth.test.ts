import { validateAuthInfo } from '../auth';

async function sign(username: string, secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const buffer = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(username),
  );
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

describe('validateAuthInfo', () => {
  beforeAll(() => {
    if (!globalThis.crypto?.subtle) {
      Object.defineProperty(globalThis, 'crypto', {
        value: require('crypto').webcrypto,
      });
    }
  });

  it('rejects missing auth instead of allowing anonymous default user access', async () => {
    await expect(
      validateAuthInfo(null, { password: 'secret' }),
    ).resolves.toBeNull();
  });

  it('rejects malformed database auth without a signature', async () => {
    await expect(
      validateAuthInfo(
        { username: 'default' },
        { storageType: 'redis', password: 'secret' },
      ),
    ).resolves.toBeNull();
  });

  it('accepts only the configured localstorage password', async () => {
    await expect(
      validateAuthInfo(
        { password: 'secret' },
        { storageType: 'localstorage', password: 'secret' },
      ),
    ).resolves.toEqual({ password: 'secret' });

    await expect(
      validateAuthInfo(
        { password: 'wrong' },
        { storageType: 'localstorage', password: 'secret' },
      ),
    ).resolves.toBeNull();
  });

  it('accepts database auth only when the username signature is valid', async () => {
    const signature = await sign('alice', 'secret');

    await expect(
      validateAuthInfo(
        { username: 'alice', signature },
        { storageType: 'redis', password: 'secret' },
      ),
    ).resolves.toEqual({ username: 'alice', signature });

    await expect(
      validateAuthInfo(
        { username: 'alice', signature },
        { storageType: 'redis', password: 'different' },
      ),
    ).resolves.toBeNull();
  });
});
