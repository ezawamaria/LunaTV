import { NextRequest } from 'next/server';

export type AuthInfo = {
  password?: string;
  username?: string;
  signature?: string;
  timestamp?: number;
  loginTime?: number;
  trustedNetwork?: boolean;
  role?: 'owner' | 'admin' | 'user';
};

// 从cookie获取认证信息 (服务端使用)
export function getAuthInfoFromCookie(request: NextRequest): AuthInfo | null {
  // 尝试新的 cookie 名称 user_auth，如果没有则尝试旧的 auth
  const authCookie =
    request.cookies.get('user_auth') || request.cookies.get('auth');

  if (!authCookie) {
    return null;
  }

  try {
    const decoded = decodeURIComponent(authCookie.value);
    const authData = JSON.parse(decoded);
    return authData;
  } catch (error) {
    return null;
  }
}

// 从cookie获取认证信息 (客户端使用)
export function getAuthInfoFromBrowserCookie(): AuthInfo | null {
  if (typeof window === 'undefined') {
    return null;
  }

  try {
    // 解析 document.cookie
    const cookies = document.cookie.split(';').reduce(
      (acc, cookie) => {
        const trimmed = cookie.trim();
        const firstEqualIndex = trimmed.indexOf('=');

        if (firstEqualIndex > 0) {
          const key = trimmed.substring(0, firstEqualIndex);
          const value = trimmed.substring(firstEqualIndex + 1);
          if (key && value) {
            acc[key] = value;
          }
        }

        return acc;
      },
      {} as Record<string, string>,
    );

    // 尝试新的 cookie 名称 user_auth，如果没有则尝试旧的 auth
    const authCookie = cookies['user_auth'] || cookies['auth'];
    if (!authCookie) {
      return null;
    }

    // 处理可能的双重编码
    let decoded = decodeURIComponent(authCookie);

    // 如果解码后仍然包含 %，说明是双重编码，需要再次解码
    if (decoded.includes('%')) {
      decoded = decodeURIComponent(decoded);
    }

    const authData = JSON.parse(decoded);
    return authData;
  } catch (error) {
    return null;
  }
}

export type AuthValidationOptions = {
  storageType?: string;
  password?: string;
  allowTrustedNetwork?: boolean;
};

async function verifyAuthSignature(
  username: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(username);

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify'],
    );

    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || [],
    );

    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData,
    );
  } catch {
    return false;
  }
}

export async function validateAuthInfo(
  authInfo: AuthInfo | null,
  options: AuthValidationOptions = {},
): Promise<AuthInfo | null> {
  if (!authInfo) return null;

  const storageType =
    options.storageType ??
    process.env.NEXT_PUBLIC_STORAGE_TYPE ??
    'localstorage';
  const password = options.password ?? process.env.PASSWORD ?? '';

  if (storageType === 'localstorage') {
    return password && authInfo.password === password ? authInfo : null;
  }

  if (options.allowTrustedNetwork !== false && authInfo.trustedNetwork) {
    return authInfo;
  }

  if (!password || !authInfo.username || !authInfo.signature) return null;

  return (await verifyAuthSignature(
    authInfo.username,
    authInfo.signature,
    password,
  ))
    ? authInfo
    : null;
}
