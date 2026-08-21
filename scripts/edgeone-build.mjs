#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

function loadLocalEnvFile() {
  const envPath = join(process.cwd(), '.env');
  if (!existsSync(envPath)) return;

  for (const rawLine of readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const match = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match || process.env[match[1]] !== undefined) continue;

    let value = match[2].trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote)) {
      value = value.slice(1, -1);
    }
    if (quote === '"') {
      value = value.replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    process.env[match[1]] = value;
  }
}

loadLocalEnvFile();

const runtimeEnvKeys = [
  'USERNAME', 'PASSWORD', 'NEXT_PUBLIC_STORAGE_TYPE',
  'UPSTASH_URL', 'UPSTASH_TOKEN', 'TMDB_API_KEY',
  'NEXT_PUBLIC_SITE_NAME', 'ANNOUNCEMENT', 'ENABLE_REGISTER',
  'SITE_BASE', 'REDIS_URL', 'KVROCKS_URL',
  'NEXT_PUBLIC_SEARCH_MAX_PAGE',
  'NEXT_PUBLIC_DOUBAN_PROXY_TYPE', 'NEXT_PUBLIC_DOUBAN_PROXY',
  'NEXT_PUBLIC_DOUBAN_IMAGE_PROXY_TYPE', 'NEXT_PUBLIC_DOUBAN_IMAGE_PROXY',
  'NEXT_PUBLIC_DISABLE_YELLOW_FILTER', 'NEXT_PUBLIC_FLUID_SEARCH',
  'NEXT_PUBLIC_BANGUMI_API_TYPE', 'NEXT_PUBLIC_BANGUMI_API_PROXY',
  'NEXT_PUBLIC_BANGUMI_IMAGE_PROXY_TYPE', 'NEXT_PUBLIC_BANGUMI_IMAGE_PROXY',
  'NEXT_PUBLIC_CORSAPI_URL', 'NEXT_PUBLIC_SUB_URL',
  'DISABLE_HERO_TRAILER', 'DISABLE_SSRF_PROTECTION',
  'TVBOX_SUBSCRIBE_TOKEN', 'TRUSTED_NETWORK_IPS',
];

// 跳过认证的路径：静态资源、登录/注册页、公开 API。
//
// 安全边界：不能对所有条目直接使用 startsWith。否则 /login-malicious、
// /api/login-admin 等受保护路由会被误判为公开路径。仅以 / 结尾的目录前缀
// 允许前缀匹配；其它页面或 API 端点必须精确匹配，或匹配其子路径边界。
const skipPaths = [
  '/_next/', '/favicon.ico', '/robots.txt', '/manifest.json',
  '/icons/', '/logo.png', '/screenshot.png',
  '/login', '/register', '/oidc-register', '/warning',
  '/api/login', '/api/register', '/api/logout', '/api/cron',
  '/api/server-config', '/api/tvbox', '/api/tvbox-config',
  '/api/live/merged', '/api/parse', '/api/bing-wallpaper',
  '/api/proxy/', '/api/telegram/', '/api/auth/oidc/',
  '/api/watch-room/', '/api/cache/', '/api/client-log',
];

function isPathAuthSkipped(pathname, paths = skipPaths) {
  return paths.some((path) => {
    if (path.endsWith('/')) {
      return pathname === path.slice(0, -1) || pathname.startsWith(path);
    }

    return pathname === path || pathname.startsWith(`${path}/`);
  });
}

function serializePathGuardFunction(paths) {
  return `function(p){var sk=${JSON.stringify(paths)};for(var i=0;i<sk.length;i++){var s=sk[i];if(s.charAt(s.length-1)==='/'){if(p===s.slice(0,-1)||p.indexOf(s)===0)return true;}else if(p===s||p.indexOf(s+'/')===0)return true;}return false;}`;
}

// 用于 layout 注入时过滤掉 API 路径（API 认证由 edge middleware 处理）
const pageSkipPaths = skipPaths.filter(p => !p.startsWith('/api/'));

let savedProxyContent = null;
let savedLayoutContent = null;

function getRuntimeEnvLiteral() {
  const env = {};
  for (const key of runtimeEnvKeys) {
    if (process.env[key] !== undefined) {
      env[key] = process.env[key];
    }
  }
  return JSON.stringify(env);
}

function replaceEnvLiterals(code, envLiteral) {
  let output = '';
  let cursor = 0;
  let replaced = 0;
  const needle = 'env: {';

  while (true) {
    const start = code.indexOf(needle, cursor);
    if (start === -1) {
      output += code.slice(cursor);
      break;
    }

    let i = start + 'env: '.length;
    let depth = 0;
    let inString = false;
    let escaped = false;

    for (; i < code.length; i += 1) {
      const char = code[i];

      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (char === '\\') {
          escaped = true;
        } else if (char === '"') {
          inString = false;
        }
        continue;
      }

      if (char === '"') {
        inString = true;
      } else if (char === '{') {
        depth += 1;
      } else if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          i += 1;
          break;
        }
      }
    }

    if (depth !== 0) {
      console.warn('[edgeone-build] Unable to replace an env literal: malformed object');
      output += code.slice(cursor);
      break;
    }

    output += code.slice(cursor, start) + `env: ${envLiteral}`;
    cursor = i;
    replaced += 1;
  }

  if (replaced > 0) {
    console.log(`[edgeone-build] Replaced ${replaced} generated env literal(s) with filtered runtime env`);
  }

  return output;
}

function patchEdgeFunctionEnvInjection() {
  const edgeFunctionPath = join(process.cwd(), '.edgeone', 'edge-functions', 'index.js');
  let code;
  try {
    code = readFileSync(edgeFunctionPath, 'utf8');
  } catch {
    return;
  }

  const marker = '/* edgeone-process-env-injected */';
  const envLiteral = getRuntimeEnvLiteral();

  code = replaceEnvLiterals(code, envLiteral);

  const target = 'let request = context.request;';
  if (!code.includes(marker) && !code.includes(target)) {
    console.warn('[edgeone-build] Unable to patch edge function env injection: target not found');
  } else if (!code.includes(marker)) {
    code = code.replace(
      target,
      `${target}\n          ${marker}\n          if (typeof globalThis !== 'undefined' && globalThis.process?.env && context?.env) {\n            Object.assign(globalThis.process.env, context.env);\n          }`
    );
  }

  // 兼容 Next.js 16 proxy.ts（executeMiddleware，构建时已临时转换）
  const middlewareSignature = 'async function executeMiddleware({request}) {';
  const middlewareMarker = '/* edgeone-middleware-env-injected */';
  if (!code.includes(middlewareMarker) && !code.includes(middlewareSignature)) {
    console.warn('[edgeone-build] Unable to patch middleware env injection: target not found');
  } else if (!code.includes(middlewareMarker)) {
    code = code.replace(
      middlewareSignature,
      `async function executeMiddleware({request, env}) {\n  ${middlewareMarker}\n  if (typeof globalThis !== 'undefined' && globalThis.process?.env && env) {\n    Object.assign(globalThis.process.env, env);\n  }`
    );
  }

  writeFileSync(edgeFunctionPath, code);
  console.log('[edgeone-build] Patched edge function process.env injection');
}

// 构建前：将 proxy.ts 转换为 middleware.ts
// EdgeOne 不完整支持 Next.js 16 proxy.ts，需要临时转换
// 同时简化 matcher（EdgeOne 不支持负向前瞻正则）并注入跳过路径
function convertProxyToMiddlewareForBuild() {
  const proxyPath = join(process.cwd(), 'src', 'proxy.ts');
  const middlewarePath = join(process.cwd(), 'src', 'middleware.ts');
  const backupPath = join(process.cwd(), 'src', 'proxy.ts.edgeone-backup');

  if (!existsSync(proxyPath) || existsSync(middlewarePath)) return false;

  savedProxyContent = readFileSync(proxyPath, 'utf8');
  let content = savedProxyContent;

  content = content.replace(/export async function proxy\b/, 'export async function middleware');

  // 简化 matcher：EdgeOne 不支持 (?!...)，改用匹配所有路径
  // 注意：不能用 /:path+（不匹配根路径 /），必须用 /:path*
  content = content.replace(
    /export const config = \{[\s\S]*?matcher[\s\S]*?\};/,
    `export const config = { matcher: ['/', '/:path*'] };`
  );

  // 在 middleware 函数体开头注入跳过路径检查
  // 替代原 matcher 负向前瞻排除的路径，避免 /login 被无限重定向
  const pathGuardLiteral = serializePathGuardFunction(skipPaths);
  const skipInjection = `
  /* edgeone-middleware-skip-paths */
  const __edgeOneShouldSkipAuth = ${pathGuardLiteral};
  if (__edgeOneShouldSkipAuth(pathname)) {
    return NextResponse.next();
  }`;

  const destructureRegex = /(const\s*\{\s*pathname\s*\}\s*=\s*request\.nextUrl\s*;)/;
  if (destructureRegex.test(content)) {
    content = content.replace(destructureRegex, `$1${skipInjection}`);
  } else {
    // 兜底：直接在函数签名后插入
    const fallback = `
  /* edgeone-middleware-skip-paths */
  const __edgeOnePathname = request.nextUrl.pathname;
  const __edgeOneShouldSkipAuth = ${pathGuardLiteral};
  if (__edgeOneShouldSkipAuth(__edgeOnePathname)) {
    return NextResponse.next();
  }`;
    const fnRegex = /(export\s+async\s+function\s+middleware\s*\([^)]*\)\s*\{)/;
    content = content.replace(fnRegex, `$1${fallback}`);
  }

  renameSync(proxyPath, backupPath);
  writeFileSync(middlewarePath, content);
  console.log('[edgeone-build] Created temporary middleware.ts with skip-paths injection');
  return true;
}

// 构建前：在 layout.tsx 注入客户端认证 guard
//
// EdgeOne Pages 的页面 SSR 请求不会稳定经过 Next middleware，且 SSR 层无法可靠
// 获取当前 pathname；此前服务端 guard 在 pathname 缺失时回退到 '/'，导致访问
// /login 也会被误判为受保护页面并再次重定向到 /login，触发 ERR_TOO_MANY_REDIRECTS。
// 因此这里不再注入任何服务端 redirect，只注入一个同步执行的 head script：它在
// React 水合前基于浏览器真实 pathname 做兜底跳转，并显式放行登录/注册等公开页。
function injectLayoutAuthCheck() {
  const layoutPath = join(process.cwd(), 'src', 'app', 'layout.tsx');
  if (!existsSync(layoutPath)) {
    console.warn('[edgeone-build] layout.tsx not found, skip auth injection');
    return false;
  }

  const original = readFileSync(layoutPath, 'utf8');
  savedLayoutContent = original;

  const marker = '/* edgeone-layout-auth-guard */';
  if (original.includes(marker)) {
    return original.includes('window.location.replace') && original.includes('/login?redirect=');
  }

  const headTag = '<head>';
  const headIdx = original.indexOf(headTag);
  if (headIdx === -1) {
    console.warn('[edgeone-build] Cannot find <head> in layout.tsx');
    return false;
  }

  const pagePathGuardLiteral = serializePathGuardFunction(pageSkipPaths);
  const guardJs = `(function(){try{var p=window.location.pathname||'/';var q=window.location.search||'';var skip=${pagePathGuardLiteral};if(skip(p))return;var ok=document.cookie.split(';').some(function(e){var t=e.trim();var x=t.indexOf('=');if(x<=0)return false;var n=t.slice(0,x);var v=t.slice(x+1);return(n==='user_auth'||n==='auth')&&v!=='';});if(ok)return;window.location.replace('/login?redirect='+encodeURIComponent(p+q));}catch(e){}})()`;
  const guardScript = `{/* edgeone-layout-auth-guard */}
        <script dangerouslySetInnerHTML={{ __html: ${JSON.stringify(guardJs)} }} />`;
  const insertPos = headIdx + headTag.length;
  const content = original.slice(0, insertPos) + '\n        ' + guardScript + original.slice(insertPos);

  writeFileSync(layoutPath, content);
  console.log('[edgeone-build] Injected client auth guard into layout.tsx <head>');
  return true;
}

function restoreProxyAfterBuild(wasConverted) {
  if (!wasConverted) return;

  const middlewarePath = join(process.cwd(), 'src', 'middleware.ts');
  const backupPath = join(process.cwd(), 'src', 'proxy.ts.edgeone-backup');

  if (savedProxyContent) {
    writeFileSync(join(process.cwd(), 'src', 'proxy.ts'), savedProxyContent);
    rmSync(middlewarePath, { force: true });
    rmSync(backupPath, { force: true });
    savedProxyContent = null;
    console.log('[edgeone-build] Restored proxy.ts');
    return;
  }

  rmSync(middlewarePath, { force: true });
  if (existsSync(backupPath)) {
    renameSync(backupPath, join(process.cwd(), 'src', 'proxy.ts'));
  }
  console.log('[edgeone-build] Restored proxy.ts from backup');
}

function restoreLayoutAfterBuild() {
  if (!savedLayoutContent) return;
  writeFileSync(join(process.cwd(), 'src', 'app', 'layout.tsx'), savedLayoutContent);
  savedLayoutContent = null;
  console.log('[edgeone-build] Restored layout.tsx');
}

// 构建前准备
const wasConverted = convertProxyToMiddlewareForBuild();
if (!injectLayoutAuthCheck()) {
  restoreProxyAfterBuild(wasConverted);
  throw new Error('[edgeone-build] Failed to inject EdgeOne auth guard; abort build to avoid exposing protected pages');
}

// 确保异常退出时也能清理
process.on('exit', () => {
  restoreProxyAfterBuild(wasConverted);
  restoreLayoutAfterBuild();
});

// 执行构建
const isInsideEdgeOneBuilder = process.env.NEXT_PRIVATE_STANDALONE === 'true';

const command = isInsideEdgeOneBuilder
  ? 'BUILD_TARGET=edgeone EDGEONE_PAGES=1 pnpm build'
  : 'BUILD_TARGET=edgeone EDGEONE_PAGES=1 edgeone makers build';

const child = spawn(command, {
  stdio: 'inherit',
  shell: true,
  env: { ...process.env, BUILD_TARGET: 'edgeone', EDGEONE_PAGES: '1' },
});

child.on('exit', (code, signal) => {
  if (!signal && code === 0) {
    for (const file of ['edgeone.json', 'package.json']) {
      copyFileSync(join(process.cwd(), file), join(process.cwd(), '.edgeone', file));
    }

    patchEdgeFunctionEnvInjection();

    // 清理可能残留的 .env 文件
    for (const envPath of [
      join(process.cwd(), '.edgeone', '.env'),
      join(process.cwd(), '.edgeone', 'cloud-functions', 'ssr-node', '.env'),
    ]) {
      rmSync(envPath, { force: true });
    }
  }

  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
