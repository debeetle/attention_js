const IAT_SKEW_SECONDS = 30;
const EXP_TTL_SECONDS = 86400;
const QWEATHER_KID = 'KBB6C7PYM4';
const QWEATHER_SUB = '482GDYNEQG';

function utf8Bytes(value) {
  return new TextEncoder().encode(value);
}

function bytesToBase64(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }

  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64UrlEncodeBytes(bytes) {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function base64UrlEncodeJson(value) {
  return base64UrlEncodeBytes(utf8Bytes(JSON.stringify(value)));
}

function pemToDer(pem) {
  const base64 = pem
    .replace(/\s+/g, '');

  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(base64, 'base64'));
  }

  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function importEd25519PrivateKey(privateKeyPem) {
  const pkcs8 = pemToDer(privateKeyPem);
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'Ed25519' },
    false,
    ['sign']
  );
}

export async function generateQWeatherJwt({
  privateKeyPem,
  kid = QWEATHER_KID,
  sub = QWEATHER_SUB,
  now = Date.now()
}) {
  if (!privateKeyPem) throw new Error('Missing privateKeyPem');
  if (!kid) throw new Error('Missing kid');
  if (!sub) throw new Error('Missing sub');

  const nowSeconds = Math.floor(now / 1000);
  const iat = nowSeconds - IAT_SKEW_SECONDS;
  const exp = iat + EXP_TTL_SECONDS;

  const header = {
    alg: 'EdDSA',
    kid,
    typ: 'JWT'
  };

  const payload = {
    sub,
    iat,
    exp
  };

  const encodedHeader = base64UrlEncodeJson(header);
  const encodedPayload = base64UrlEncodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const key = await importEd25519PrivateKey(privateKeyPem);
  const signature = new Uint8Array(
    await crypto.subtle.sign('Ed25519', key, utf8Bytes(signingInput))
  );

  return `${signingInput}.${base64UrlEncodeBytes(signature)}`;
}

export async function generateQWeatherJwtFromEnv(env, options = {}) {
  return generateQWeatherJwt({
    privateKeyPem: env.QWEATHER_PRIVATE_KEY || env.qweather_key,
    kid: env.QWEATHER_KID || QWEATHER_KID,
    sub: env.QWEATHER_SUB || QWEATHER_SUB,
    ...options
  });
}

export async function buildQWeatherAuthorizationHeader(env, options = {}) {
  const token = await generateQWeatherJwtFromEnv(env, options);
  return `Bearer ${token}`;
}
