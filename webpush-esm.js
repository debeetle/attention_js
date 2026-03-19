// ESM port of webpush-pwa adapted for Cloudflare Workers
// Exports: setVapidDetails(subject, publicKey, privateKey) and sendNotification(subscription, payload, env)

let vapid = {
  subject: null,
  publicKey: null,
  privateKey: null
};

function base64UrlToUint8Array(base64UrlString) {
  base64UrlString = base64UrlString.replace(/-/g, '+').replace(/_/g, '/');
  while (base64UrlString.length % 4) base64UrlString += '=';
  const str = atob(base64UrlString);
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) arr[i] = str.charCodeAt(i);
  return arr;
}

function uint8ArrayToBase64Url(uint8) {
  let binary = '';
  const len = uint8.length;
  for (let i = 0; i < len; i++) binary += String.fromCharCode(uint8[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function importVapidKeyPair(pubB64u, privB64u) {
  const pub = base64UrlToUint8Array(pubB64u);
  const priv = base64UrlToUint8Array(privB64u);

  let x, y;
  if (pub.length === 65 && pub[0] === 0x04) {
    x = pub.slice(1, 33);
    y = pub.slice(33, 65);
  } else if (pub.length === 64) {
    x = pub.slice(0, 32);
    y = pub.slice(32, 64);
  } else {
    throw new Error('Unsupported VAPID public key format');
  }

  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: uint8ArrayToBase64Url(x),
    y: uint8ArrayToBase64Url(y),
    d: uint8ArrayToBase64Url(priv)
  };

  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  return key;
}

function derToJose(signature, keySize = 32) {
  const bytes = new Uint8Array(signature);
  if (bytes.length === keySize * 2) return bytes;
  if (bytes[0] !== 0x30) throw new Error('Invalid DER signature (expected sequence)');
  let offset = 2;
  if (bytes[1] & 0x80) {
    const lenBytes = bytes[1] & 0x7f;
    offset = 2 + lenBytes;
  }
  if (bytes[offset] !== 0x02) throw new Error('Invalid DER signature (expected integer r)');
  let rLen = bytes[offset + 1];
  let rStart = offset + 2;
  let r = bytes.slice(rStart, rStart + rLen);
  offset = rStart + rLen;
  if (bytes[offset] !== 0x02) throw new Error('Invalid DER signature (expected integer s)');
  let sLen = bytes[offset + 1];
  let sStart = offset + 2;
  let s = bytes.slice(sStart, sStart + sLen);

  if (r.length > keySize) r = r.slice(r.length - keySize);
  else if (r.length < keySize) {
    const pad = new Uint8Array(keySize - r.length);
    r = concatUint8Arrays(pad, r);
  }
  if (s.length > keySize) s = s.slice(s.length - keySize);
  else if (s.length < keySize) {
    const pad = new Uint8Array(keySize - s.length);
    s = concatUint8Arrays(pad, s);
  }

  const out = new Uint8Array(keySize * 2);
  out.set(r, 0);
  out.set(s, keySize);
  return out;
}

function concatUint8Arrays(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function randomBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

async function hkdf(salt, ikm, info, length) {
  const saltKey = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const prkBuf = await crypto.subtle.sign('HMAC', saltKey, ikm);

  const prkKey = await crypto.subtle.importKey('raw', prkBuf, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const infoPlus = new Uint8Array(info.length + 1);
  infoPlus.set(info, 0);
  infoPlus[info.length] = 1;
  const t1 = await crypto.subtle.sign('HMAC', prkKey, infoPlus);
  return new Uint8Array(t1).slice(0, length);
}

async function createVapidJwt(audience) {
  if (!vapid.subject || !vapid.publicKey || !vapid.privateKey) throw new Error('VAPID keys not set');
  const header = { alg: 'ES256', typ: 'JWT' };
  const exp = Math.floor(Date.now() / 1000) + 12 * 60 * 60;
  const payload = { aud: audience, exp, sub: vapid.subject };

  const enc = obj => uint8ArrayToBase64Url(new TextEncoder().encode(JSON.stringify(obj)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const data = new TextEncoder().encode(signingInput);

  const key = await importVapidKeyPair(vapid.publicKey, vapid.privateKey);
  const derSig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data);
  const rawSig = derToJose(derSig);
  const token = `${signingInput}.${uint8ArrayToBase64Url(rawSig)}`;
  return token;
}

async function encryptPayload(subscription, payload) {
  const userPublicKey = base64UrlToUint8Array(subscription.keys.p256dh);
  const userAuth = base64UrlToUint8Array(subscription.keys.auth);

  const salt = randomBytes(16);
  const localKeyPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const localPublicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', localKeyPair.publicKey));

  const userPubImported = await crypto.subtle.importKey('raw', userPublicKey.buffer, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: userPubImported }, localKeyPair.privateKey, 256));

  const authInfo = new TextEncoder().encode('Content-Encoding: auth\0');
  const prk = await hkdf(userAuth, sharedSecret, authInfo, 32);

  const keyLabel = new TextEncoder().encode('P-256\0');
  const subscriptionKey = userPublicKey;
  const subscriptionKeyLen = new Uint8Array(2);
  subscriptionKeyLen[1] = subscriptionKey.length;
  const localKeyLen = new Uint8Array(2);
  localKeyLen[1] = localPublicKeyRaw.length;
  const context = concatUint8Arrays(keyLabel, subscriptionKeyLen, subscriptionKey, localKeyLen, localPublicKeyRaw);

  const nonceInfo = concatUint8Arrays(new TextEncoder().encode('Content-Encoding: nonce\0'), context);
  const cekInfo = concatUint8Arrays(new TextEncoder().encode('Content-Encoding: aesgcm\0'), context);

  const nonce = await hkdf(salt, prk, nonceInfo, 12);
  const cek = await hkdf(salt, prk, cekInfo, 16);

  const payloadBytes = new TextEncoder().encode(payload);
  const padding = new Uint8Array(2);
  const plaintext = concatUint8Arrays(padding, payloadBytes);

  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, plaintext);
  const cipherBytes = new Uint8Array(cipherBuf);

  return {
    salt: uint8ArrayToBase64Url(salt),
    localPublicKey: uint8ArrayToBase64Url(localPublicKeyRaw),
    cipherText: cipherBytes
  };
}

function originFromEndpoint(endpoint) {
  try {
    const u = new URL(endpoint);
    return `${u.protocol}//${u.hostname}` + (u.port ? `:${u.port}` : '');
  } catch (e) {
    return endpoint;
  }
}

function setVapidDetails(subject, publicKey, privateKey) {
  vapid.subject = subject;
  vapid.publicKey = publicKey;
  vapid.privateKey = privateKey;
}

async function sendNotification(subscription, payload) {
  const endpoint = subscription.endpoint;
  const audience = originFromEndpoint(endpoint);
  const jwt = await createVapidJwt(audience);

  const vapidPublicB64u = vapid.publicKey;
  const baseHeaders = {
    TTL: '2419200',
    Authorization: `WebPush ${jwt}`,
    'Crypto-Key': `p256ecdsa=${vapidPublicB64u}`
  };

  let fetchOptions = { method: 'POST', headers: baseHeaders, body: null };

  if (payload) {
    const enc = await encryptPayload(subscription, payload);
    fetchOptions.headers = Object.assign({}, fetchOptions.headers, {
      Encryption: `salt=${enc.salt}`,
      'Crypto-Key': `dh=${enc.localPublicKey}; p256ecdsa=${vapidPublicB64u}`,
      'Content-Encoding': 'aesgcm',
      'Content-Type': 'application/octet-stream'
    });
    fetchOptions.body = enc.cipherText;
  }

  const res = await fetch(endpoint, fetchOptions);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`Push send failed: ${res.status} ${res.statusText} ${text}`);
    err.status = res.status;
    throw err;
  }
  return true;
}

export { setVapidDetails, sendNotification };
