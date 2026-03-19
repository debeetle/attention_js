import { setVapidDetails, sendNotification } from './websub_webhook_rss.js';

function base64ToUint8Array(b64) {
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

async function aesGcmEncrypt(rawKeyBase64, plaintextStr) {
  const keyBytes = base64ToUint8Array(rawKeyBase64);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintextStr));
  return { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
}

async function aesGcmDecrypt(rawKeyBase64, ivArr, ctArr) {
  const keyBytes = base64ToUint8Array(rawKeyBase64);
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const iv = new Uint8Array(ivArr);
  const ct = new Uint8Array(ctArr).buffer;
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(ptBuf);
}

async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  const arr = new Uint8Array(buf);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

function splitCsv(value) {
  return (value || '').split(',').map(s => s.trim()).filter(Boolean);
}

function getRequestOrigin(request) {
  return request.headers.get('Origin') || request.headers.get('Referer') || '';
}

function isOriginAllowed(request, allowedList) {
  if (!allowedList || allowedList.length === 0) return true;
  const origin = getRequestOrigin(request);
  if (!origin) return false;
  return allowedList.some(item => origin.startsWith(item));
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function formEncode(params) {
  return Object.entries(params)
    .filter(([, value]) => value !== undefined && value !== null && String(value).length > 0)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join('&');
}

async function hmacHex(secret, data, hash = 'SHA-256') {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: { name: hash } },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, data);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyWebhookSignature(request, rawBody, secret) {
  if (!secret) return true;
  const sig256 = request.headers.get('x-hub-signature-256') || request.headers.get('x-signature-sha256') || '';
  const sig1 = request.headers.get('x-hub-signature') || request.headers.get('x-signature-sha1') || '';

  if (sig256.startsWith('sha256=')) {
    const expected = await hmacHex(secret, rawBody, 'SHA-256');
    return safeEqual(`sha256=${expected}`, sig256);
  }

  if (sig1.startsWith('sha1=')) {
    const expected = await hmacHex(secret, rawBody, 'SHA-1');
    return safeEqual(`sha1=${expected}`, sig1);
  }

  return false;
}

async function fetchFeedPreview(feedUrl) {
  const res = await fetch(feedUrl, {
    headers: { 'User-Agent': 'Attention-Worker/1.0' }
  });
  const text = await res.text();
  return { status: res.status, contentType: res.headers.get('content-type') || '', text };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const allowedOrigins = splitCsv(env.ALLOWED_ORIGINS);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type,x-api-key,x-hub-signature,x-hub-signature-256,x-signature-sha1,x-signature-sha256'
        }
      });
    }

    if (env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY) {
      setVapidDetails(env.VAPID_SUBJECT || 'mailto:nobody@example.com', env.VAPID_PUBLIC_KEY, env.VAPID_PRIVATE_KEY);
    }

    if (request.method === 'GET' && url.pathname === '/config') {
      return json({ vapidPublicKey: env.VAPID_PUBLIC_KEY || '' });
    }

    if (request.method === 'POST' && url.pathname === '/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const sub = await request.json();
      const endpoint = sub && sub.endpoint;
      if (!endpoint) return new Response('Bad Request', { status: 400 });

      const key = await sha256hex(endpoint);
      try {
        const existing = await env.SUBS.get(key);
        if (existing) {
          const parsed = JSON.parse(existing);
          const plainOld = await aesGcmDecrypt(env.SUBS_ENC_KEY, parsed.iv, parsed.ct);
          const objOld = JSON.parse(plainOld);
          const oldSub = objOld.sub;
          const sameEndpoint = oldSub.endpoint === sub.endpoint;
          const sameP256dh = oldSub.keys && sub.keys && oldSub.keys.p256dh === sub.keys.p256dh;
          const sameAuth = oldSub.keys && sub.keys && oldSub.keys.auth === sub.keys.auth;
          if (sameEndpoint && sameP256dh && sameAuth) {
            return json({ status: 'ok', updated: false });
          }
        }
      } catch (e) {
      }

      const plain = JSON.stringify({ sub, created: Date.now() });
      const enc = await aesGcmEncrypt(env.SUBS_ENC_KEY, plain);
      await env.SUBS.put(key, JSON.stringify({ iv: enc.iv, ct: enc.ct }));
      return json({ status: 'ok', updated: true });
    }

    if (request.method === 'POST' && url.pathname === '/unsubscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json();
      if (!body || !body.endpoint) return new Response('Bad Request', { status: 400 });
      await env.SUBS.delete(await sha256hex(body.endpoint));
      return json({ status: 'deleted' });
    }

    if (request.method === 'POST' && url.pathname === '/send') {
      const apiKey = request.headers.get('x-api-key');
      if (!apiKey || apiKey !== env.SEND_API_KEY) return new Response('Unauthorized', { status: 401 });
      const body = await request.json();
      const endpoint = body && body.endpoint;
      if (!endpoint) return new Response('Bad Request', { status: 400 });

      const stored = await env.SUBS.get(await sha256hex(endpoint));
      if (!stored) return new Response('Not found', { status: 404 });

      const parsed = JSON.parse(stored);
      const plain = await aesGcmDecrypt(env.SUBS_ENC_KEY, parsed.iv, parsed.ct);
      const subscription = JSON.parse(plain).sub;

      try {
        await sendNotification(subscription, JSON.stringify(body.payload || {}));
        return json({ ok: true });
      } catch (e) {
        return new Response(String(e && e.message ? e.message : e), { status: 500 });
      }
    }

    if (url.pathname === '/websub') {
      if (request.method === 'GET') {
        const mode = url.searchParams.get('hub.mode');
        const challenge = url.searchParams.get('hub.challenge');
        const token = url.searchParams.get('hub.verify_token');
        if (!mode || !challenge) return new Response('Bad Request', { status: 400 });
        if (env.WEBSUB_VERIFY_TOKEN && token !== env.WEBSUB_VERIFY_TOKEN) return new Response('Forbidden', { status: 403 });
        return new Response(challenge, { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      if (request.method === 'POST') {
        const rawBody = await request.arrayBuffer();
        if (env.WEBSUB_SECRET) {
          const ok = await verifyWebhookSignature(request, rawBody, env.WEBSUB_SECRET);
          if (!ok) return new Response('Unauthorized', { status: 401 });
        }
        return new Response(null, { status: 204 });
      }

      return new Response('Method Not Allowed', { status: 405 });
    }

    if (request.method === 'POST' && url.pathname === '/websub/subscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json().catch(() => ({}));
      const hub = body.hub || env.WEBSUB_HUB_URL || '';
      const topic = body.topic || env.WEBSUB_TOPIC || '';
      const callback = body.callback || env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`;
      const secret = body.secret || env.WEBSUB_SECRET || '';
      const leaseSeconds = body.lease_seconds || env.WEBSUB_LEASE_SECONDS || '864000';
      if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

      const res = await fetch(hub, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formEncode({
          'hub.mode': 'subscribe',
          'hub.topic': topic,
          'hub.callback': callback,
          'hub.secret': secret,
          'hub.lease_seconds': leaseSeconds
        })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

    if (request.method === 'POST' && url.pathname === '/websub/unsubscribe') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const body = await request.json().catch(() => ({}));
      const hub = body.hub || env.WEBSUB_HUB_URL || '';
      const topic = body.topic || env.WEBSUB_TOPIC || '';
      const callback = body.callback || env.WEBSUB_CALLBACK_URL || `${url.origin}/websub`;
      if (!hub || !topic || !callback) return new Response('Missing hub, topic, or callback URL', { status: 400 });

      const res = await fetch(hub, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formEncode({
          'hub.mode': 'unsubscribe',
          'hub.topic': topic,
          'hub.callback': callback
        })
      });
      return json({ ok: res.ok, status: res.status, body: await res.text().catch(() => '') }, res.status);
    }

    if (request.method === 'POST' && url.pathname === '/webhook') {
      if (!isOriginAllowed(request, allowedOrigins)) return new Response('Forbidden', { status: 403 });
      const rawBody = await request.arrayBuffer();
      if (env.WEBHOOK_SECRET) {
        const ok = await verifyWebhookSignature(request, rawBody, env.WEBHOOK_SECRET);
        if (!ok) return new Response('Unauthorized', { status: 401 });
      }
      return new Response(null, { status: 204 });
    }

    if (request.method === 'GET' && url.pathname === '/poll') {
      const feedUrl = url.searchParams.get('url') || env.POLL_URL || '';
      if (!feedUrl) return new Response('Missing feed URL', { status: 400 });
      const preview = await fetchFeedPreview(feedUrl);
      return json({
        ok: true,
        feedUrl,
        status: preview.status,
        contentType: preview.contentType,
        preview: preview.text.slice(0, 4000)
      });
    }

    return env.ASSETS.fetch(request);
  }
};
