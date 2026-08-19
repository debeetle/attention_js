const CACHE_NAME = 'attention1';
const ASSETS = [
    '/',
    '/index.html',
    '/manifest.webmanifest',
    '/font/STZHONGS.TTF',
    '/font/SourceCodePro-VariableFont_wght.ttf',
    '/font/latinmodern-math.otf',
    '/figure/Git_icon.svg',
    '/figure/Wikipedia-logo-v2.svg',
    '/figure/sspai.svg',
    '/figure/IThome_logo.png'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS))
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames.map((cacheName) => {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

self.addEventListener('fetch', (event) => {
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            return cachedResponse || fetch(event.request);
        })
    );
});
