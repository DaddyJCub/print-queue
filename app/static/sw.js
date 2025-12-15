// Service Worker for Printellect PWA
const CACHE_NAME = 'print-queue-v1';
const OFFLINE_URL = '/static/offline.html';

// Assets to cache immediately
const PRECACHE_ASSETS = [
  '/',
  '/queue',
  '/static/manifest.json',
  '/static/offline.html',
];

// Install event - precache essential assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[SW] Precaching assets');
      return cache.addAll(PRECACHE_ASSETS);
    })
  );
  // Activate immediately
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => {
            console.log('[SW] Deleting old cache:', name);
            return caches.delete(name);
          })
      );
    })
  );
  // Take control immediately
  self.clients.claim();
});

// Fetch event - network first with cache fallback
self.addEventListener('fetch', (event) => {
  // Skip non-GET requests
  if (event.request.method !== 'GET') return;
  
  // Skip admin routes (always need fresh data)
  if (event.request.url.includes('/admin')) return;
  
  // Skip API routes
  if (event.request.url.includes('/api/')) return;
  
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Clone the response before caching
        const responseClone = response.clone();
        
        // Cache successful responses for HTML pages and static assets
        if (response.ok) {
          const url = new URL(event.request.url);
          const shouldCache = 
            event.request.destination === 'document' ||
            url.pathname.startsWith('/static/') ||
            url.pathname === '/queue' ||
            url.pathname === '/';
          
          if (shouldCache) {
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, responseClone);
            });
          }
        }
        
        return response;
      })
      .catch(() => {
        // Network failed, try cache
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }
          
          // If it's a navigation request, show offline page
          if (event.request.destination === 'document') {
            return caches.match(OFFLINE_URL);
          }
          
          // Return empty response for other requests
          return new Response('', { status: 503, statusText: 'Offline' });
        });
      })
  );
});

// Handle push notifications (if enabled in the future)
self.addEventListener('push', (event) => {
  if (!event.data) return;
  
  const data = event.data.json();
  const options = {
    body: data.body || 'New notification',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [100, 50, 100],
    data: {
      url: data.url || '/',
    },
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || 'Printellect', options)
  );
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  
  event.waitUntil(
    clients.openWindow(event.notification.data.url || '/')
  );
});
