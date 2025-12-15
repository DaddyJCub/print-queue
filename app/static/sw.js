// Service Worker for Printellect PWA
const SW_VERSION = '2.0.0';
const CACHE_NAME = 'print-queue-v2';
const OFFLINE_URL = '/static/offline.html';

// Log helper with timestamp
function swLog(level, ...args) {
  const ts = new Date().toISOString();
  console[level](`[SW ${SW_VERSION}] [${ts}]`, ...args);
}

// Assets to cache immediately
const PRECACHE_ASSETS = [
  '/',
  '/queue',
  '/static/manifest.json',
  '/static/offline.html',
];

// Error handlers for diagnostics
self.addEventListener('error', (event) => {
  swLog('error', 'Uncaught error:', event.message, event.filename, event.lineno);
});

self.addEventListener('unhandledrejection', (event) => {
  swLog('error', 'Unhandled promise rejection:', event.reason);
});

// Install event - precache essential assets
self.addEventListener('install', (event) => {
  swLog('info', 'Installing...');
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      swLog('info', 'Precaching assets');
      return cache.addAll(PRECACHE_ASSETS).then(() => {
        swLog('info', 'Precache complete');
      }).catch(err => {
        swLog('error', 'Precache failed:', err);
        // Don't fail install if precache fails (network issues)
      });
    })
  );
  // Activate immediately without waiting for old SW to be replaced
  self.skipWaiting();
  swLog('info', 'skipWaiting() called');
});

// Activate event - clean up old caches and claim clients
self.addEventListener('activate', (event) => {
  swLog('info', 'Activating...');
  event.waitUntil(
    Promise.all([
      // Clean old caches
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => {
              swLog('info', 'Deleting old cache:', name);
              return caches.delete(name);
            })
        );
      }),
      // Claim all clients so push works immediately
      self.clients.claim().then(() => {
        swLog('info', 'clients.claim() complete - SW now controls all tabs');
      })
    ])
  );
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

// Handle push notifications
self.addEventListener('push', (event) => {
  swLog('info', 'Push event received');
  if (!event.data) {
    swLog('warn', 'Push event has no data');
    return;
  }
  
  let data;
  try {
    data = event.data.json();
    swLog('info', 'Push payload:', JSON.stringify(data));
  } catch (e) {
    swLog('error', 'Failed to parse push data:', e);
    data = { title: 'Printellect', body: event.data.text() };
  }
  
  const options = {
    body: data.body || 'New notification',
    icon: '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [100, 50, 100],
    tag: data.tag || 'printellect-notification',
    renotify: true,
    data: {
      url: data.url || '/',
    },
  };
  
  event.waitUntil(
    self.registration.showNotification(data.title || 'Printellect', options)
      .then(() => swLog('info', 'Notification shown'))
      .catch(err => swLog('error', 'Failed to show notification:', err))
  );
});

// Handle notification click
self.addEventListener('notificationclick', (event) => {
  swLog('info', 'Notification clicked:', event.notification.tag);
  event.notification.close();
  
  event.waitUntil(
    clients.openWindow(event.notification.data.url || '/')
  );
});

// Message handler for diagnostics
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'GET_SW_STATUS') {
    event.ports[0].postMessage({
      version: SW_VERSION,
      cacheName: CACHE_NAME,
      state: 'active'
    });
  }
});
