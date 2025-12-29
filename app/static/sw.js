// Service Worker for Printellect PWA
const SW_VERSION = '2.5.0';
const CACHE_NAME = 'print-queue-v7';
const OFFLINE_URL = '/static/offline.html';
let ACTIVE_TRIP_USER = null;

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
  
  const url = new URL(event.request.url);
  const isTripPage = url.pathname.startsWith('/trips');
  
  // Skip admin routes (always need fresh data)
  if (event.request.url.includes('/admin')) return;
  
  // Skip API routes (including trips API)
  if (event.request.url.includes('/api/')) return;
  if (event.request.url.includes('/trips/api/')) return;
  
  // Skip my-requests routes (has dynamic redirect logic that shouldn't be cached)
  if (event.request.url.includes('/my-requests')) return;
  
  // Skip auth/user profile routes (has session-dependent content)
  if (event.request.url.includes('/auth/') || event.request.url.includes('/user/')) return;
  
  // Skip trip PDF download (dynamic file serving)
  if (event.request.url.includes('/pdf/view')) return;
  
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Clone the response before caching
        const responseClone = response.clone();
        
        // Cache successful responses for HTML pages and static assets
        if (response.ok) {
          const shouldCache = 
            event.request.destination === 'document' ||
            url.pathname.startsWith('/static/') ||
            url.pathname === '/queue' ||
            url.pathname === '/';
          
          if (shouldCache) {
            caches.open(CACHE_NAME).then((cache) => {
              // For trip pages, only cache when we have an active user context
              if (isTripPage) {
                if (!ACTIVE_TRIP_USER) return;
                const cacheCopy = responseClone.clone();
                const headers = new Headers(cacheCopy.headers);
                headers.set('X-Trip-User', ACTIVE_TRIP_USER);
                const taggedResponse = new Response(cacheCopy.body, {
                  status: cacheCopy.status,
                  statusText: cacheCopy.statusText,
                  headers,
                });
                cache.put(event.request, taggedResponse);
              } else {
                cache.put(event.request, responseClone);
              }
            });
          }
        }
        
        return response;
      })
      .catch(() => {
        // Network failed, try cache
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            if (isTripPage) {
              const owner = cachedResponse.headers.get('X-Trip-User');
              if (!ACTIVE_TRIP_USER || owner !== ACTIVE_TRIP_USER) {
                return caches.match(OFFLINE_URL);
              }
            }
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
    icon: data.icon || '/static/icons/icon-192.png',
    badge: '/static/icons/badge-96.png',  // Monochrome icon for Android status bar
    vibrate: [100, 50, 100],
    tag: data.tag || 'printellect-notification',
    renotify: true,
    data: {
      url: data.url || '/',
      // Pass through any custom data from the push payload
      ...(data.data || {}),
    },
  };
  
  // Add image if provided (for progress notifications with snapshots)
  // Note: 'image' shows as a large image in the notification on supported platforms
  if (data.image) {
    options.image = data.image;
    swLog('info', 'Including image in notification:', data.image);
  }
  
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
  if (!event.data) return;
  
  if (event.data.type === 'GET_SW_STATUS') {
    event.ports[0]?.postMessage({
      version: SW_VERSION,
      cacheName: CACHE_NAME,
      state: 'active'
    });
  }
  
  if (event.data.type === 'SET_ACTIVE_USER') {
    ACTIVE_TRIP_USER = event.data.userId || null;
    // Clean up any trip caches belonging to other users
    caches.keys().then((names) => {
      names
        .filter((name) => name.startsWith('trip-cache-') && !name.endsWith(String(ACTIVE_TRIP_USER)))
        .forEach((name) => caches.delete(name));
    }).catch(() => {});
  }
  
  if (event.data.type === 'CLEAR_ACTIVE_USER') {
    ACTIVE_TRIP_USER = null;
    caches.keys().then((names) => {
      names.filter((name) => name.startsWith('trip-cache-')).forEach((name) => caches.delete(name));
    }).catch(() => {});
  }
});
