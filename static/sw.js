// static/sw.js

// 1. STANDARD LIFECYCLE
self.addEventListener('install', (event) => {
    self.skipWaiting(); 
});

self.addEventListener('activate', (event) => {
    event.waitUntil(clients.claim()); 
});

// HELPER: Normalize paths (Safeguard for trailing slashes)
// Ensures that "/chat/5/" matches "/chat/5"
function normalizePath(path) {
    return path.replace(/\/$/, "");
}

// 2. PUSH EVENT
self.addEventListener('push', function(event) {
  if (event.data) {
    const data = event.data.json();
    
    // Create URL object from the payload data
    const notificationUrl = new URL(data.url, self.location.origin);

    const options = {
      body: data.body,
      icon: data.icon,   // User Avatar (Modern)
      image: data.image, // Post Cover Image (Android/Desktop Rich Media)
      badge: data.badge, // Small Status Bar Icon
      tag: data.tag,     // Prevents notification spam (updates existing)
      renotify: true,    // Vibrate/Sound even if replacing an old tag
      timestamp: data.timestamp, // Server-side timestamp for accuracy
      data: { url: data.url },   // Persist URL for click event
      
      // MODERN ACTIONS
      actions: [
        {
          action: 'view',
          title: '👀 View',
        },
        {
          action: 'close',
          title: '✖ Close',
        }
      ]
    };

    event.waitUntil(
      clients.matchAll({ type: 'window', includeUncontrolled: true })
        .then(function(clientList) {
          
          // Check if user is active in the SPECIFIC chat sending the message
          const isChatOpenAndFocused = clientList.some(client => {
            const clientUrl = new URL(client.url, self.location.origin);
            
            // Check 1: Is the tab focused?
            const isFocused = client.focused;
            
            // Check 2: Match the PATHnames (Normalized for safety)
            const clientPath = normalizePath(clientUrl.pathname);
            const notifPath = normalizePath(notificationUrl.pathname);

            return isFocused && (clientPath === notifPath);
          });

          if (isChatOpenAndFocused) {
            console.log("User is active in this specific chat. Suppressing.");
            return; 
          }

          // Otherwise, show it
          return self.registration.showNotification(data.title, options);
        })
    );
  }
});

// 3. CLICK EVENT
self.addEventListener('notificationclick', function(event) {
  event.notification.close(); // Close the notification immediately
  
  // Handle Button Clicks (Modern Action)
  if (event.action === 'close') {
    return;
  }
  
  // Clean logic to focus existing tab or open new one
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(function(clientList) {
        
        const targetUrl = new URL(event.notification.data.url, self.location.origin);
        const targetPath = normalizePath(targetUrl.pathname);

        // 1. Try to find an existing tab with this URL
        for (const client of clientList) {
          const clientUrl = new URL(client.url, self.location.origin);
          
          // Match path even if one has a trailing slash and the other doesn't
          if (normalizePath(clientUrl.pathname) === targetPath && 'focus' in client) {
            return client.focus();
          }
        }
        
        // 2. If no tab found, open a new one
        if (clients.openWindow) {
          return clients.openWindow(event.notification.data.url);
        }
      })
  );
});
