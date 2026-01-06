/* Service Worker: Push notifications for To-Do PWA */

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    try {
      data = { body: event.data ? event.data.text() : '' };
    } catch (e2) {
      data = {};
    }
  }

  const title = (data && data.title) ? String(data.title) : 'Erinnerung';
  const body = (data && data.body) ? String(data.body) : '';
  const url = (data && data.url) ? String(data.url) : '/todo';

  event.waitUntil(
    self.registration.showNotification(title, {
      body,
      tag: 'todo_push',
      renotify: true,
      data: { url }
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification && event.notification.data && event.notification.data.url) ? event.notification.data.url : '/todo';

  event.waitUntil((async () => {
    const allClients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of allClients) {
      if (client.url && client.url.includes(url)) {
        await client.focus();
        return;
      }
    }
    await self.clients.openWindow(url);
  })());
});
