const VERSION='e-control-guest-network-only-v1';
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('fetch',event=>{
  // Dashboard, API, token, PIN and Home Assistant data always stay on the network.
  event.respondWith(fetch(event.request));
});
