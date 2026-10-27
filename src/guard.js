/* Runtime tripwires.

   These do not make the page "more secure" — they make a claim checkable.
   If any code path ever reaches for the network or a persistent store, the
   violation is printed to the terminal instead of silently succeeding, and
   the top bar flips to say so. The only network use this app makes is
   fetching its own files; message content never leaves the page. */

const NETWORK = [
  ['fetch', 'fetch'],
  ['XMLHttpRequest', 'XMLHttpRequest'],
  ['WebSocket', 'WebSocket'],
  ['EventSource', 'EventSource'],
];

const STORAGE = [
  ['localStorage', 'localStorage'],
  ['sessionStorage', 'sessionStorage'],
];

export function installGuards(report) {
  if (typeof window === 'undefined') return;

  const trip = (label) => {
    try { report(label); } catch { /* reporter must never break the app */ }
  };

  for (const [prop] of NETWORK) {
    try {
      Object.defineProperty(window, prop, {
        configurable: true,
        get() {
          trip(prop);
          return function BlockedByRootNode() {
            throw new Error(`network egress blocked by ROOT//NODE (${prop})`);
          };
        },
      });
    } catch { /* some engines refuse to redefine; leave it alone */ }
  }

  for (const [prop] of STORAGE) {
    try {
      Object.defineProperty(window, prop, {
        configurable: true,
        get() {
          trip(prop);
          throw new Error(`persistent storage blocked by ROOT//NODE (${prop})`);
        },
      });
    } catch { /* ignore */ }
  }

  try {
    const realOpen = window.indexedDB && window.indexedDB.open;
    if (realOpen) {
      window.indexedDB.open = function () {
        trip('indexedDB');
        throw new Error('persistent storage blocked by ROOT//NODE (indexedDB)');
      };
    }
  } catch { /* ignore */ }

  try {
    if (navigator.sendBeacon) {
      Object.defineProperty(navigator, 'sendBeacon', {
        configurable: true,
        get() {
          trip('sendBeacon');
          return () => { throw new Error('network egress blocked (sendBeacon)'); };
        },
      });
    }
  } catch { /* ignore */ }

  // Service workers would be another persistence vector; refuse to register.
  try {
    if (navigator.serviceWorker) {
      Object.defineProperty(navigator.serviceWorker, 'register', {
        configurable: true,
        value: function () {
          trip('serviceWorker');
          return Promise.reject(new Error('service workers blocked by ROOT//NODE'));
        },
      });
    }
  } catch { /* ignore */ }
}
