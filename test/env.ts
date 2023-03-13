import * as crypto from 'crypto';
import { TextEncoder, TextDecoder } from 'util'

// this setup works in node 18.14, failed in my node 16 & 14.

(globalThis as any).TextEncoder = TextEncoder;
(globalThis as any).TextDecoder = TextDecoder;
(globalThis as any).crypto = crypto.webcrypto;

Object.defineProperty(globalThis.self, "crypto", {
  value: {
    subtle: crypto.webcrypto.subtle,
    getRandomValues: crypto.webcrypto.getRandomValues
  },
});
