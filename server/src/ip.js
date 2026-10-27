function normalized(ip) {
  const value = String(ip || '');
  return value.startsWith('::ffff:') ? value.slice('::ffff:'.length) : value;
}

export function isPrivateAddress(ip) {
  const host = normalized(ip);
  if (host === '127.0.0.1' || host === '::1' || host === 'localhost') return true;
  if (host.startsWith('10.') || host.startsWith('192.168.')) return true;
  const parts = host.split('.');
  if (parts.length === 4 && parts.every((part) => /^\d+$/.test(part))) {
    const [first, second] = parts.map(Number);
    if (first === 172 && second >= 16 && second <= 31) return true;
  }
  const lower = host.toLowerCase();
  return lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80');
}

function forwardedClient(value) {
  if (typeof value !== 'string') return '';
  return value.split(',')[0].trim();
}

export function clientIp(req) {
  const peer = String(req.socket?.remoteAddress || req.ip || 'unknown');
  if (isPrivateAddress(peer)) {
    const real = forwardedClient(req.headers?.['x-real-ip']);
    if (real) return real.slice(0, 64);
    const forwarded = forwardedClient(req.headers?.['x-forwarded-for']);
    if (forwarded) return forwarded.slice(0, 64);
  }
  return peer.slice(0, 64);
}
