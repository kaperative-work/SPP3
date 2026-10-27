export function guardBlocked(state, now) {
  if (!state?.lockedUntil || state.lockedUntil <= now) {
    return { locked: false, retryAfterSec: 0 };
  }
  return {
    locked: true,
    retryAfterSec: Math.max(1, Math.ceil((state.lockedUntil - now) / 1000)),
  };
}

export function recordFailure(state, now, policy) {
  const fresh = !state || now - state.windowStartedAt >= policy.windowMs;
  if (fresh) {
    return {
      failedCount: 1,
      windowStartedAt: now,
      lockedUntil: policy.maxFailures <= 1 ? now + policy.lockMs : null,
    };
  }
  const failedCount = state.failedCount + 1;
  const stillLocked = state.lockedUntil && state.lockedUntil > now ? state.lockedUntil : null;
  return {
    failedCount,
    windowStartedAt: state.windowStartedAt,
    lockedUntil: failedCount >= policy.maxFailures ? now + policy.lockMs : stillLocked,
  };
}
