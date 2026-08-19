/**
 * Client-side session persistence for the auth flows in `components/auth`.
 *
 * Previously, the "Remember me" checkbox on the login form was collected
 * but never used anywhere — it had no effect on session behavior, which
 * misled users into thinking it changed how long they'd stay signed in
 * (see issue #500).
 *
 * This module gives the flag real, verifiable behavior:
 *   - rememberMe = true  -> the session is written to localStorage, so it
 *     survives closing the tab/browser and is restored on the next visit.
 *   - rememberMe = false -> the session is written to sessionStorage, so
 *     it is cleared as soon as the tab/window is closed.
 *
 * This intentionally only controls *where* the client keeps its local copy
 * of the session (persistent vs. tab-scoped storage). It does not change
 * how a session is authenticated or refreshed against a backend — that
 * remains the responsibility of the API layer once one exists.
 */

const SESSION_STORAGE_KEY = 'soroban_auth_session';

export interface StoredSession<T = unknown> {
  user: T;
  rememberMe: boolean;
  /** Epoch ms when the session was persisted. */
  storedAt: number;
}

function getTargetStorage(rememberMe: boolean): Storage | null {
  if (typeof window === 'undefined') return null;
  return rememberMe ? window.localStorage : window.sessionStorage;
}

/**
 * Persist a session for the given user, honoring the rememberMe flag.
 *
 * Any previously stored session (in either storage) is cleared first, so
 * toggling the flag between logins never leaves a stale duplicate behind
 * in the other storage.
 */
export function persistSession<T>(user: T, rememberMe: boolean): void {
  if (typeof window === 'undefined') return;

  clearSession();

  const session: StoredSession<T> = {
    user,
    rememberMe,
    storedAt: Date.now(),
  };

  const storage = getTargetStorage(rememberMe);
  storage?.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

/**
 * Load a previously persisted session, if any.
 *
 * Checks localStorage first (a "remembered" session that outlives the
 * tab), then falls back to sessionStorage (a session scoped to the
 * current tab/window).
 */
export function loadSession<T = unknown>(): StoredSession<T> | null {
  if (typeof window === 'undefined') return null;

  for (const storage of [window.localStorage, window.sessionStorage]) {
    const raw = storage.getItem(SESSION_STORAGE_KEY);
    if (!raw) continue;

    try {
      return JSON.parse(raw) as StoredSession<T>;
    } catch {
      // Corrupt entry — remove it and keep looking in the other storage.
      storage.removeItem(SESSION_STORAGE_KEY);
    }
  }

  return null;
}

/** Remove any persisted session from both localStorage and sessionStorage. */
export function clearSession(): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(SESSION_STORAGE_KEY);
  window.sessionStorage.removeItem(SESSION_STORAGE_KEY);
}
