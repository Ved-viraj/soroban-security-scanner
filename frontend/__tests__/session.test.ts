import { persistSession, loadSession, clearSession } from '../lib/auth/session';

describe('session persistence (rememberMe semantics)', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('stores the session in localStorage when rememberMe is true', () => {
    persistSession({ email: 'demo@example.com' }, true);

    expect(window.localStorage.getItem('soroban_auth_session')).not.toBeNull();
    expect(window.sessionStorage.getItem('soroban_auth_session')).toBeNull();
  });

  it('stores the session in sessionStorage when rememberMe is false', () => {
    persistSession({ email: 'demo@example.com' }, false);

    expect(window.sessionStorage.getItem('soroban_auth_session')).not.toBeNull();
    expect(window.localStorage.getItem('soroban_auth_session')).toBeNull();
  });

  it('round-trips the stored user and rememberMe flag through loadSession', () => {
    persistSession({ email: 'demo@example.com' }, true);

    const session = loadSession<{ email: string }>();

    expect(session).not.toBeNull();
    expect(session?.user).toEqual({ email: 'demo@example.com' });
    expect(session?.rememberMe).toBe(true);
    expect(typeof session?.storedAt).toBe('number');
  });

  it('clears any prior session from the other storage when rememberMe changes', () => {
    persistSession({ email: 'demo@example.com' }, true);
    expect(window.localStorage.getItem('soroban_auth_session')).not.toBeNull();

    persistSession({ email: 'demo@example.com' }, false);

    expect(window.localStorage.getItem('soroban_auth_session')).toBeNull();
    expect(window.sessionStorage.getItem('soroban_auth_session')).not.toBeNull();
  });

  it('returns null when no session has been persisted', () => {
    expect(loadSession()).toBeNull();
  });

  it('clearSession removes the session from both storages', () => {
    persistSession({ email: 'demo@example.com' }, true);
    persistSession({ email: 'demo@example.com' }, false);

    // Manually seed both storages to verify clearSession wipes both.
    window.localStorage.setItem('soroban_auth_session', JSON.stringify({ user: {} }));

    clearSession();

    expect(window.localStorage.getItem('soroban_auth_session')).toBeNull();
    expect(window.sessionStorage.getItem('soroban_auth_session')).toBeNull();
    expect(loadSession()).toBeNull();
  });

  it('discards and cleans up a corrupted session entry instead of throwing', () => {
    window.localStorage.setItem('soroban_auth_session', '{not valid json');

    expect(() => loadSession()).not.toThrow();
    expect(loadSession()).toBeNull();
    expect(window.localStorage.getItem('soroban_auth_session')).toBeNull();
  });
});
