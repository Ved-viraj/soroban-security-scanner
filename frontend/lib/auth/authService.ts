/**
 * Auth service boundary for the frontend.
 *
 * All authentication flows (login, sign-up, password reset, MFA
 * verification) go through this module instead of embedding mock logic
 * in components. Swapping the mock for a real backend only requires
 * replacing the function bodies here with API calls; component code and
 * tests stay unchanged.
 *
 * Mock auth is strictly opt-in and never available in production by
 * default:
 *
 *   - `NEXT_PUBLIC_ENABLE_MOCK_AUTH=true`  -> mocks enabled everywhere
 *   - `NEXT_PUBLIC_ENABLE_MOCK_AUTH=false` -> mocks disabled everywhere
 *   - unset                                -> enabled only outside
 *     production builds (local dev / tests), disabled in `next build`
 *     output because Next.js inlines `process.env.NODE_ENV`.
 *
 * There are no hardcoded demo credentials and no fixed MFA code. The
 * mock MFA flow generates a fresh one-time code when a code is "sent"
 * and only accepts that code, mirroring server-side one-time code
 * validation. The pending code is exposed through `getPendingMfaCode()`
 * so the demo UI (and tests) can surface the simulated delivery; this
 * only ever matters while mock auth is explicitly enabled.
 */

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe: boolean;
}

export interface SignUpData {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
}

export interface AuthUser {
  email: string;
  name: string;
  verified?: boolean;
}

export interface LoginResult {
  user: AuthUser;
  requiresMfa: boolean;
}

const MOCK_AUTH_FLAG = 'NEXT_PUBLIC_ENABLE_MOCK_AUTH';

/** The most recently "sent" one-time code in mock mode. */
let pendingMfaCode: string | null = null;

/**
 * Whether the mock implementation may run.
 *
 * Production builds default to disabled: unless the operator explicitly
 * sets `NEXT_PUBLIC_ENABLE_MOCK_AUTH=true`, the flag is inlined as
 * undefined during `next build` and `process.env.NODE_ENV` is inlined
 * as `"production"`, so this evaluates to `false` in shipped bundles.
 */
export function isMockAuthEnabled(): boolean {
  if (process.env[MOCK_AUTH_FLAG] === 'true') return true;
  if (process.env[MOCK_AUTH_FLAG] === 'false') return false;
  return process.env.NODE_ENV !== 'production';
}

function assertMockAuthAllowed(): void {
  if (!isMockAuthEnabled()) {
    throw new Error(
      'Authentication is unavailable: mock auth is disabled in this build. ' +
        'Configure a real auth backend, or set NEXT_PUBLIC_ENABLE_MOCK_AUTH=true ' +
        'for local development only.'
    );
  }
}

function simulateDelay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function generateSixDigitCode(): string {
  const buffer = new Uint32Array(1);
  crypto.getRandomValues(buffer);
  return String(100000 + (buffer[0] % 900000));
}

/** The one-time code the mock most recently "sent", if any. */
export function getPendingMfaCode(): string | null {
  return pendingMfaCode;
}

/**
 * Mock login. Simulates a successful API round-trip for any well-formed
 * credentials — there are no hardcoded demo accounts. Returns a result
 * that always requires MFA, matching the mock's flow.
 */
export async function login(credentials: LoginCredentials): Promise<LoginResult> {
  assertMockAuthAllowed();
  await simulateDelay(1500);

  return {
    user: {
      email: credentials.email,
      name: credentials.email.split('@')[0] || 'User',
    },
    requiresMfa: true,
  };
}

/** Mock sign-up. Simulates account creation against an API. */
export async function signUp(data: SignUpData): Promise<AuthUser> {
  assertMockAuthAllowed();
  await simulateDelay(2000);

  return {
    email: data.email,
    name: `${data.firstName} ${data.lastName}`.trim() || 'User',
  };
}

/** Mock password reset. Simulates the API sending a reset email. */
export async function resetPassword(email: string): Promise<void> {
  assertMockAuthAllowed();
  await simulateDelay(1000);
}

/**
 * Mock MFA code delivery. Generates a fresh one-time code and stores it
 * as the "sent" code; a real implementation would call the backend,
 * which generates and delivers the code server-side.
 */
export async function sendMfaCode(_method: string): Promise<void> {
  assertMockAuthAllowed();
  await simulateDelay(500);
  pendingMfaCode = generateSixDigitCode();
}

/** Mock MFA code re-send. Regenerates the one-time code. */
export async function resendMfaCode(_method: string): Promise<void> {
  assertMockAuthAllowed();
  await simulateDelay(500);
  pendingMfaCode = generateSixDigitCode();
}

/**
 * Mock MFA verification. Only accepts the code that was previously
 * "sent"; the code is invalidated after a successful check. There is no
 * fixed or guessable code.
 */
export async function verifyMfa(code: string, _method: string): Promise<void> {
  assertMockAuthAllowed();
  await simulateDelay(1000);

  if (!pendingMfaCode || code !== pendingMfaCode) {
    throw new Error('Invalid verification code');
  }

  pendingMfaCode = null;
}
