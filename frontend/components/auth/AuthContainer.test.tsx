import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import AuthContainer from './AuthContainer';

const SESSION_KEY = 'soroban_auth_session';

async function loginAndCompleteMfa(rememberMe: boolean) {
  const user = userEvent.setup();
  render(<AuthContainer />);

  await user.type(screen.getByLabelText(/email address/i), 'user@example.com');
  await user.type(screen.getByLabelText(/^password$/i), 'correct horse battery staple');

  if (rememberMe) {
    await user.click(screen.getByLabelText(/remember me/i));
  }

  await user.click(screen.getByRole('button', { name: /sign in/i }));

  // The mock login always requires MFA before a session is established.
  const codeInput = await screen.findByLabelText(/verification code/i, {}, { timeout: 3000 });

  // Demo mode surfaces the one-time code the mock "sent"; use that code
  // to complete MFA (there is no fixed/known code anymore).
  const demoHint = await screen.findByText(/demo mode/i, {}, { timeout: 3000 });
  const sentCode = demoHint.textContent?.match(/\b\d{6}\b/)?.[0];
  expect(sentCode).toBeDefined();

  await user.type(codeInput, sentCode as string);
  await user.click(screen.getByRole('button', { name: /verify code/i }));

  await waitFor(() => expect(screen.getByText(/authentication successful/i)).toBeInTheDocument(), {
    timeout: 3000,
  });
}

describe('AuthContainer - rememberMe session persistence', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('does not persist a session until authentication (including MFA) fully completes', async () => {
    const user = userEvent.setup();
    render(<AuthContainer />);

    await user.type(screen.getByLabelText(/email address/i), 'user@example.com');
    await user.type(screen.getByLabelText(/^password$/i), 'correct horse battery staple');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await screen.findByLabelText(/verification code/i, {}, { timeout: 3000 });

    expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();
    expect(window.sessionStorage.getItem(SESSION_KEY)).toBeNull();
  });

  it('persists the session in localStorage when rememberMe is checked', async () => {
    await loginAndCompleteMfa(true);

    expect(window.localStorage.getItem(SESSION_KEY)).not.toBeNull();
    expect(window.sessionStorage.getItem(SESSION_KEY)).toBeNull();
  }, 10000);

  it('persists the session in sessionStorage (not localStorage) when rememberMe is unchecked', async () => {
    await loginAndCompleteMfa(false);

    expect(window.sessionStorage.getItem(SESSION_KEY)).not.toBeNull();
    expect(window.localStorage.getItem(SESSION_KEY)).toBeNull();
  }, 10000);
});
