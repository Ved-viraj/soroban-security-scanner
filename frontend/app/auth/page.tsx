'use client';

import React from 'react';
import AuthContainer from '../../components/auth/AuthContainer';
import { PageErrorBoundary } from '../../components/ui/ErrorBoundary';

export default function AuthPage() {
  return (
    <PageErrorBoundary context={{ page: 'auth' }}>
      <div className="min-h-screen">
        <AuthContainer />
      </div>
    </PageErrorBoundary>
  );
}
