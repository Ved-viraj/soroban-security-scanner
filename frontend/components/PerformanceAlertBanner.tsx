'use client';

import { useState, useEffect } from 'react';

interface VitalsAlert {
  metric: string;
  value: number;
  threshold: number;
  severity: 'Warning' | 'Critical';
  message: string;
  timestamp: string;
}

export function PerformanceAlertBanner() {
  const [alerts, setAlerts] = useState<VitalsAlert[]>([]);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch('/api/v1/performance/web-vitals/alerts');
        if (response.ok) {
          const data = await response.json();
          setAlerts(data.alerts || []);
          setIsVisible((data.alerts || []).length > 0);
        }
      } catch {
        // Silently fail — banner is non-critical
      }
    };

    fetchAlerts();
    const interval = setInterval(fetchAlerts, 60000); // Check every minute
    return () => clearInterval(interval);
  }, []);

  if (!isVisible || alerts.length === 0) return null;

  const criticalCount = alerts.filter(a => a.severity === 'Critical').length;
  const warningCount = alerts.filter(a => a.severity === 'Warning').length;

  return (
    <div
      role="alert"
      className={`fixed top-0 left-0 right-0 z-50 px-4 py-2 text-sm font-medium text-white shadow-lg ${
        criticalCount > 0 ? 'bg-red-600' : 'bg-yellow-500'
      }`}
    >
      <div className="flex items-center justify-between max-w-7xl mx-auto">
        <div className="flex items-center gap-2">
          <span className="text-lg">{criticalCount > 0 ? '🚨' : '⚠️'}</span>
          <span>
            Performance Alert: {criticalCount > 0 && `${criticalCount} critical`}
            {criticalCount > 0 && warningCount > 0 && ', '}
            {warningCount > 0 && `${warningCount} warning`}
            {' — '}
            {alerts.map(a => a.metric).join(', ')}
          </span>
        </div>
        <button
          onClick={() => setIsVisible(false)}
          className="text-white hover:bg-white/20 px-2 py-0.5 rounded transition-colors"
          aria-label="Dismiss alert banner"
        >
          ✕
        </button>
      </div>
    </div>
  );
}
