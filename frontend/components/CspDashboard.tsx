'use client';

import { useEffect, useMemo, useState } from 'react';
import { BarChart3, ShieldAlert, TrendingUp } from 'lucide-react';

interface ViolationItem {
  directive: string;
  blocked_uri: string;
  document_uri: string;
  source_file?: string;
  line_number?: number;
  violated_at: string;
  user_agent?: string;
}

interface DashboardResponse {
  violations_by_directive: Array<{ directive: string; count: number; trend: string }>;
  top_blocked_uris: Array<{ blocked_uri: string; count: number }>;
  violations_over_time: Array<{ date: string; count: number }>;
}

export default function CspDashboard() {
  const [violations, setViolations] = useState<ViolationItem[]>([]);
  const [dashboard, setDashboard] = useState<DashboardResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const [violationsRes, dashboardRes] = await Promise.all([
          fetch('/api/v1/security/csp-violations?per_page=10').then(res => res.json()),
          fetch('/api/v1/security/csp-dashboard').then(res => res.json()),
        ]);
        setViolations(violationsRes.data ?? []);
        setDashboard(dashboardRes);
      } catch (error) {
        console.error('Unable to load CSP dashboard', error);
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  const totalViolations = useMemo(() => violations.length, [violations]);

  if (loading) {
    return <div className="skeleton h-96 w-full rounded-lg" />;
  }

  return (
    <div className="space-y-6 rounded-xl border border-gray-200 bg-white p-6 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-semibold text-gray-900">CSP violation dashboard</h2>
          <p className="mt-2 text-sm text-gray-600">
            Review report-only violations, track directive drift, and prioritize enforcement
            readiness.
          </p>
        </div>
        <div className="rounded-full bg-blue-50 px-3 py-2 text-sm font-semibold text-blue-700">
          {totalViolations} recent violations
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-gray-200 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <TrendingUp className="h-4 w-4 text-blue-600" />
            Violation trend
          </div>
          <div className="space-y-2">
            {(dashboard?.violations_over_time ?? []).map(item => (
              <div
                key={item.date}
                className="flex items-center justify-between text-sm text-gray-600"
              >
                <span>{item.date}</span>
                <span className="font-semibold text-gray-900">{item.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-gray-200 p-4">
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-700">
            <BarChart3 className="h-4 w-4 text-emerald-600" />
            Directive breakdown
          </div>
          <div className="space-y-2">
            {(dashboard?.violations_by_directive ?? []).map(item => (
              <div
                key={item.directive}
                className="flex items-center justify-between text-sm text-gray-600"
              >
                <span>{item.directive}</span>
                <span className="font-semibold text-gray-900">{item.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-gray-200 p-4">
        <div className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-700">
          <ShieldAlert className="h-4 w-4 text-amber-600" />
          Recent violations
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead>
              <tr className="text-left text-gray-500">
                <th className="px-3 py-2">Directive</th>
                <th className="px-3 py-2">Blocked URI</th>
                <th className="px-3 py-2">Document</th>
                <th className="px-3 py-2">Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {violations.map((item, index) => (
                <tr key={`${item.blocked_uri}-${index}`}>
                  <td className="px-3 py-2 font-medium text-gray-900">{item.directive}</td>
                  <td className="px-3 py-2 text-gray-600">{item.blocked_uri}</td>
                  <td className="px-3 py-2 text-gray-600">{item.document_uri}</td>
                  <td className="px-3 py-2 text-gray-600">
                    {new Date(item.violated_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
