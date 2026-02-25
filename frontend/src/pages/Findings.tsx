import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getFindings } from '../lib/api';
import { useState } from 'react';

const SEV_COLOR: Record<string, string> = {
  critical: '#ff4757',
  high: '#ff6348',
  medium: '#ffa502',
  low: '#3742fa',
  info: '#a0a0b0',
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export default function Findings() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<any | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['findings', sessionId],
    queryFn: () => getFindings(sessionId!),
    enabled: !!sessionId,
  });

  const findings = (data?.findings ?? (Array.isArray(data) ? data : []))
    .filter((f: any) => filter === 'all' || f.severity === filter)
    .filter((f: any) =>
      !search || f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.vuln_type?.toLowerCase().includes(search.toLowerCase())
    )
    .sort((a: any, b: any) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <Link to={`/session/${sessionId}`} className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            ← Back to session
          </Link>
          <h2 className="text-xl font-bold mt-1" style={{ color: 'var(--accent)' }}>
            Findings ({findings.length})
          </h2>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-2 items-center">
        <input
          placeholder="Search findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-64 px-3 py-1.5 rounded text-sm"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
        />
        {['all', ...SEV_ORDER].map((s) => (
          <button
            key={s}
            onClick={() => setFilter(s)}
            className={`px-3 py-1 rounded text-xs font-bold ${filter === s ? 'ring-1' : ''}`}
            style={{
              background: s === 'all' ? 'var(--bg-card)' : SEV_COLOR[s] + '22',
              color: s === 'all' ? 'var(--text-secondary)' : SEV_COLOR[s],
              ['--tw-ring-color' as string]: 'var(--accent)',
            }}
          >
            {s}
          </button>
        ))}
      </div>

      {isLoading && <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>}

      {/* Table */}
      <div className="rounded overflow-hidden" style={{ border: '1px solid var(--border)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)' }}>
              <th className="text-left px-3 py-2 w-20">Severity</th>
              <th className="text-left px-3 py-2">Title</th>
              <th className="text-left px-3 py-2 w-32">Type</th>
              <th className="text-left px-3 py-2 w-48">URL</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f: any) => (
              <tr key={f.id}
                  className="cursor-pointer hover:bg-[var(--bg-card)] transition-colors"
                  style={{ borderTop: '1px solid var(--border)' }}
                  onClick={() => setSelected(selected?.id === f.id ? null : f)}>
                <td className="px-3 py-2">
                  <span className="px-2 py-0.5 rounded font-bold"
                        style={{ background: SEV_COLOR[f.severity] + '22', color: SEV_COLOR[f.severity] }}>
                    {f.severity}
                  </span>
                </td>
                <td className="px-3 py-2 font-bold">{f.title}</td>
                <td className="px-3 py-2" style={{ color: 'var(--text-secondary)' }}>{f.vuln_type}</td>
                <td className="px-3 py-2 truncate max-w-48" style={{ color: 'var(--text-secondary)' }}>
                  {f.url}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="rounded p-4 space-y-3" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold">{selected.title}</h3>
            <button onClick={() => setSelected(null)} className="text-xs" style={{color: 'var(--text-secondary)'}}>✕ Close</button>
          </div>
          <div className="grid grid-cols-3 gap-3 text-xs">
            <div>
              <strong>Severity:</strong>{' '}
              <span style={{ color: SEV_COLOR[selected.severity] }}>{selected.severity}</span>
            </div>
            <div><strong>Type:</strong> {selected.vuln_type}</div>
            <div><strong>URL:</strong> {selected.url || 'N/A'}</div>
          </div>
          {selected.detail && (
            <div>
              <strong className="text-xs">Detail:</strong>
              <pre className="mt-1 p-2 rounded text-xs overflow-auto max-h-40"
                   style={{ background: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
                {selected.detail}
              </pre>
            </div>
          )}
          {selected.evidence && (
            <div>
              <strong className="text-xs">Evidence / PoC:</strong>
              <pre className="mt-1 p-2 rounded text-xs overflow-auto max-h-40"
                   style={{ background: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
                {selected.evidence}
              </pre>
            </div>
          )}
          {selected.remediation && (
            <div>
              <strong className="text-xs">Remediation:</strong>
              <p className="mt-1 text-xs" style={{ color: 'var(--text-secondary)' }}>
                {selected.remediation}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
