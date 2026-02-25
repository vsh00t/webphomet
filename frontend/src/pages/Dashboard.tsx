import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { getSessions, createSession, startAgent } from '../lib/api';
import { useState } from 'react';

const STATUS_COLOR: Record<string, string> = {
  created: '#3742fa',
  running: '#ffa502',
  paused: '#a0a0b0',
  completed: '#00ff88',
  failed: '#ff4757',
};

export default function Dashboard() {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ['sessions'], queryFn: getSessions });
  const [target, setTarget] = useState('');
  const [scope, setScope] = useState('');

  const createMut = useMutation({
    mutationFn: () => createSession({ target, scope_regex: scope || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); setTarget(''); setScope(''); },
  });

  const launchMut = useMutation({
    mutationFn: (id: string) => startAgent(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sessions'] }),
  });

  const sessions = data?.sessions ?? (Array.isArray(data) ? data : []);

  return (
    <div>
      <h2 className="text-xl font-bold mb-4" style={{ color: 'var(--accent)' }}>
        Sessions
      </h2>

      {/* Create session form */}
      <div className="flex gap-2 mb-6">
        <input
          placeholder="Target URL (e.g. http://target.com)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="flex-1 px-3 py-2 rounded text-sm"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
        />
        <input
          placeholder="Scope regex (optional)"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          className="w-64 px-3 py-2 rounded text-sm"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
        />
        <button
          onClick={() => createMut.mutate()}
          disabled={!target || createMut.isPending}
          className="px-4 py-2 rounded text-sm font-bold transition-opacity disabled:opacity-40"
          style={{ background: 'var(--accent)', color: 'var(--bg-primary)' }}
        >
          + New Session
        </button>
      </div>

      {isLoading && <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>}

      {/* Sessions table */}
      <div className="rounded overflow-hidden" style={{ border: '1px solid var(--border)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)' }}>
              <th className="text-left px-4 py-2">Target</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Created</th>
              <th className="text-left px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((s: any) => (
              <tr key={s.id} style={{ borderTop: '1px solid var(--border)' }} className="hover:bg-[var(--bg-card)] transition-colors">
                <td className="px-4 py-2">
                  <Link to={`/session/${s.id}`} style={{ color: 'var(--accent)' }} className="underline">
                    {s.target_base_url || s.target}
                  </Link>
                </td>
                <td className="px-4 py-2">
                  <span className="px-2 py-0.5 rounded text-xs font-bold"
                        style={{ background: STATUS_COLOR[s.status] + '22', color: STATUS_COLOR[s.status] }}>
                    {s.status}
                  </span>
                </td>
                <td className="px-4 py-2" style={{ color: 'var(--text-secondary)' }}>
                  {new Date(s.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-2 space-x-2">
                  {s.status === 'created' && (
                    <button
                      onClick={() => launchMut.mutate(s.id)}
                      disabled={launchMut.isPending}
                      className="px-2 py-1 rounded text-xs font-bold"
                      style={{ background: 'var(--accent)', color: 'var(--bg-primary)' }}
                    >
                      ▶ Launch Agent
                    </button>
                  )}
                  <Link to={`/findings/${s.id}`} className="px-2 py-1 rounded text-xs"
                        style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                    Findings
                  </Link>
                  <Link to={`/config/${s.id}`} className="px-2 py-1 rounded text-xs"
                        style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                    Config
                  </Link>
                </td>
              </tr>
            ))}
            {sessions.length === 0 && !isLoading && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center" style={{ color: 'var(--text-secondary)' }}>
                  No sessions yet. Create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
