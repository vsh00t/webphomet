import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { getSessions, createSession, startAgent, stopAgent, deleteSession, deleteAllSessions } from '../lib/api';
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

  const [error, setError] = useState('');

  const createMut = useMutation({
    mutationFn: () => createSession({ target, scope_regex: scope || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); setTarget(''); setScope(''); setError(''); },
    onError: (e: any) => setError(`Create failed: ${e.message}`),
  });

  const launchMut = useMutation({
    mutationFn: (id: string) => startAgent(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); setError(''); },
    onError: (e: any) => setError(`Launch failed: ${e.message}`),
  });

  const stopMut = useMutation({
    mutationFn: (id: string) => stopAgent(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); setError(''); },
    onError: (e: any) => setError(`Stop failed: ${e.message}`),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteSession(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); },
    onError: (e: any) => setError(`Delete failed: ${e.message}`),
  });

  const deleteAllMut = useMutation({
    mutationFn: (ids: string[]) => deleteAllSessions(ids),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['sessions'] }); },
    onError: (e: any) => setError(`Bulk delete failed: ${e.message}`),
  });

  const sessions = data?.sessions ?? (Array.isArray(data) ? data : []);
  const stoppedSessions = sessions.filter((s: any) => s.status !== 'running');

  return (
    <div>
      <h2 className="text-xl font-bold mb-4" style={{ color: 'var(--accent)' }}>
        Sessions
      </h2>

      {/* Bulk actions */}
      {sessions.length > 1 && (
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => {
              if (confirm(`Delete ${stoppedSessions.length} non-running session(s)?`)) {
                deleteAllMut.mutate(stoppedSessions.map((s: any) => s.id));
              }
            }}
            disabled={deleteAllMut.isPending || stoppedSessions.length === 0}
            className="px-3 py-1.5 rounded text-xs font-bold cursor-pointer hover:opacity-80 disabled:opacity-40 transition-opacity"
            style={{ background: '#ff4757', color: '#fff' }}
          >
            {deleteAllMut.isPending ? '⏳ Deleting...' : `🗑 Delete All Non-Running (${stoppedSessions.length})`}
          </button>
        </div>
      )}

      {/* Create session form */}
      <div className="flex gap-2 mb-6">
        <input
          placeholder="Target URL (e.g. https://example.com)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="flex-1 px-3 py-2 rounded text-sm"
          style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          onKeyDown={(e) => e.key === 'Enter' && target && createMut.mutate()}
        />
        <input
          placeholder="Scope hosts (optional, comma-sep)"
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

      {error && (
        <div className="mb-4 px-4 py-2 rounded text-sm" style={{ background: '#ff475722', color: '#ff4757', border: '1px solid #ff4757' }}>
          {error}
          <button onClick={() => setError('')} className="ml-2 font-bold">✕</button>
        </div>
      )}

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
                  {(s.status === 'created' || s.status === 'paused') && (
                    <button
                      onClick={() => launchMut.mutate(s.id)}
                      disabled={launchMut.isPending}
                      className="px-2 py-1 rounded text-xs font-bold cursor-pointer hover:opacity-80"
                      style={{ background: 'var(--accent)', color: 'var(--bg-primary)' }}
                    >
                      {launchMut.isPending ? '⏳ Starting...' : '▶ Launch Agent'}
                    </button>
                  )}
                  {(s.status === 'completed' || s.status === 'failed') && (
                    <button
                      onClick={() => launchMut.mutate(s.id)}
                      disabled={launchMut.isPending}
                      className="px-2 py-1 rounded text-xs font-bold cursor-pointer hover:opacity-80"
                      style={{ background: '#ffa502', color: 'var(--bg-primary)' }}
                    >
                      {launchMut.isPending ? '⏳ Starting...' : '🔄 Re-launch'}
                    </button>
                  )}
                  {s.status === 'running' && (
                    <button
                      onClick={() => { if (confirm('Stop this running agent?')) stopMut.mutate(s.id); }}
                      disabled={stopMut.isPending}
                      className="px-2 py-1 rounded text-xs font-bold cursor-pointer hover:opacity-80"
                      style={{ background: '#ff4757', color: '#fff' }}
                    >
                      {stopMut.isPending ? '⏳ Stopping...' : '⏹ Stop Agent'}
                    </button>
                  )}
                  <Link to={`/findings/${s.id}`} className="px-2 py-1 rounded text-xs"
                        style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                    Findings
                  </Link>
                  <Link to={`/correlations/${s.id}`} className="px-2 py-1 rounded text-xs"
                        style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                    Correlations
                  </Link>
                  <Link to={`/config/${s.id}`} className="px-2 py-1 rounded text-xs"
                        style={{ background: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
                    Config
                  </Link>
                  {s.status !== 'running' && (
                    <button
                      onClick={() => { if (confirm('Delete this session?')) deleteMut.mutate(s.id); }}
                      disabled={deleteMut.isPending}
                      className="px-2 py-1 rounded text-xs cursor-pointer hover:opacity-80"
                      style={{ background: '#ff475722', color: '#ff4757' }}
                      title="Delete session"
                    >
                      🗑
                    </button>
                  )}
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
