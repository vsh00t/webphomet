import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getSession, getFindings, getToolRuns, getPendingBreakpoints, resolveBreakpoint } from '../lib/api';
import { useWebSocket } from '../hooks/useWebSocket';
import { useMutation, useQueryClient } from '@tanstack/react-query';

const SEV_COLOR: Record<string, string> = {
  critical: '#ff4757',
  high: '#ff6348',
  medium: '#ffa502',
  low: '#3742fa',
  info: '#a0a0b0',
};

const STATUS_ICON: Record<string, string> = {
  pending: '⏳',
  running: '⚡',
  success: '✅',
  failed: '❌',
};

export default function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const qc = useQueryClient();
  const { events, connected } = useWebSocket(id);

  const { data: session } = useQuery({
    queryKey: ['session', id],
    queryFn: () => getSession(id!),
    enabled: !!id,
  });

  const { data: findingsData } = useQuery({
    queryKey: ['findings', id],
    queryFn: () => getFindings(id!),
    enabled: !!id,
  });

  const { data: toolsData } = useQuery({
    queryKey: ['toolRuns', id],
    queryFn: () => getToolRuns(id!),
    enabled: !!id,
  });

  const { data: bpData } = useQuery({
    queryKey: ['breakpoints', id],
    queryFn: () => getPendingBreakpoints(id),
    enabled: !!id,
    refetchInterval: 2000,
  });

  const resolveMut = useMutation({
    mutationFn: (args: { breakpoint_id: string; action: string; message?: string }) =>
      resolveBreakpoint(args),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['breakpoints', id] }),
  });

  const findings = findingsData?.findings ?? (Array.isArray(findingsData) ? findingsData : []);
  const toolRuns = toolsData?.tool_runs ?? (Array.isArray(toolsData) ? toolsData : []);
  const pending = bpData?.pending ?? [];

  const sevCounts = findings.reduce((acc: Record<string, number>, f: any) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Link to="/" className="text-xs" style={{ color: 'var(--text-secondary)' }}>← Back</Link>
          <h2 className="text-xl font-bold mt-1" style={{ color: 'var(--accent)' }}>
            {session?.target_base_url || session?.target || id}
          </h2>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
            Status: <span className="font-bold">{session?.status}</span>
            {' · '}ID: {id?.slice(0, 8)}...
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            {connected ? 'Live' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Severity summary */}
      <div className="flex gap-3">
        {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
          <div key={s} className="px-4 py-3 rounded text-center min-w-[80px]"
               style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
            <div className="text-2xl font-bold" style={{ color: SEV_COLOR[s] }}>
              {sevCounts[s] || 0}
            </div>
            <div className="text-xs uppercase mt-1" style={{ color: 'var(--text-secondary)' }}>
              {s}
            </div>
          </div>
        ))}
        <div className="px-4 py-3 rounded text-center min-w-[80px]"
             style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
          <div className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>
            {toolRuns.length}
          </div>
          <div className="text-xs uppercase mt-1" style={{ color: 'var(--text-secondary)' }}>
            tool runs
          </div>
        </div>
      </div>

      {/* Pending breakpoints */}
      {pending.length > 0 && (
        <div className="rounded p-4 space-y-3" style={{ background: '#ffa50215', border: '1px solid var(--warning)' }}>
          <h3 className="text-sm font-bold" style={{ color: 'var(--warning)' }}>
            ⚠ Pending Breakpoints ({pending.length})
          </h3>
          {pending.map((bp: any) => (
            <div key={bp.id} className="flex items-center justify-between p-3 rounded"
                 style={{ background: 'var(--bg-card)' }}>
              <div>
                <div className="text-sm font-bold">{bp.proposed_action}</div>
                <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
                  {bp.reason}
                </div>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => resolveMut.mutate({ breakpoint_id: bp.id, action: 'approved' })}
                  className="px-3 py-1 rounded text-xs font-bold"
                  style={{ background: 'var(--accent)', color: 'var(--bg-primary)' }}
                >
                  ✓ Approve
                </button>
                <button
                  onClick={() => resolveMut.mutate({ breakpoint_id: bp.id, action: 'rejected', message: 'Operator rejected' })}
                  className="px-3 py-1 rounded text-xs font-bold"
                  style={{ background: 'var(--danger)', color: '#fff' }}
                >
                  ✕ Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Two columns: Tool Runs + Live Events */}
      <div className="grid grid-cols-2 gap-4">
        {/* Tool Runs */}
        <div className="rounded" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
          <h3 className="px-4 py-2 text-sm font-bold"
              style={{ borderBottom: '1px solid var(--border)', color: 'var(--accent)' }}>
            Tool Runs
          </h3>
          <div className="max-h-80 overflow-auto">
            {toolRuns.slice(0, 30).map((tr: any) => (
              <div key={tr.id} className="px-4 py-2 text-xs flex items-center gap-2"
                   style={{ borderBottom: '1px solid var(--border)' }}>
                <span>{STATUS_ICON[tr.status] || '?'}</span>
                <span className="font-bold">{tr.tool_name}</span>
                <span style={{ color: 'var(--text-secondary)' }} className="truncate flex-1">
                  {tr.command}
                </span>
              </div>
            ))}
            {toolRuns.length === 0 && (
              <p className="px-4 py-4 text-xs" style={{ color: 'var(--text-secondary)' }}>No tool runs yet.</p>
            )}
          </div>
        </div>

        {/* Live Events */}
        <div className="rounded" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
          <h3 className="px-4 py-2 text-sm font-bold"
              style={{ borderBottom: '1px solid var(--border)', color: 'var(--accent)' }}>
            Live Events
          </h3>
          <div className="max-h-80 overflow-auto">
            {events.slice(0, 50).map((evt, i) => (
              <div key={i} className="px-4 py-2 text-xs"
                   style={{ borderBottom: '1px solid var(--border)' }}>
                <span className="font-bold mr-2" style={{ color: 'var(--accent)' }}>{evt.type}</span>
                <span style={{ color: 'var(--text-secondary)' }}>
                  {JSON.stringify(evt.data).slice(0, 120)}
                </span>
              </div>
            ))}
            {events.length === 0 && (
              <p className="px-4 py-4 text-xs" style={{ color: 'var(--text-secondary)' }}>
                No events yet. {!connected && 'WebSocket disconnected.'}
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Recent findings */}
      <div className="rounded" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
        <h3 className="px-4 py-2 text-sm font-bold"
            style={{ borderBottom: '1px solid var(--border)', color: 'var(--accent)' }}>
          Recent Findings
        </h3>
        <div className="max-h-64 overflow-auto">
          {findings.slice(0, 20).map((f: any) => (
            <div key={f.id} className="px-4 py-2 text-xs flex items-center gap-3"
                 style={{ borderBottom: '1px solid var(--border)' }}>
              <span className="px-2 py-0.5 rounded font-bold"
                    style={{ background: SEV_COLOR[f.severity] + '22', color: SEV_COLOR[f.severity], minWidth: 60, textAlign: 'center' }}>
                {f.severity}
              </span>
              <span className="font-bold flex-1">{f.title}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{f.vuln_type}</span>
            </div>
          ))}
          {findings.length === 0 && (
            <p className="px-4 py-4 text-xs" style={{ color: 'var(--text-secondary)' }}>No findings yet.</p>
          )}
        </div>
        {findings.length > 0 && (
          <Link to={`/findings/${id}`}
                className="block px-4 py-2 text-xs text-center"
                style={{ borderTop: '1px solid var(--border)', color: 'var(--accent)' }}>
            View all {findings.length} findings →
          </Link>
        )}
      </div>
    </div>
  );
}
