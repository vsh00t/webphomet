import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getBreakpointConfig, configureBreakpoints } from '../lib/api';
import { useState, useEffect } from 'react';

const ALL_PHASES = [
  'pre_recon', 'post_recon', 'pre_scanning', 'post_scanning',
  'pre_exploit', 'post_exploit', 'pre_report', 'post_owasp',
];

export default function Config() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const qc = useQueryClient();

  const { data: cfg, isLoading } = useQuery({
    queryKey: ['bpConfig', sessionId],
    queryFn: () => getBreakpointConfig(sessionId!),
    enabled: !!sessionId,
  });

  const [enabled, setEnabled] = useState(true);
  const [phases, setPhases] = useState<string[]>([]);
  const [sevBreak, setSevBreak] = useState(true);
  const [timeout, setTimeout_] = useState(0);
  const [tools, setTools] = useState('');

  useEffect(() => {
    if (cfg) {
      setEnabled(cfg.enabled);
      setPhases(cfg.phase_breaks || []);
      setSevBreak(cfg.severity_break);
      setTimeout_(cfg.auto_approve_timeout || 0);
      setTools((cfg.tool_breaks || []).join(', '));
    }
  }, [cfg]);

  const saveMut = useMutation({
    mutationFn: () => configureBreakpoints({
      session_id: sessionId,
      enabled,
      phase_breaks: phases,
      tool_breaks: tools.split(',').map(t => t.trim()).filter(Boolean),
      severity_break: sevBreak,
      auto_approve_timeout: timeout,
    }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['bpConfig', sessionId] }),
  });

  const togglePhase = (p: string) => {
    setPhases(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]);
  };

  if (isLoading) return <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>;

  return (
    <div className="space-y-6 max-w-xl">
      <div>
        <Link to={`/session/${sessionId}`} className="text-xs" style={{ color: 'var(--text-secondary)' }}>
          ← Back to session
        </Link>
        <h2 className="text-xl font-bold mt-1" style={{ color: 'var(--accent)' }}>
          Session Configuration
        </h2>
      </div>

      {/* Breakpoints */}
      <div className="rounded p-4 space-y-4" style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
        <h3 className="text-sm font-bold" style={{ color: 'var(--accent)' }}>Breakpoint Settings</h3>

        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} />
          Enable breakpoints
        </label>

        <div>
          <p className="text-xs font-bold mb-2" style={{ color: 'var(--text-secondary)' }}>Phase breakpoints:</p>
          <div className="flex flex-wrap gap-2">
            {ALL_PHASES.map((p) => (
              <button
                key={p}
                onClick={() => togglePhase(p)}
                className={`px-3 py-1 rounded text-xs font-bold transition-colors ${
                  phases.includes(p) ? 'ring-1' : ''
                }`}
                style={{
                  background: phases.includes(p) ? 'var(--accent)' + '33' : 'var(--bg-secondary)',
                  color: phases.includes(p) ? 'var(--accent)' : 'var(--text-secondary)',
                }}
              >
                {p}
              </button>
            ))}
          </div>
        </div>

        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={sevBreak} onChange={e => setSevBreak(e.target.checked)} />
          Pause on critical findings
        </label>

        <div>
          <label className="text-xs font-bold block mb-1" style={{ color: 'var(--text-secondary)' }}>
            Tool-specific breakpoints (comma-separated):
          </label>
          <input
            value={tools}
            onChange={e => setTools(e.target.value)}
            placeholder="run_injection_tests, run_ssrf_tests"
            className="w-full px-3 py-1.5 rounded text-sm"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          />
        </div>

        <div>
          <label className="text-xs font-bold block mb-1" style={{ color: 'var(--text-secondary)' }}>
            Auto-approve timeout (seconds, 0 = manual):
          </label>
          <input
            type="number"
            value={timeout}
            onChange={e => setTimeout_(Number(e.target.value))}
            className="w-32 px-3 py-1.5 rounded text-sm"
            style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-primary)' }}
          />
        </div>

        <button
          onClick={() => saveMut.mutate()}
          disabled={saveMut.isPending}
          className="px-4 py-2 rounded text-sm font-bold"
          style={{ background: 'var(--accent)', color: 'var(--bg-primary)' }}
        >
          {saveMut.isPending ? 'Saving...' : 'Save Configuration'}
        </button>
        {saveMut.isSuccess && (
          <span className="text-xs ml-3" style={{ color: 'var(--accent)' }}>✓ Saved</span>
        )}
      </div>
    </div>
  );
}
