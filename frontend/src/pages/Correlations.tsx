import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getCorrelations, getFindings } from '../lib/api';
import { useState } from 'react';

const CAT_COLOR: Record<string, string> = {
  sqli: '#ff4757',
  xss: '#ff6348',
  command_injection: '#e84118',
  ssrf: '#ffa502',
  path_traversal: '#e1b12c',
  crypto: '#3742fa',
  deserialization: '#8854d0',
};

function confidenceBadge(c: number) {
  const bg = c >= 0.7 ? '#ff475722' : c >= 0.5 ? '#ffa50222' : '#3742fa22';
  const fg = c >= 0.7 ? '#ff4757' : c >= 0.5 ? '#ffa502' : '#3742fa';
  return { background: bg, color: fg };
}

export default function Correlations() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [minConf, setMinConf] = useState(0.3);

  const { data: correlations, isLoading } = useQuery({
    queryKey: ['correlations', sessionId, minConf],
    queryFn: () => getCorrelations(sessionId!, minConf),
    enabled: !!sessionId,
  });

  const { data: findingsData } = useQuery({
    queryKey: ['findings', sessionId],
    queryFn: () => getFindings(sessionId!),
    enabled: !!sessionId,
  });

  const findings = findingsData?.findings ?? (Array.isArray(findingsData) ? findingsData : []);
  const corrs = correlations ?? [];

  // Build a lookup for finding titles
  const findingMap = new Map<string, any>();
  findings.forEach((f: any) => findingMap.set(f.id, f));

  // Group by category
  const byCategory = corrs.reduce((acc: Record<string, any[]>, c: any) => {
    const cat = c.hotspot_category || 'unknown';
    (acc[cat] = acc[cat] || []).push(c);
    return acc;
  }, {});

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Link to={`/session/${sessionId}`} className="text-xs" style={{ color: 'var(--text-secondary)' }}>
            ← Back to session
          </Link>
          <h2 className="text-xl font-bold mt-1" style={{ color: 'var(--accent)' }}>
            Code Correlations ({corrs.length})
          </h2>
          <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
            Static hotspots linked to dynamic findings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs" style={{ color: 'var(--text-secondary)' }}>Min confidence:</label>
          <input
            type="range"
            min={0}
            max={1}
            step={0.05}
            value={minConf}
            onChange={(e) => setMinConf(parseFloat(e.target.value))}
            className="w-32"
          />
          <span className="text-xs font-bold" style={{ color: 'var(--accent)' }}>{minConf.toFixed(2)}</span>
        </div>
      </div>

      {isLoading && <p style={{ color: 'var(--text-secondary)' }}>Loading...</p>}

      {/* Stats */}
      <div className="flex gap-3 flex-wrap">
        {Object.entries(byCategory).map(([cat, items]) => (
          <div key={cat} className="px-4 py-3 rounded text-center min-w-[100px]"
               style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
            <div className="text-xl font-bold" style={{ color: CAT_COLOR[cat] || 'var(--accent)' }}>
              {items.length}
            </div>
            <div className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>{cat}</div>
          </div>
        ))}
      </div>

      {/* Correlations table */}
      <div className="rounded overflow-hidden" style={{ border: '1px solid var(--border)' }}>
        <table className="w-full text-xs">
          <thead>
            <tr style={{ background: 'var(--bg-secondary)' }}>
              <th className="text-left px-3 py-2 w-16">Conf.</th>
              <th className="text-left px-3 py-2">Finding</th>
              <th className="text-left px-3 py-2 w-24">Category</th>
              <th className="text-left px-3 py-2">Hotspot File</th>
              <th className="text-left px-3 py-2 w-14">Line</th>
              <th className="text-left px-3 py-2">Type</th>
            </tr>
          </thead>
          <tbody>
            {corrs.map((c: any, i: number) => {
              const finding = findingMap.get(c.finding_id) || {};
              return (
                <tr key={c.id || i}
                    className="hover:bg-[var(--bg-card)] transition-colors"
                    style={{ borderTop: '1px solid var(--border)' }}>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 rounded font-bold text-xs"
                          style={confidenceBadge(c.confidence)}>
                      {(c.confidence * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="px-3 py-2 font-bold">
                    {c.finding_title || finding.title || c.finding_id?.slice(0, 8)}
                  </td>
                  <td className="px-3 py-2">
                    <span className="px-2 py-0.5 rounded"
                          style={{
                            background: (CAT_COLOR[c.hotspot_category] || '#888') + '22',
                            color: CAT_COLOR[c.hotspot_category] || '#888',
                          }}>
                      {c.hotspot_category}
                    </span>
                  </td>
                  <td className="px-3 py-2 truncate max-w-[200px]" style={{ color: 'var(--text-secondary)' }}>
                    {c.hotspot_file}
                  </td>
                  <td className="px-3 py-2" style={{ color: 'var(--text-secondary)' }}>
                    {c.hotspot_line}
                  </td>
                  <td className="px-3 py-2" style={{ color: 'var(--text-secondary)' }}>
                    {c.correlation_type}
                  </td>
                </tr>
              );
            })}
            {corrs.length === 0 && !isLoading && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--text-secondary)' }}>
                  No correlations found. Run hotspot analysis and the correlation engine first.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Snippet preview for first 10 */}
      {corrs.slice(0, 10).filter((c: any) => c.hotspot_snippet).map((c: any, i: number) => (
        <div key={`snippet-${i}`} className="rounded p-3"
             style={{ background: 'var(--bg-card)', border: '1px solid var(--border)' }}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold" style={{ color: CAT_COLOR[c.hotspot_category] || 'var(--accent)' }}>
              {c.hotspot_file}:{c.hotspot_line}
            </span>
            <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>
              → {c.finding_title || c.finding_id?.slice(0, 8)}
              {' '}<span className="font-bold" style={confidenceBadge(c.confidence)}>
                {(c.confidence * 100).toFixed(0)}%
              </span>
            </span>
          </div>
          <pre className="text-xs overflow-auto max-h-24 p-2 rounded"
               style={{ background: 'var(--bg-primary)', color: 'var(--text-secondary)' }}>
            {c.hotspot_snippet}
          </pre>
          {c.notes && (
            <p className="text-xs mt-1" style={{ color: 'var(--text-secondary)' }}>
              {c.notes}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
