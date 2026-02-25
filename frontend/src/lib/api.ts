const BASE = '/api/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

/* Sessions */
export const getSessions = () => request<{ sessions: any[] }>('/sessions/');
export const getSession = (id: string) => request<any>(`/sessions/${id}`);
export const deleteSession = (id: string) =>
  fetch(`${BASE}/sessions/${id}`, { method: 'DELETE' }).then((r) => {
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  });
export const deleteAllSessions = async (ids: string[]) => {
  await Promise.all(ids.map(deleteSession));
};
export const createSession = (body: { target: string; scope_regex?: string }) => {
  // Ensure target has a protocol so URL parsing works
  let url = body.target.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  let hostname: string | undefined;
  try { hostname = new URL(url).hostname; } catch { /* ignore */ }

  return request<any>('/sessions/', {
    method: 'POST',
    body: JSON.stringify({
      target_base_url: url,
      app_type: 'web',
      scope: hostname ? { allowed_hosts: [hostname] } : undefined,
    }),
  });
};

/* Findings */
export const getFindings = (sessionId: string) =>
  request<{ findings: any[] }>(`/findings/session/${sessionId}`);
export const getFindingsSummary = (sessionId: string) =>
  request<any>(`/findings/session/${sessionId}/summary`);

/* Tool Runs */
export const getToolRuns = (sessionId: string) =>
  request<any[]>(`/tools/session/${sessionId}`);

/* Agent */
export const startAgent = (sessionId: string) =>
  request<any>('/agent/start', { method: 'POST', body: JSON.stringify({ session_id: sessionId }) });
export const stopAgent = (sessionId: string) =>
  request<any>('/agent/stop', { method: 'POST', body: JSON.stringify({ session_id: sessionId }) });

/* Breakpoints */
export const getBreakpointConfig = (sessionId: string) =>
  request<any>(`/breakpoints/config/${sessionId}`);
export const configureBreakpoints = (body: any) =>
  request<any>('/breakpoints/configure', { method: 'POST', body: JSON.stringify(body) });
export const getPendingBreakpoints = (sessionId?: string) =>
  request<{ pending: any[]; count: number }>(
    `/breakpoints/pending${sessionId ? `?session_id=${sessionId}` : ''}`
  );
export const resolveBreakpoint = (body: { breakpoint_id: string; action: string; message?: string; modified_args?: any }) =>
  request<any>('/breakpoints/resolve', { method: 'POST', body: JSON.stringify(body) });

/* Report */
export const buildReport = (sessionId: string) =>
  request<any>('/tools/build-report', {
    method: 'POST',
    body: JSON.stringify({ session_id: sessionId }),
  });

/* Git/Code (now under /git-code/ prefix) */
export const cloneRepo = (body: { session_id: string; url: string; name?: string }) =>
  request<any>('/git-code/clone-repo', { method: 'POST', body: JSON.stringify(body) });
export const listRepos = (sessionId: string) =>
  request<any>(`/git-code/list-repos?session_id=${sessionId}`);
export const findHotspots = (body: { session_id: string; repo_name: string; categories?: string[] }) =>
  request<any>('/git-code/find-hotspots', { method: 'POST', body: JSON.stringify(body) });

/* Correlations */
export const getCorrelations = (sessionId: string, minConfidence = 0) =>
  request<any[]>(`/correlations/session/${sessionId}?min_confidence=${minConfidence}`);
export const getCorrelationsForFinding = (findingId: string) =>
  request<any[]>(`/correlations/finding/${findingId}`);
export const runCorrelation = (body: {
  session_id: string;
  repo_name: string;
  hotspots: any[];
  min_confidence?: number;
}) =>
  request<any[]>('/correlations/run', { method: 'POST', body: JSON.stringify(body) });
