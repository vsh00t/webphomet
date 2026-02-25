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
export const createSession = (body: { target: string; scope_regex?: string }) =>
  request<any>('/sessions/', { method: 'POST', body: JSON.stringify(body) });

/* Findings */
export const getFindings = (sessionId: string) =>
  request<{ findings: any[] }>(`/findings/?session_id=${sessionId}`);

/* Tool Runs */
export const getToolRuns = (sessionId: string) =>
  request<{ tool_runs: any[] }>(`/sessions/${sessionId}/tool-runs`);

/* Agent */
export const startAgent = (sessionId: string) =>
  request<any>('/agent/run', { method: 'POST', body: JSON.stringify({ session_id: sessionId }) });

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
