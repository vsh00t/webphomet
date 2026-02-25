export interface Session {
  id: string;
  target_base_url: string;
  status: 'created' | 'running' | 'paused' | 'completed' | 'failed';
  scope: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  session_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  vuln_type: string;
  detail: string;
  evidence: string;
  url: string;
  remediation: string;
  caido_finding_id: string | null;
  caido_request_id: string | null;
  created_at: string;
}

export interface ToolRun {
  id: string;
  session_id: string;
  tool_name: string;
  command: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  stdout: string;
  stderr: string;
  exit_code: number | null;
  started_at: string;
  finished_at: string | null;
}

export interface Breakpoint {
  id: string;
  session_id: string;
  phase: string;
  tool_name: string;
  proposed_action: string;
  proposed_args: Record<string, unknown>;
  reason: string;
  timestamp: string;
  action: 'pending' | 'approved' | 'rejected' | 'modified' | 'timeout';
}

export interface BreakpointConfig {
  session_id: string;
  enabled: boolean;
  phase_breaks: string[];
  tool_breaks: string[];
  severity_break: boolean;
  auto_approve_timeout: number;
}

export interface WsEvent {
  type: string;
  session_id?: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface Correlation {
  id: string;
  finding_id: string;
  repo_name: string;
  hotspot_file: string;
  hotspot_line: number;
  hotspot_category: string;
  hotspot_snippet: string;
  confidence: number;
  correlation_type: string;
  notes: string;
  created_at: string;
  /* Joined from finding (only on /run response) */
  finding_title?: string;
  finding_vuln_type?: string;
}
