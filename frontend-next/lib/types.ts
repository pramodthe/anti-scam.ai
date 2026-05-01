export type GmailEmail = {
  id: string;
  thread_id: string;
  from_email: string;
  to_email: string;
  subject: string;
  send_time: string;
  body: string;
};

export type LinkScanResult = {
  original_url: string;
  normalized_url: string;
  final_url: string;
  reachable: boolean;
  ssl_state: "valid" | "invalid" | "unknown";
  yutori_verdict: "safe" | "suspicious" | "malicious" | "unknown";
  yutori_preview_url?: string | null;
  risk_flags: string[];
  scan_status: "ok" | "timeout" | "error";
};

export type RiskEvaluation = {
  id: string;
  decision: "quarantine" | "deliver";
  risk_score: number;
  risk_reasons: string[];
  description: string;
  model_version: string;
  status: string;
  links_found: number;
  links_scanned: number;
  link_results: LinkScanResult[];
  link_scan_failed_closed: boolean;
};

export type QuarantineRecord = {
  id: string;
  description: string;
  risk_score: number;
  risk_reasons: string[];
  model_version: string;
  status: string;
  label: 0 | 1 | null;
  email: GmailEmail;
  link_results: LinkScanResult[];
  link_scan_failed_closed: boolean;
};

export type EmailReviewItem = {
  id: string;
  sender_name: string;
  sender_email: string;
  subject: string;
  received_at: string;
  body_preview: string;
  body_full: string;
  description: string;
  risk_score: number;
  risk_reasons: string[];
  model_version: string;
  status: "pending_human_review" | "confirmed_scam" | "confirmed_legit" | "released";
  label: 0 | 1 | null;
  link_results: LinkScanResult[];
  link_scan_failed_closed: boolean;
};

export type LinkLabResponse = {
  email_risk_summary: {
    decision: "quarantine" | "deliver";
    risk_score: number;
    links_found: number;
    links_scanned: number;
    link_scan_failed_closed: boolean;
    risk_reasons: string[];
  };
  link_results: LinkScanResult[];
};

export type ManualCheckResponse = LinkLabResponse & {
  research: {
    query: string;
    summary: string;
    provider: string;
    executed: boolean;
    preview_url?: string | null;
    task_id?: string | null;
    details?: Record<string, unknown> | null;
  };
};

export type DashboardSummary = {
  screened_count: number;
  quarantined_count: number;
  confirmed_scam_count: number;
  false_positive_count: number;
  last_scan_at?: string | null;
  screening_enabled: boolean;
  scanner_status: "idle" | "running" | "disabled";
  recent_high_risk: Array<{
    id: string;
    subject: string;
    sender_name: string;
    sender_email: string;
    risk_score: number;
    status: "pending_human_review" | "confirmed_scam" | "confirmed_legit" | "released";
    updated_at: string;
  }>;
};
