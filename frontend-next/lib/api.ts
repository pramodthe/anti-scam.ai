import type {
  DashboardSummary,
  EmailReviewItem,
  GmailEmail,
  LinkLabResponse,
  ManualCheckResponse,
  QuarantineRecord,
  RiskEvaluation,
} from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_EMAIL_API_BASE ?? "http://127.0.0.1:8000";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with status ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export async function getHealth(): Promise<{ status: string }> {
  return request("/health");
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  return request("/dashboard/summary");
}

export async function listEmails(params: {
  email_address: string;
  minutes_since: number;
  include_read: boolean;
  max_results: number;
}): Promise<{ count: number; emails: GmailEmail[] }> {
  const search = new URLSearchParams({
    email_address: params.email_address,
    minutes_since: String(params.minutes_since),
    include_read: String(params.include_read),
    max_results: String(params.max_results),
  });

  return request(`/gmail/emails?${search.toString()}`);
}

export async function evaluateEmail(email: GmailEmail): Promise<RiskEvaluation> {
  return request("/risk/emails/evaluate", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}

export async function sendEmail(payload: { to: string; subject: string; body: string }) {
  return request<{ message_id: string }>("/gmail/send", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteEmail(messageId: string) {
  return request(`/gmail/emails/${messageId}`, {
    method: "DELETE",
  });
}

export async function listQuarantine(): Promise<{ count: number; emails: QuarantineRecord[] }> {
  return request("/risk/quarantine");
}

export async function listQuarantineEmails(): Promise<{ count: number; emails: EmailReviewItem[] }> {
  return request("/emails/quarantine");
}

export async function listScamEmails(): Promise<{ count: number; emails: EmailReviewItem[] }> {
  return request("/emails/scam");
}

export async function labelQuarantine(messageId: string, label: 0 | 1) {
  return request(`/risk/quarantine/${messageId}/label`, {
    method: "POST",
    body: JSON.stringify({ label }),
  });
}

export async function releaseQuarantine(messageId: string) {
  return request(`/risk/quarantine/${messageId}/release`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function markScam(messageId: string) {
  return request(`/emails/${messageId}/mark-scam`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function markNonScam(messageId: string) {
  return request(`/emails/${messageId}/mark-non-scam`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function removeFromScam(messageId: string) {
  return request(`/emails/${messageId}/remove-from-scam`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function runScreening() {
  return request<{ processed: number; quarantined: number; delivered: number; skipped: number; status: string }>(
    "/screening/run",
    {
      method: "POST",
      body: JSON.stringify({}),
    },
  );
}

export async function evaluateLinks(payload: {
  sender_email: string;
  subject: string;
  body: string;
  urls: string[];
}): Promise<LinkLabResponse> {
  return request("/risk/links/evaluate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function manualCheck(payload: {
  sender_email: string;
  company_name: string;
  subject: string;
  body: string;
  urls: string[];
}): Promise<ManualCheckResponse> {
  return request("/manual-check", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
