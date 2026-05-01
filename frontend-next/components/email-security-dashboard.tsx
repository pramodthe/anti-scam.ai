"use client";

import type { FormEvent, ReactNode } from "react";
import { useEffect, useMemo, useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  AlertTriangle,
  ArrowUpRight,
  BadgeCheck,
  FileSearch,
  Inbox,
  MailWarning,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import {
  getDashboardSummary,
  getHealth,
  listQuarantineEmails,
  listScamEmails,
  manualCheck,
  markNonScam,
  markScam,
  removeFromScam,
  runScreening,
} from "@/lib/api";
import type { DashboardSummary, EmailReviewItem, ManualCheckResponse } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { toast } from "@/components/ui/sonner";
import { Textarea } from "@/components/ui/textarea";

type WorkspaceSection = "dashboard" | "quarantine" | "scam" | "manual";

type ManualFormState = {
  senderEmail: string;
  companyName: string;
  subject: string;
  body: string;
  urls: string;
};

type MetricItem = {
  label: string;
  value: string;
  hint: string;
  tone?: "safe" | "watch" | "threat";
};

function toneForScore(score: number): "safe" | "watch" | "threat" {
  if (score <= 0.3) return "safe";
  if (score <= 0.6) return "watch";
  return "threat";
}

function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`;
}

function formatTimestamp(value?: string | null) {
  if (!value) return "Not scanned yet";
  return value;
}

function sectionMeta(section: WorkspaceSection) {
  switch (section) {
    case "dashboard":
      return {
        title: "Dashboard",
        description: "Scanner state, queue pressure, and recent high-risk decisions.",
      };
    case "quarantine":
      return {
        title: "Quarantine",
        description: "Review suspicious mail before it reaches the user inbox.",
      };
    case "scam":
      return {
        title: "Scam",
        description: "Confirmed scam records and sender evidence retained by the platform.",
      };
    case "manual":
      return {
        title: "Manual Check",
        description: "Research an email, company, or sender without opening a live message.",
      };
  }
}

function AppNavButton({
  active,
  icon: Icon,
  label,
  count,
  onClick,
}: {
  active: boolean;
  icon: LucideIcon;
  label: string;
  count?: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`app-nav-item ${active ? "app-nav-item-active" : ""}`}
    >
      <span className="flex items-center gap-3">
        <span className={`rounded-full p-2 ${active ? "bg-primary/14 text-primary" : "bg-black/5 text-muted-foreground"}`}>
          <Icon className="size-4" />
        </span>
        <span className="text-sm font-medium">{label}</span>
      </span>
      {typeof count === "number" ? <span className="text-xs text-muted-foreground">{count}</span> : null}
    </button>
  );
}

function MetricStrip({ items }: { items: MetricItem[] }) {
  return (
    <div className="grid gap-px overflow-hidden rounded-[24px] border border-border bg-border md:grid-cols-2 2xl:grid-cols-4">
      {items.map((item) => (
        <div key={item.label} className="bg-white px-5 py-4">
          <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">{item.label}</div>
          <div className="mt-3 flex items-end justify-between gap-4">
            <div className="text-2xl font-semibold tracking-[-0.05em] text-foreground">{item.value}</div>
            {item.tone ? <Badge variant={item.tone}>{item.tone}</Badge> : null}
          </div>
          <div className="mt-2 text-sm leading-6 text-muted-foreground">{item.hint}</div>
        </div>
      ))}
    </div>
  );
}

function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex min-h-[220px] items-center justify-center rounded-[24px] border border-dashed border-border bg-muted/35 px-6 text-center">
      <div className="max-w-sm">
        <div className="text-base font-medium text-foreground">{title}</div>
        <div className="mt-2 text-sm leading-7 text-muted-foreground">{description}</div>
      </div>
    </div>
  );
}

function EmailList({
  items,
  selectedId,
  onSelect,
  emptyTitle,
  emptyDescription,
}: {
  items: EmailReviewItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  emptyTitle: string;
  emptyDescription: string;
}) {
  if (!items.length) {
    return <EmptyState title={emptyTitle} description={emptyDescription} />;
  }

  return (
    <div className="grid gap-2">
      {items.map((item) => {
        const active = item.id === selectedId;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onSelect(item.id)}
            className={`mail-row ${active ? "mail-row-active" : ""}`}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-foreground">{item.subject || "(no subject)"}</div>
                <div className="mt-1 truncate text-xs uppercase tracking-[0.14em] text-muted-foreground">
                  {item.sender_name || item.sender_email}
                </div>
              </div>
              <Badge variant={toneForScore(item.risk_score)} className="shrink-0">
                {formatPercent(item.risk_score)}
              </Badge>
            </div>
            <div className="mt-3 line-clamp-2 text-sm leading-6 text-muted-foreground">{item.body_preview}</div>
            <div className="mt-3 flex items-center justify-between gap-3 text-xs text-muted-foreground">
              <span>{item.sender_email}</span>
              <span>{item.received_at || "Unknown time"}</span>
            </div>
          </button>
        );
      })}
    </div>
  );
}

function DetailLabel({ children }: { children: ReactNode }) {
  return <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">{children}</div>;
}

function EvidenceLinks({ email }: { email: EmailReviewItem }) {
  if (!email.link_results.length) {
    return <div className="text-sm text-muted-foreground">No extracted links were stored for this email.</div>;
  }

  return (
    <div className="grid gap-3">
      {email.link_results.map((link, index) => {
        const href = link.final_url || link.normalized_url || link.original_url;
        return (
          <div key={`${href}-${index}`} className="rounded-[18px] border border-border bg-muted/45 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="neutral">{link.yutori_verdict}</Badge>
              <Badge variant="neutral">{link.ssl_state}</Badge>
              <Badge variant="neutral">{link.scan_status}</Badge>
            </div>
            <div className="mt-3 break-all text-sm font-medium text-foreground">{href || "Missing URL"}</div>
            {link.risk_flags.length ? (
              <div className="mt-3 grid gap-1 text-sm leading-6 text-muted-foreground">
                {link.risk_flags.map((flag) => (
                  <div key={flag}>{flag}</div>
                ))}
              </div>
            ) : null}
            {link.yutori_preview_url ? (
              <a
                href={link.yutori_preview_url}
                target="_blank"
                rel="noreferrer"
                className="mt-4 inline-flex items-center gap-2 text-sm font-medium text-foreground"
              >
                Open Yutori preview
                <ArrowUpRight className="size-4" />
              </a>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function EmailPreview({
  email,
  primaryAction,
  secondaryAction,
}: {
  email: EmailReviewItem | null;
  primaryAction?: ReactNode;
  secondaryAction?: ReactNode;
}) {
  if (!email) {
    return <EmptyState title="No email selected" description="Choose an item from the list to inspect the full record." />;
  }

  return (
    <div className="section-fade flex h-full flex-col overflow-hidden">
      <div className="border-b border-border px-6 py-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Selected record</div>
            <h2 className="mt-2 text-2xl font-semibold tracking-[-0.05em] text-foreground">{email.subject || "(no subject)"}</h2>
            <div className="mt-2 text-sm leading-6 text-muted-foreground">
              {email.sender_name ? `${email.sender_name} · ${email.sender_email}` : email.sender_email}
            </div>
          </div>
          <Badge variant={toneForScore(email.risk_score)}>{formatPercent(email.risk_score)}</Badge>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <Badge variant="neutral">{email.status.replaceAll("_", " ")}</Badge>
          <Badge variant="neutral">{email.received_at || "unknown time"}</Badge>
          {email.label !== null ? <Badge variant="neutral">{email.label === 1 ? "marked scam" : "marked non-scam"}</Badge> : null}
        </div>
        {(primaryAction || secondaryAction) ? <div className="mt-5 flex flex-wrap gap-3">{primaryAction}{secondaryAction}</div> : null}
      </div>

      <div className="grid flex-1 gap-6 overflow-y-auto px-6 py-6">
        <section className="grid gap-3">
          <DetailLabel>AI research summary</DetailLabel>
          <div className="rounded-[20px] bg-muted/45 px-4 py-4 text-sm leading-7 text-foreground/86">
            {email.description || "No AI summary available for this record."}
          </div>
        </section>

        <section className="grid gap-3">
          <DetailLabel>Risk reasons</DetailLabel>
          <div className="grid gap-2 rounded-[20px] bg-muted/45 px-4 py-4 text-sm leading-7 text-foreground/86">
            {email.risk_reasons.length ? email.risk_reasons.map((reason) => <div key={reason}>{reason}</div>) : "No reasons stored."}
          </div>
        </section>

        <section className="grid gap-3">
          <DetailLabel>Email body</DetailLabel>
          <div className="rounded-[20px] bg-muted/45 px-4 py-4 text-sm leading-7 whitespace-pre-wrap text-foreground/86">
            {email.body_full || "No body content was captured."}
          </div>
        </section>

        <section className="grid gap-3">
          <DetailLabel>Links and Yutori evidence</DetailLabel>
          <EvidenceLinks email={email} />
        </section>
      </div>
    </div>
  );
}

export function EmailSecurityDashboard() {
  const [activeSection, setActiveSection] = useState<WorkspaceSection>("dashboard");
  const [emailHealth, setEmailHealth] = useState<"checking" | "online" | "offline">("checking");
  const [dashboard, setDashboard] = useState<DashboardSummary | null>(null);
  const [quarantineEmails, setQuarantineEmails] = useState<EmailReviewItem[]>([]);
  const [scamEmails, setScamEmails] = useState<EmailReviewItem[]>([]);
  const [selectedQuarantineId, setSelectedQuarantineId] = useState<string | null>(null);
  const [selectedScamId, setSelectedScamId] = useState<string | null>(null);
  const [busyAction, setBusyAction] = useState<string>("");
  const [manualBusy, setManualBusy] = useState(false);
  const [screeningBusy, setScreeningBusy] = useState(false);
  const [refreshBusy, setRefreshBusy] = useState(false);
  const [manualResult, setManualResult] = useState<ManualCheckResponse | null>(null);
  const [manualForm, setManualForm] = useState<ManualFormState>({
    senderEmail: "",
    companyName: "",
    subject: "",
    body: "",
    urls: "",
  });

  const selectedQuarantine = useMemo(
    () => quarantineEmails.find((item) => item.id === selectedQuarantineId) ?? quarantineEmails[0] ?? null,
    [quarantineEmails, selectedQuarantineId],
  );
  const selectedScam = useMemo(
    () => scamEmails.find((item) => item.id === selectedScamId) ?? scamEmails[0] ?? null,
    [scamEmails, selectedScamId],
  );

  async function loadHealth() {
    try {
      await getHealth();
      setEmailHealth("online");
    } catch {
      setEmailHealth("offline");
    }
  }

  async function refreshAll() {
    const [summary, quarantine, scam] = await Promise.all([
      getDashboardSummary(),
      listQuarantineEmails(),
      listScamEmails(),
    ]);

    setDashboard(summary);
    setQuarantineEmails(quarantine.emails);
    setScamEmails(scam.emails);
    setSelectedQuarantineId((current) => {
      if (current && quarantine.emails.some((item) => item.id === current)) return current;
      return quarantine.emails[0]?.id ?? null;
    });
    setSelectedScamId((current) => {
      if (current && scam.emails.some((item) => item.id === current)) return current;
      return scam.emails[0]?.id ?? null;
    });
  }

  async function refreshWorkspace(showToast = false) {
    setRefreshBusy(true);
    try {
      await Promise.all([loadHealth(), refreshAll()]);
      if (showToast) toast.success("Workspace refreshed.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to refresh workspace");
    } finally {
      setRefreshBusy(false);
    }
  }

  useEffect(() => {
    void refreshWorkspace();
  }, []);

  async function handleRunScreening() {
    setScreeningBusy(true);
    try {
      const result = await runScreening();
      await refreshWorkspace();
      toast.success(
        `Screened ${result.processed} email(s), quarantined ${result.quarantined}, delivered ${result.delivered}.`,
      );
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Screening failed");
    } finally {
      setScreeningBusy(false);
    }
  }

  async function handleQuarantineAction(messageId: string, kind: "scam" | "non-scam") {
    setBusyAction(`${kind}:${messageId}`);
    try {
      if (kind === "scam") {
        await markScam(messageId);
      } else {
        await markNonScam(messageId);
      }
      await refreshWorkspace();
      toast.success(kind === "scam" ? "Email marked as scam." : "Email marked as non-scam.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Review action failed");
    } finally {
      setBusyAction("");
    }
  }

  async function handleRemoveScam(messageId: string) {
    setBusyAction(`remove:${messageId}`);
    try {
      await removeFromScam(messageId);
      await refreshWorkspace();
      toast.success("Email removed from scam section.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Failed to remove scam email");
    } finally {
      setBusyAction("");
    }
  }

  async function handleManualSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setManualBusy(true);
    try {
      const result = await manualCheck({
        sender_email: manualForm.senderEmail,
        company_name: manualForm.companyName,
        subject: manualForm.subject,
        body: manualForm.body,
        urls: manualForm.urls
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean),
      });
      setManualResult(result);
      toast.success("Manual AI check complete.");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Manual check failed");
    } finally {
      setManualBusy(false);
    }
  }

  const activeMeta = sectionMeta(activeSection);
  const dashboardMetrics: MetricItem[] = [
    {
      label: "Screened",
      value: String(dashboard?.screened_count ?? 0),
      hint: "Messages processed by the front-door scanner.",
    },
    {
      label: "Quarantine",
      value: String(dashboard?.quarantined_count ?? 0),
      hint: "Suspicious messages awaiting human confirmation.",
      tone: "watch",
    },
    {
      label: "Confirmed scam",
      value: String(dashboard?.confirmed_scam_count ?? 0),
      hint: "Messages the user confirmed as phishing or scam.",
      tone: "threat",
    },
    {
      label: "False positives",
      value: String(dashboard?.false_positive_count ?? 0),
      hint: "Messages released as legitimate after review.",
      tone: "safe",
    },
  ];

  return (
    <main className="min-h-screen p-3 sm:p-4">
      <div className="mx-auto flex min-h-[calc(100vh-1.5rem)] max-w-[1600px] flex-col overflow-hidden rounded-[30px] border border-white/70 bg-[rgba(255,255,255,0.78)] shadow-[0_24px_80px_rgba(40,53,74,0.10)] backdrop-blur-xl lg:min-h-[calc(100vh-2rem)] lg:flex-row">
        <aside className="border-b border-border bg-[rgba(251,247,240,0.92)] px-4 py-4 lg:w-[260px] lg:border-b-0 lg:border-r lg:px-5 lg:py-5">
          <div className="flex items-center justify-between gap-3 lg:block">
            <div>
              <div className="text-[11px] uppercase tracking-[0.18em] text-muted-foreground">anti-scam.ai</div>
              <div className="mt-2 text-2xl font-semibold tracking-[-0.06em] text-foreground">Mail Gatekeeper</div>
            </div>
            <Badge variant={emailHealth === "online" ? "safe" : emailHealth === "offline" ? "threat" : "watch"}>
              {emailHealth}
            </Badge>
          </div>

          <div className="mt-6 grid gap-2">
            <AppNavButton
              active={activeSection === "dashboard"}
              icon={Inbox}
              label="Dashboard"
              onClick={() => setActiveSection("dashboard")}
            />
            <AppNavButton
              active={activeSection === "quarantine"}
              icon={MailWarning}
              label="Quarantine"
              count={quarantineEmails.length}
              onClick={() => setActiveSection("quarantine")}
            />
            <AppNavButton
              active={activeSection === "scam"}
              icon={ShieldAlert}
              label="Scam"
              count={scamEmails.length}
              onClick={() => setActiveSection("scam")}
            />
            <AppNavButton
              active={activeSection === "manual"}
              icon={FileSearch}
              label="Manual Check"
              onClick={() => setActiveSection("manual")}
            />
          </div>

          <div className="mt-6 rounded-[24px] border border-border bg-white px-4 py-4">
            <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Scanner</div>
            <div className="mt-3 text-lg font-semibold tracking-[-0.04em] text-foreground">
              {dashboard?.scanner_status ?? "idle"}
            </div>
            <div className="mt-2 text-sm leading-6 text-muted-foreground">
              Last scan: {formatTimestamp(dashboard?.last_scan_at)}
            </div>
            <div className="mt-2 text-sm leading-6 text-muted-foreground">
              Screening {dashboard?.screening_enabled ? "enabled" : "disabled"}.
            </div>
          </div>

          <div className="mt-4 rounded-[24px] border border-border bg-white px-4 py-4">
            <div className="flex items-center gap-2 text-sm font-medium text-foreground">
              <ShieldCheck className="size-4 text-primary" />
              Review model
            </div>
            <div className="mt-3 text-sm leading-7 text-muted-foreground">
              Suspicious mail is researched before the user opens it. Manual review writes back into the current memory path.
            </div>
          </div>
        </aside>

        <section className="flex min-h-0 flex-1 flex-col">
          <header className="border-b border-border px-4 py-4 sm:px-6">
            <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
              <div>
                <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Operator workspace</div>
                <h1 className="mt-2 text-3xl font-semibold tracking-[-0.06em] text-foreground">{activeMeta.title}</h1>
                <p className="mt-2 max-w-2xl text-sm leading-7 text-muted-foreground">{activeMeta.description}</p>
              </div>
              <div className="flex flex-wrap gap-3">
                <Button variant="outline" onClick={() => void refreshWorkspace(true)} disabled={refreshBusy}>
                  <RefreshCw className={`size-4 ${refreshBusy ? "animate-spin" : ""}`} data-icon="inline-start" />
                  Refresh
                </Button>
                <Button onClick={handleRunScreening} disabled={screeningBusy}>
                  <ScanSearch className={`size-4 ${screeningBusy ? "animate-spin" : ""}`} data-icon="inline-start" />
                  {screeningBusy ? "Screening…" : "Run screening"}
                </Button>
              </div>
            </div>
          </header>

          <div className="flex-1 min-h-0 p-4 sm:p-6">
            {activeSection === "dashboard" ? (
              <div className="section-fade grid h-full min-h-0 gap-4 xl:grid-cols-[minmax(0,1.15fr)_380px]">
                <div className="grid min-h-0 gap-4">
                  <MetricStrip items={dashboardMetrics} />

                  <div className="grid min-h-0 gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
                    <div className="app-surface">
                      <div className="app-surface-header">
                        <div>
                          <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Recent high-risk mail</div>
                          <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Latest quarantine pressure</div>
                        </div>
                      </div>
                      <div className="min-h-0 overflow-y-auto px-4 pb-4">
                        {dashboard?.recent_high_risk?.length ? (
                          <div className="grid gap-2">
                            {dashboard.recent_high_risk.map((item) => (
                              <button
                                key={item.id}
                                type="button"
                                onClick={() => {
                                  if (item.status === "confirmed_scam") {
                                    setSelectedScamId(item.id);
                                    setActiveSection("scam");
                                  } else {
                                    setSelectedQuarantineId(item.id);
                                    setActiveSection("quarantine");
                                  }
                                }}
                                className="mail-row text-left"
                              >
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <div className="truncate text-sm font-semibold text-foreground">{item.subject || "(no subject)"}</div>
                                    <div className="mt-1 truncate text-xs uppercase tracking-[0.14em] text-muted-foreground">
                                      {item.sender_name || item.sender_email}
                                    </div>
                                  </div>
                                  <div className="flex shrink-0 gap-2">
                                    <Badge variant={toneForScore(item.risk_score)}>{formatPercent(item.risk_score)}</Badge>
                                    <Badge variant="neutral">{item.status.replaceAll("_", " ")}</Badge>
                                  </div>
                                </div>
                              </button>
                            ))}
                          </div>
                        ) : (
                          <EmptyState
                            title="No high-risk items yet"
                            description="Run screening or wait for the background loop to quarantine suspicious mail."
                          />
                        )}
                      </div>
                    </div>

                    <div className="app-surface">
                      <div className="app-surface-header">
                        <div>
                          <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Workflow</div>
                          <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">How the platform behaves</div>
                        </div>
                      </div>
                      <div className="grid gap-4 px-4 pb-4">
                        <div className="rounded-[18px] bg-muted/45 p-4">
                          <div className="flex items-center gap-3 text-sm font-medium text-foreground">
                            <Inbox className="size-4 text-primary" />
                            Gmail intake
                          </div>
                          <div className="mt-2 text-sm leading-7 text-muted-foreground">
                            New mail is polled from the connected account before the user works inside the inbox.
                          </div>
                        </div>
                        <div className="rounded-[18px] bg-muted/45 p-4">
                          <div className="flex items-center gap-3 text-sm font-medium text-foreground">
                            <AlertTriangle className="size-4 text-[#d76b2d]" />
                            AI research
                          </div>
                          <div className="mt-2 text-sm leading-7 text-muted-foreground">
                            Suspicious entities, links, and descriptions are researched through the risk agent and Yutori browser use.
                          </div>
                        </div>
                        <div className="rounded-[18px] bg-muted/45 p-4">
                          <div className="flex items-center gap-3 text-sm font-medium text-foreground">
                            <BadgeCheck className="size-4 text-[#b4452e]" />
                            Human confirmation
                          </div>
                          <div className="mt-2 text-sm leading-7 text-muted-foreground">
                            The user confirms SCAM or NON-SCAM, and that decision feeds the current memory path.
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="app-surface">
                  <div className="app-surface-header">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">System status</div>
                      <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Live conditions</div>
                    </div>
                  </div>
                  <div className="grid gap-4 px-4 pb-4">
                    <div className="rounded-[18px] bg-muted/45 p-4">
                      <div className="text-sm font-medium text-foreground">Email backend</div>
                      <div className="mt-2 text-sm leading-7 text-muted-foreground">
                        {emailHealth === "online"
                          ? "Healthy. API and queue endpoints are responding."
                          : emailHealth === "offline"
                            ? "Offline. The frontend cannot reach the backend."
                            : "Checking backend reachability."}
                      </div>
                    </div>
                    <div className="rounded-[18px] bg-muted/45 p-4">
                      <div className="text-sm font-medium text-foreground">Quarantine queue</div>
                      <div className="mt-2 text-3xl font-semibold tracking-[-0.06em] text-foreground">{quarantineEmails.length}</div>
                      <div className="mt-2 text-sm leading-7 text-muted-foreground">Items waiting for human confirmation.</div>
                    </div>
                    <div className="rounded-[18px] bg-muted/45 p-4">
                      <div className="text-sm font-medium text-foreground">Scam registry</div>
                      <div className="mt-2 text-3xl font-semibold tracking-[-0.06em] text-foreground">{scamEmails.length}</div>
                      <div className="mt-2 text-sm leading-7 text-muted-foreground">Confirmed scams stored with sender and link evidence.</div>
                    </div>
                  </div>
                </div>
              </div>
            ) : null}

            {activeSection === "quarantine" ? (
              <div className="section-fade grid h-full min-h-0 gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
                <div className="app-surface">
                  <div className="app-surface-header">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Queue</div>
                      <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Suspicious emails</div>
                    </div>
                    <Badge variant="neutral">{quarantineEmails.length}</Badge>
                  </div>
                  <div className="min-h-0 overflow-y-auto px-4 pb-4">
                    <EmailList
                      items={quarantineEmails}
                      selectedId={selectedQuarantine?.id ?? null}
                      onSelect={setSelectedQuarantineId}
                      emptyTitle="Quarantine is clear"
                      emptyDescription="No messages are currently waiting for review."
                    />
                  </div>
                </div>

                <div className="app-surface overflow-hidden">
                  <EmailPreview
                    email={selectedQuarantine}
                    primaryAction={
                      <Button
                        onClick={() => selectedQuarantine && void handleQuarantineAction(selectedQuarantine.id, "scam")}
                        disabled={!selectedQuarantine || busyAction === `scam:${selectedQuarantine?.id}`}
                      >
                        <ShieldAlert className="size-4" data-icon="inline-start" />
                        {busyAction === `scam:${selectedQuarantine?.id}` ? "Saving…" : "Mark SCAM"}
                      </Button>
                    }
                    secondaryAction={
                      <Button
                        variant="outline"
                        onClick={() => selectedQuarantine && void handleQuarantineAction(selectedQuarantine.id, "non-scam")}
                        disabled={!selectedQuarantine || busyAction === `non-scam:${selectedQuarantine?.id}`}
                      >
                        <ShieldCheck className="size-4" data-icon="inline-start" />
                        {busyAction === `non-scam:${selectedQuarantine?.id}` ? "Saving…" : "Mark NON-SCAM"}
                      </Button>
                    }
                  />
                </div>
              </div>
            ) : null}

            {activeSection === "scam" ? (
              <div className="section-fade grid h-full min-h-0 gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
                <div className="app-surface">
                  <div className="app-surface-header">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Registry</div>
                      <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Confirmed scam mail</div>
                    </div>
                    <Badge variant="neutral">{scamEmails.length}</Badge>
                  </div>
                  <div className="min-h-0 overflow-y-auto px-4 pb-4">
                    <EmailList
                      items={scamEmails}
                      selectedId={selectedScam?.id ?? null}
                      onSelect={setSelectedScamId}
                      emptyTitle="No confirmed scams yet"
                      emptyDescription="Messages marked SCAM will appear here with sender and link evidence."
                    />
                  </div>
                </div>

                <div className="app-surface overflow-hidden">
                  <EmailPreview
                    email={selectedScam}
                    primaryAction={
                      <Button
                        variant="outline"
                        onClick={() => selectedScam && void handleRemoveScam(selectedScam.id)}
                        disabled={!selectedScam || busyAction === `remove:${selectedScam?.id}`}
                      >
                        <ShieldCheck className="size-4" data-icon="inline-start" />
                        {busyAction === `remove:${selectedScam?.id}` ? "Saving…" : "Remove from SCAM"}
                      </Button>
                    }
                  />
                </div>
              </div>
            ) : null}

            {activeSection === "manual" ? (
              <div className="section-fade grid h-full min-h-0 gap-4 xl:grid-cols-[420px_minmax(0,1fr)]">
                <div className="app-surface">
                  <div className="app-surface-header">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Manual intake</div>
                      <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Describe the message</div>
                    </div>
                  </div>
                  <form onSubmit={handleManualSubmit} className="grid gap-4 px-4 pb-4">
                    <div className="grid gap-2">
                      <DetailLabel>Sender email</DetailLabel>
                      <Input
                        value={manualForm.senderEmail}
                        onChange={(event) => setManualForm((current) => ({ ...current, senderEmail: event.target.value }))}
                        placeholder="billing@company-example.com"
                      />
                    </div>
                    <div className="grid gap-2">
                      <DetailLabel>Company or sender name</DetailLabel>
                      <Input
                        value={manualForm.companyName}
                        onChange={(event) => setManualForm((current) => ({ ...current, companyName: event.target.value }))}
                        placeholder="Company name mentioned in the email"
                      />
                    </div>
                    <div className="grid gap-2">
                      <DetailLabel>Subject</DetailLabel>
                      <Input
                        value={manualForm.subject}
                        onChange={(event) => setManualForm((current) => ({ ...current, subject: event.target.value }))}
                        placeholder="Subject line"
                      />
                    </div>
                    <div className="grid gap-2">
                      <DetailLabel>Email description or body</DetailLabel>
                      <Textarea
                        value={manualForm.body}
                        onChange={(event) => setManualForm((current) => ({ ...current, body: event.target.value }))}
                        placeholder="Paste the suspicious message, company pitch, or sender description"
                        className="min-h-[180px]"
                      />
                    </div>
                    <div className="grid gap-2">
                      <DetailLabel>Links, one per line</DetailLabel>
                      <Textarea
                        value={manualForm.urls}
                        onChange={(event) => setManualForm((current) => ({ ...current, urls: event.target.value }))}
                        placeholder={"https://example.com\nhttps://another-link.example"}
                        className="min-h-[120px]"
                      />
                    </div>
                    <Button type="submit" disabled={manualBusy}>
                      <FileSearch className="size-4" data-icon="inline-start" />
                      {manualBusy ? "Running investigation…" : "Run AI check"}
                    </Button>
                  </form>
                </div>

                <div className="app-surface">
                  <div className="app-surface-header">
                    <div>
                      <div className="text-[11px] uppercase tracking-[0.16em] text-muted-foreground">Result</div>
                      <div className="mt-2 text-lg font-semibold tracking-[-0.04em] text-foreground">Research output</div>
                    </div>
                  </div>

                  <div className="min-h-0 overflow-y-auto px-4 pb-4">
                    {manualResult ? (
                      <div className="grid gap-5">
                        <MetricStrip
                          items={[
                            {
                              label: "Verdict",
                              value: manualResult.email_risk_summary.decision,
                              hint: "Platform recommendation for this manual submission.",
                              tone: toneForScore(manualResult.email_risk_summary.risk_score),
                            },
                            {
                              label: "Risk score",
                              value: formatPercent(manualResult.email_risk_summary.risk_score),
                              hint: "Combined result from heuristics, AI review, and link evidence.",
                            },
                            {
                              label: "Links found",
                              value: String(manualResult.email_risk_summary.links_found),
                              hint: "URLs extracted from the submission.",
                            },
                            {
                              label: "Links scanned",
                              value: String(manualResult.email_risk_summary.links_scanned),
                              hint: manualResult.email_risk_summary.link_scan_failed_closed
                                ? "At least one scan failed closed."
                                : "All available URLs were evaluated.",
                            },
                          ]}
                        />

                        <section className="grid gap-3">
                          <DetailLabel>Research summary</DetailLabel>
                          <div className="rounded-[20px] bg-muted/45 px-4 py-4 text-sm leading-7 text-foreground/86">
                            {manualResult.research.summary || "No external research summary was returned."}
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Badge variant="neutral">{manualResult.research.provider}</Badge>
                            <Badge variant="neutral">{manualResult.research.executed ? "executed" : "not executed"}</Badge>
                            {manualResult.research.preview_url ? (
                              <a
                                href={manualResult.research.preview_url}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-2 rounded-full border border-border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-foreground"
                              >
                                Open preview
                                <ArrowUpRight className="size-4" />
                              </a>
                            ) : null}
                          </div>
                        </section>

                        <section className="grid gap-3">
                          <DetailLabel>Risk reasons</DetailLabel>
                          <div className="grid gap-2 rounded-[20px] bg-muted/45 px-4 py-4 text-sm leading-7 text-foreground/86">
                            {manualResult.email_risk_summary.risk_reasons.length
                              ? manualResult.email_risk_summary.risk_reasons.map((reason) => <div key={reason}>{reason}</div>)
                              : "No reasons were returned."}
                          </div>
                        </section>

                        <section className="grid gap-3">
                          <DetailLabel>Link evidence</DetailLabel>
                          <div className="grid gap-3">
                            {manualResult.link_results.length ? (
                              manualResult.link_results.map((link, index) => {
                                const href = link.final_url || link.normalized_url || link.original_url;
                                return (
                                  <div key={`${href}-${index}`} className="rounded-[18px] border border-border bg-muted/45 p-4">
                                    <div className="flex flex-wrap gap-2">
                                      <Badge variant="neutral">{link.yutori_verdict}</Badge>
                                      <Badge variant="neutral">{link.ssl_state}</Badge>
                                      <Badge variant="neutral">{link.scan_status}</Badge>
                                    </div>
                                    <div className="mt-3 break-all text-sm font-medium text-foreground">{href || "Missing URL"}</div>
                                    {link.risk_flags.length ? (
                                      <div className="mt-3 grid gap-1 text-sm leading-6 text-muted-foreground">
                                        {link.risk_flags.map((flag) => (
                                          <div key={flag}>{flag}</div>
                                        ))}
                                      </div>
                                    ) : null}
                                  </div>
                                );
                              })
                            ) : (
                              <EmptyState
                                title="No link evidence"
                                description="Add URLs to the submission if you want the agent to inspect redirect and destination behavior."
                              />
                            )}
                          </div>
                        </section>
                      </div>
                    ) : (
                      <EmptyState
                        title="No investigation yet"
                        description="Submit a sender, company, or suspicious description to see the AI and Yutori research output here."
                      />
                    )}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </section>
      </div>
    </main>
  );
}
