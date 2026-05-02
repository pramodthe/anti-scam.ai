"use client";

import { Suspense, useEffect, useState, type FormEvent } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, ExternalLink } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { toast } from "@/components/ui/sonner";
import { getGoogleSetupStatus, googleOAuthStartUrl, reloadScreeningAccount, saveGoogleOAuthClient } from "@/lib/api";

function SetupContent() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<Awaited<ReturnType<typeof getGoogleSetupStatus>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [saving, setSaving] = useState(false);

  const refreshStatus = async () => {
    try {
      const s = await getGoogleSetupStatus();
      setStatus(s);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not reach API");
      setStatus(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshStatus();
  }, []);

  useEffect(() => {
    const err = searchParams.get("error");
    const connected = searchParams.get("connected");
    const email = searchParams.get("email");
    if (err) {
      toast.error(decodeURIComponent(err));
    }
    if (connected === "1") {
      void (async () => {
        try {
          const r = await reloadScreeningAccount();
          const who = email ? decodeURIComponent(email) : "Gmail";
          if (r.screening_enabled) {
            toast.success(`${who} connected — inbox screening is active`);
          } else {
            toast.success(`${who} connected`, {
              description: "Screening is off: add a mailbox in .env or ensure RISK_SCREENING_ENABLED=true and token has refresh_token.",
            });
          }
        } catch {
          toast.success(email ? `Connected ${decodeURIComponent(email)}` : "Gmail connected");
        }
        await refreshStatus();
      })();
    }
  }, [searchParams]);

  async function onSaveCredentials(e: FormEvent) {
    e.preventDefault();
    if (!clientId.trim() || !clientSecret.trim()) {
      toast.error("Enter both Client ID and Client secret");
      return;
    }
    setSaving(true);
    try {
      await saveGoogleOAuthClient({ client_id: clientId.trim(), client_secret: clientSecret.trim() });
      toast.success("Saved OAuth client (stored under .secrets on the API machine)");
      setClientSecret("");
      await refreshStatus();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  return (
    <main className="min-h-screen bg-[rgba(251,247,240,0.96)] p-4 sm:p-8">
      <div className="mx-auto max-w-xl space-y-6">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" asChild>
            <Link href="/">
              <ArrowLeft className="mr-2 size-4" />
              Console
            </Link>
          </Button>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Gmail developer setup</CardTitle>
            <CardDescription>
              Enter your Google Cloud OAuth <strong>Web application</strong> client here, then sign in once. The API saves your
              refresh token locally so the scanner can read mail.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="rounded-[18px] bg-muted/45 p-4 text-sm leading-6 text-muted-foreground">
              <p className="font-medium text-foreground">Google Cloud Console</p>
              <ol className="mt-2 list-decimal space-y-1 pl-5">
                <li>Create an OAuth client with type <strong>Web application</strong> (not Desktop).</li>
                <li>
                  Add this authorized redirect URI — must match exactly:
                  <code className="mt-1 block break-all rounded-lg bg-background px-2 py-1 text-xs text-foreground">
                    {status?.redirect_uri || "http://127.0.0.1:8000/auth/google/callback"}
                  </code>
                </li>
                <li>Enable Gmail API and add test users while the app is in Testing.</li>
              </ol>
              <a
                href="https://console.cloud.google.com/apis/credentials"
                target="_blank"
                rel="noreferrer"
                className="mt-3 inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline"
              >
                Open Credentials <ExternalLink className="size-3.5" />
              </a>
            </div>

            <Separator />

            <div className="grid gap-2 text-sm">
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">OAuth client configured</span>
                <span className={status?.has_oauth_client ? "font-medium text-emerald-700" : "font-medium text-amber-700"}>
                  {loading ? "…" : status?.has_oauth_client ? "Yes" : "No"}
                </span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-muted-foreground">Gmail signed in</span>
                <span className={status?.has_refresh_token ? "font-medium text-emerald-700" : "font-medium text-amber-700"}>
                  {loading ? "…" : status?.has_refresh_token ? "Yes" : "No"}
                </span>
              </div>
              {status?.connected_email ? (
                <div className="flex justify-between gap-2 pt-1">
                  <span className="text-muted-foreground">Mailbox</span>
                  <span className="truncate font-medium text-foreground" title={status.connected_email}>
                    {status.connected_email}
                  </span>
                </div>
              ) : null}
            </div>

            <form onSubmit={onSaveCredentials} className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground" htmlFor="client_id">
                  Client ID
                </label>
                <Input
                  id="client_id"
                  name="client_id"
                  autoComplete="off"
                  placeholder="….apps.googleusercontent.com"
                  value={clientId}
                  onChange={(ev) => setClientId(ev.target.value)}
                />
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground" htmlFor="client_secret">
                  Client secret
                </label>
                <Input
                  id="client_secret"
                  name="client_secret"
                  type="password"
                  autoComplete="off"
                  placeholder="GOCSPX-…"
                  value={clientSecret}
                  onChange={(ev) => setClientSecret(ev.target.value)}
                />
              </div>
              <Button type="submit" disabled={saving}>
                {saving ? "Saving…" : "Save OAuth client"}
              </Button>
            </form>

            <Separator />

            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Saving the Client ID and secret alone does not connect Gmail — you must click <strong>Sign in with Google</strong> so the API can store a refresh token.
              </p>
              <p className="text-sm text-muted-foreground">After saving the client, sign in with the Google account whose inbox you want to monitor.</p>
              <Button
                type="button"
                variant="secondary"
                disabled={!status?.has_oauth_client}
                className="w-full sm:w-auto"
                onClick={() => {
                  window.location.href = googleOAuthStartUrl();
                }}
              >
                Sign in with Google
              </Button>
              {!status?.has_oauth_client ? (
                <p className="text-xs text-muted-foreground">Save Client ID and secret first.</p>
              ) : null}
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="w-full sm:w-auto"
                onClick={async () => {
                  try {
                    const r = await reloadScreeningAccount();
                    toast.success(
                      r.screening_enabled
                        ? `Scanner updated — monitoring ${r.mailbox || "inbox"}`
                        : "Scanner still off — finish Google sign-in or check .env",
                    );
                    await refreshStatus();
                  } catch (e) {
                    toast.error(e instanceof Error ? e.message : "Could not reload scanner");
                  }
                }}
              >
                Resync scanner with saved token
              </Button>
              <p className="text-xs text-muted-foreground">
                Use if the API was running before you signed in, or you replaced token.json manually.
              </p>
            </div>

            <p className="text-xs leading-5 text-muted-foreground">
              Optional: set <code className="rounded bg-muted px-1">FRONTEND_URL</code> and{" "}
              <code className="rounded bg-muted px-1">GMAIL_OAUTH_REDIRECT_URI</code> in the API <code className="rounded bg-muted px-1">.env</code> if you
              use non-default ports or hosts. Restart the API after connecting if background screening does not pick up the new mailbox immediately.
            </p>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}

export default function SetupPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">Loading setup…</div>
      }
    >
      <SetupContent />
    </Suspense>
  );
}
