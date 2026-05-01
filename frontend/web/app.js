const emailBase = window.location.origin;

const state = {
  safeEmails: [],
  threatEmails: [],
  evaluations: new Map(),
  scanActivity: [],
  riskFailures: 0,
};

const els = {
  heroSafe: document.querySelector("#hero-safe"),
  heroThreats: document.querySelector("#hero-threats"),
  heroLinks: document.querySelector("#hero-links"),
  emailApiStatus: document.querySelector("#email-api-status"),
  metricSafe: document.querySelector("#metric-safe"),
  metricThreats: document.querySelector("#metric-threats"),
  metricLinks: document.querySelector("#metric-links"),
  metricFailures: document.querySelector("#metric-failures"),
  safeFeed: document.querySelector("#safe-feed"),
  threatFeed: document.querySelector("#threat-feed"),
  linkOutput: document.querySelector("#link-output-body"),
  toastStack: document.querySelector("#toast-stack"),
  safeSearch: document.querySelector("#safe-search"),
  threatSearch: document.querySelector("#threat-search"),
};

function showToast(message) {
  const node = document.createElement("div");
  node.className = "toast";
  node.textContent = message;
  els.toastStack.append(node);
  window.setTimeout(() => node.remove(), 3000);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    headers: {
      ...(options.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(options.headers || {}),
    },
    ...options,
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }
  return response.json();
}

function riskTone(score) {
  if (score <= 0.3) return "safe";
  if (score <= 0.6) return "elevated";
  return "threat";
}

function riskGlyph(score) {
  if (score <= 0.3) return "CLEAR";
  if (score <= 0.6) return "WATCH";
  return "HOLD";
}

function updateMetrics() {
  const links = state.scanActivity.reduce((total, item) => total + Number(item.links_scanned || 0), 0);
  els.metricSafe.textContent = String(state.safeEmails.length);
  els.metricThreats.textContent = String(state.threatEmails.length);
  els.metricLinks.textContent = String(links);
  els.metricFailures.textContent = String(state.riskFailures);
  els.heroSafe.textContent = String(state.safeEmails.length);
  els.heroThreats.textContent = String(state.threatEmails.length);
  els.heroLinks.textContent = String(links);
}

function renderRecordMeta(items) {
  return `<div class="record-meta">${items.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>`;
}

function renderReasons(reasons = []) {
  if (!reasons.length) return "";
  return `
    <div class="detail-row">
      <span class="detail-label">Reasons</span>
      <div class="detail-value">${reasons.map((reason) => `<div>${escapeHtml(reason)}</div>`).join("")}</div>
    </div>
  `;
}

function renderLinks(linkResults = []) {
  if (!linkResults.length) return "";
  return `
    <div class="detail-row">
      <span class="detail-label">Link Intelligence</span>
      <div class="detail-value">
        ${linkResults
          .map((link) => {
            const preview = link.yutori_preview_url
              ? `<a class="ghost-action" href="${escapeHtml(link.yutori_preview_url)}" target="_blank" rel="noreferrer">Open preview</a>`
              : "";
            const flags = (link.risk_flags || []).length
              ? `<div>${link.risk_flags.map((flag) => `<div>${escapeHtml(flag)}</div>`).join("")}</div>`
              : "";
            const href = escapeHtml(link.final_url || link.normalized_url || link.original_url || "");
            return `
              <div class="link-output-entry">
                <strong>${href || "Missing URL"}</strong>
                ${renderRecordMeta([
                  `verdict ${link.yutori_verdict || "unknown"}`,
                  `ssl ${link.ssl_state || "unknown"}`,
                  `scan ${link.scan_status || "error"}`,
                ])}
                ${flags}
                ${preview}
              </div>
            `;
          })
          .join("")}
      </div>
    </div>
  `;
}

function renderSafeFeed() {
  const query = els.safeSearch.value.trim().toLowerCase();
  const filtered = state.safeEmails.filter((email) => {
    if (!query) return true;
    return [email.subject, email.from_email, email.body].some((part) =>
      String(part || "").toLowerCase().includes(query),
    );
  });

  if (!filtered.length) {
    els.safeFeed.innerHTML = `<div class="empty-state">No cleared messages match the current filter.</div>`;
    return;
  }

  els.safeFeed.innerHTML = filtered
    .map((email) => {
      const evaluation = state.evaluations.get(email.id) || {};
      const score = Number(evaluation.risk_score || 0);
      const tone = riskTone(score);
      return `
        <article class="record">
          <div class="record-top">
            <div>
              <h3>${escapeHtml(email.subject || "(no subject)")}</h3>
              <p>${escapeHtml(email.from_email || "")}</p>
            </div>
            <span class="tag ${tone}">${riskGlyph(score)} ${Math.round(score * 100)}%</span>
          </div>
          ${renderRecordMeta([
            `decision ${evaluation.decision || "deliver"}`,
            `to ${email.to_email || ""}`,
            `sent ${email.send_time || ""}`,
            `links ${evaluation.links_scanned || 0}/${evaluation.links_found || 0}`,
          ])}
          <div class="record-body">
            ${renderReasons(evaluation.risk_reasons || [])}
            ${renderLinks(evaluation.link_results || [])}
            <div class="detail-row">
              <span class="detail-label">Body</span>
              <div class="body-copy">${escapeHtml(email.body || "")}</div>
            </div>
          </div>
          <div class="record-actions">
            <button class="danger-action" data-delete="${escapeHtml(email.id)}">Delete email</button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderThreatFeed() {
  const query = els.threatSearch.value.trim().toLowerCase();
  const filtered = state.threatEmails.filter((record) => {
    if (!query) return true;
    return [
      record.email?.subject,
      record.email?.from_email,
      ...(record.risk_reasons || []),
    ].some((part) => String(part || "").toLowerCase().includes(query));
  });

  if (!filtered.length) {
    els.threatFeed.innerHTML = `<div class="empty-state">Threat queue is empty or filtered out.</div>`;
    return;
  }

  els.threatFeed.innerHTML = filtered
    .map((record) => {
      const email = record.email || {};
      const score = Number(record.risk_score || 0);
      const tone = riskTone(score);
      const label = record.label === null || record.label === undefined ? "unlabeled" : record.label === 1 ? "scam" : "not scam";
      return `
        <article class="record">
          <div class="record-top">
            <div>
              <h3>${escapeHtml(email.subject || "(no subject)")}</h3>
              <p>${escapeHtml(email.from_email || "")}</p>
            </div>
            <span class="tag ${tone}">${riskGlyph(score)} ${Math.round(score * 100)}%</span>
          </div>
          ${renderRecordMeta([
            `status ${record.status || "pending_human_review"}`,
            `label ${label}`,
            `model ${record.model_version || ""}`,
          ])}
          <div class="record-body">
            <div class="detail-row">
              <span class="detail-label">Description</span>
              <div class="detail-value">${escapeHtml(record.description || "")}</div>
            </div>
            ${renderReasons(record.risk_reasons || [])}
            ${renderLinks(record.link_results || [])}
            <div class="detail-row">
              <span class="detail-label">Body</span>
              <div class="body-copy">${escapeHtml(email.body || "")}</div>
            </div>
          </div>
          <div class="record-actions">
            <button class="primary-action" data-label-scam="${escapeHtml(record.id)}">Label scam</button>
            <button class="secondary-action" data-label-legit="${escapeHtml(record.id)}">Not scam + release</button>
            <button class="ghost-action" data-release="${escapeHtml(record.id)}">Release only</button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderLinkOutput(result) {
  if (!result) {
    els.linkOutput.textContent = "Manual URL verdicts, SSL state, and browser intelligence will appear here.";
    return;
  }
  const summary = result.email_risk_summary || {};
  els.linkOutput.innerHTML = `
    ${renderRecordMeta([
      `decision ${summary.decision || "deliver"}`,
      `risk ${Math.round(Number(summary.risk_score || 0) * 100)}%`,
      `links ${summary.links_scanned || 0}/${summary.links_found || 0}`,
    ])}
    ${renderReasons(summary.risk_reasons || [])}
    ${renderLinks(result.link_results || [])}
  `;
}

async function loadEmailHealth() {
  try {
    await requestJson(`${emailBase}/health`);
    els.emailApiStatus.textContent = "online";
  } catch {
    els.emailApiStatus.textContent = "offline";
  }
}

async function loadThreatQueue() {
  const result = await requestJson(`${emailBase}/risk/quarantine`);
  state.threatEmails = result.emails || [];
  updateMetrics();
  renderThreatFeed();
}

async function scanInbox(payload) {
  const params = new URLSearchParams({
    email_address: payload.email_address,
    minutes_since: String(payload.minutes_since),
    include_read: String(payload.include_read),
    max_results: String(payload.max_results),
  });
  const result = await requestJson(`${emailBase}/gmail/emails?${params.toString()}`);
  const emails = result.emails || [];
  const safeEmails = [];
  const evaluations = new Map();
  const scanActivity = [];
  let riskFailures = 0;

  for (const email of emails) {
    try {
      const evaluation = await requestJson(`${emailBase}/risk/emails/evaluate`, {
        method: "POST",
        body: JSON.stringify({ email }),
      });
      evaluations.set(email.id, evaluation);
      scanActivity.push({
        id: email.id,
        subject: email.subject,
        links_scanned: evaluation.links_scanned || 0,
      });
      if (evaluation.decision === "deliver") safeEmails.push(email);
    } catch {
      riskFailures += 1;
    }
  }

  state.safeEmails = safeEmails;
  state.evaluations = evaluations;
  state.scanActivity = scanActivity;
  state.riskFailures = riskFailures;
  updateMetrics();
  renderSafeFeed();
  await loadThreatQueue();
  showToast(`Scanned ${emails.length} messages`);
}

async function sendEmail(payload) {
  const result = await requestJson(`${emailBase}/gmail/send`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  showToast(`Email sent: ${result.message_id}`);
}

async function labelThreat(id, label) {
  await requestJson(`${emailBase}/risk/quarantine/${id}/label`, {
    method: "POST",
    body: JSON.stringify({ label }),
  });
}

async function releaseThreat(id) {
  await requestJson(`${emailBase}/risk/quarantine/${id}/release`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

async function deleteEmail(id) {
  await requestJson(`${emailBase}/gmail/emails/${id}`, { method: "DELETE" });
}

async function runLinkAnalysis(payload) {
  const result = await requestJson(`${emailBase}/risk/links/evaluate`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
  renderLinkOutput(result);
  showToast("Link analysis complete");
}

function bindEvents() {
  document.querySelectorAll("[data-jump]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.querySelector(button.dataset.jump);
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });

  document.querySelector("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await scanInbox({
        email_address: form.get("email_address"),
        minutes_since: Number(form.get("minutes_since") || 1440),
        max_results: Number(form.get("max_results") || 25),
        include_read: form.get("include_read") === "on",
      });
    } catch (error) {
      showToast("Inbox scan failed");
      console.error(error);
    }
  });

  document.querySelector("#compose-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await sendEmail({
        to: form.get("to"),
        subject: form.get("subject"),
        body: form.get("body"),
      });
      event.currentTarget.reset();
    } catch (error) {
      showToast("Send failed");
      console.error(error);
    }
  });

  document.querySelector("#link-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await runLinkAnalysis({
        sender_email: form.get("sender_email"),
        subject: form.get("subject"),
        body: form.get("body"),
        urls: String(form.get("urls") || "")
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean),
      });
    } catch (error) {
      showToast("Link analysis failed");
      console.error(error);
    }
  });

  els.safeSearch.addEventListener("input", renderSafeFeed);
  els.threatSearch.addEventListener("input", renderThreatFeed);

  els.safeFeed.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-delete]");
    if (!button) return;
    const id = button.dataset.delete;
    if (!window.confirm("Delete this email from Gmail?")) return;
    try {
      await deleteEmail(id);
      state.safeEmails = state.safeEmails.filter((email) => email.id !== id);
      state.evaluations.delete(id);
      updateMetrics();
      renderSafeFeed();
      showToast("Email deleted");
    } catch (error) {
      showToast("Delete failed");
      console.error(error);
    }
  });

  els.threatFeed.addEventListener("click", async (event) => {
    const scam = event.target.closest("[data-label-scam]");
    const legit = event.target.closest("[data-label-legit]");
    const release = event.target.closest("[data-release]");
    try {
      if (scam) {
        await labelThreat(scam.dataset.labelScam, 1);
        showToast("Marked as scam");
      } else if (legit) {
        await labelThreat(legit.dataset.labelLegit, 0);
        await releaseThreat(legit.dataset.labelLegit);
        showToast("Released as legitimate");
      } else if (release) {
        await releaseThreat(release.dataset.release);
        showToast("Released from quarantine");
      } else {
        return;
      }
      await loadThreatQueue();
    } catch (error) {
      showToast("Threat action failed");
      console.error(error);
    }
  });

}

async function boot() {
  bindEvents();
  renderSafeFeed();
  renderThreatFeed();
  renderLinkOutput(null);
  await Promise.all([loadEmailHealth(), loadThreatQueue()]);
}

boot();
