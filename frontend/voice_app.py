"""Standalone Voice Threat Monitor UI — powered by Modulate Velma-2.

Separate Streamlit app from the email risk UI.
Connects to the voice API server (default: http://127.0.0.1:8100).
"""

import os
from pathlib import Path

import requests
import streamlit as st
import streamlit.components.v1 as components
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

VOICE_API = os.getenv("VOICE_API_URL", "http://127.0.0.1:8100")

# ── Page config ─────────────────────────────────────────────────────────

st.set_page_config(page_title="Voice Threat Monitor", page_icon="🎙️", layout="wide")
st.title("🎙️ Voice Threat Monitor")
st.caption(
    "Real-time voice analysis powered by Modulate Velma-2 — detects phishing, "
    "scam patterns, PII leaks, and social engineering in live speech."
)

# ── Health check ────────────────────────────────────────────────────────

try:
    health = requests.get(f"{VOICE_API}/health", timeout=5).json()
    streaming_ok = health.get("modulate_streaming_configured", False)
    batch_ok = health.get("modulate_batch_configured", False)
    if streaming_ok:
        st.success("Modulate API connected — streaming + batch ready")
    else:
        st.warning("MODULATE_API_KEY not configured — set it in .env to enable voice analysis")
except requests.RequestException:
    streaming_ok = False
    batch_ok = False
    st.error("Voice API unreachable — make sure the voice server is running on " + VOICE_API)

# ── Real-time streaming ────────────────────────────────────────────────

st.markdown("---")
st.subheader("Live Microphone Monitor")
st.caption("Click **Start Listening** to capture microphone audio and stream it to Velma-2 for real-time analysis.")

WS_URL = VOICE_API.replace("http://", "ws://").replace("https://", "wss://") + "/ws/voice"

VOICE_HTML = """
<style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .vm-container { max-width: 100%; padding: 0; }
    .vm-controls { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; }
    .vm-btn { padding: 10px 24px; border: none; border-radius: 8px; font-size: 14px; font-weight: 600;
               cursor: pointer; transition: all 0.2s; }
    .vm-btn-start { background: #22c55e; color: white; }
    .vm-btn-start:hover { background: #16a34a; }
    .vm-btn-stop { background: #ef4444; color: white; }
    .vm-btn-stop:hover { background: #dc2626; }
    .vm-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .vm-status { font-size: 13px; color: #666; }
    .vm-risk-bar { height: 36px; border-radius: 8px; background: #e5e7eb; overflow: hidden; margin-bottom: 16px; position: relative; }
    .vm-risk-fill { height: 100%; transition: width 0.3s, background 0.3s; border-radius: 8px; }
    .vm-risk-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                      font-weight: 700; font-size: 14px; color: #1f2937; text-shadow: 0 0 4px rgba(255,255,255,0.8); }
    .vm-panel { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 12px;
                max-height: 320px; overflow-y: auto; background: #fafafa; }
    .vm-panel h4 { margin: 0 0 8px; font-size: 13px; color: #374151; }
    .vm-utterance { padding: 6px 0; border-bottom: 1px solid #f3f4f6; font-size: 13px; line-height: 1.5; }
    .vm-utterance:last-child { border-bottom: none; }
    .vm-speaker { font-weight: 600; color: #6366f1; }
    .vm-emotion { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; margin-left: 6px; }
    .vm-emotion-neutral { background: #e5e7eb; color: #374151; }
    .vm-emotion-high { background: #fecaca; color: #991b1b; }
    .vm-emotion-moderate { background: #fed7aa; color: #9a3412; }
    .vm-alert { padding: 8px 12px; border-radius: 6px; margin-bottom: 6px; font-size: 12px; }
    .vm-alert-pii { background: #fecaca; border-left: 3px solid #ef4444; }
    .vm-alert-emotion { background: #fed7aa; border-left: 3px solid #f97316; }
    .vm-alert-scam { background: #fef08a; border-left: 3px solid #eab308; }
    .vm-alert-urgency { background: #e0e7ff; border-left: 3px solid #6366f1; }
    .vm-summary { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; margin-top: 12px; display: none; }
    .vm-summary.active { display: block; }
    .vm-summary h4 { color: #166534; margin: 0 0 8px; }
</style>
<div class="vm-container">
    <div class="vm-controls">
        <button id="vmStart" class="vm-btn vm-btn-start" onclick="startListening()">Start Listening</button>
        <button id="vmStop" class="vm-btn vm-btn-stop" onclick="stopListening()" disabled>Stop</button>
        <span id="vmStatus" class="vm-status">Ready</span>
    </div>

    <div class="vm-risk-bar">
        <div id="vmRiskFill" class="vm-risk-fill" style="width: 0%; background: #22c55e;"></div>
        <div id="vmRiskLabel" class="vm-risk-label">Risk: 0%</div>
    </div>

    <div class="vm-panel" id="vmTranscript">
        <h4>Live Transcript</h4>
        <div id="vmTranscriptContent"><em style="color:#9ca3af;">Waiting for audio...</em></div>
    </div>

    <div class="vm-panel" id="vmAlerts">
        <h4>Alerts</h4>
        <div id="vmAlertsContent"><em style="color:#9ca3af;">No alerts yet</em></div>
    </div>

    <div id="vmSummary" class="vm-summary">
        <h4>Session Summary</h4>
        <div id="vmSummaryContent"></div>
    </div>
</div>

<script>
let ws = null;
let mediaStream = null;
let audioContext = null;
let processor = null;
let firstUtterance = true;
let firstAlert = true;

const WS_URL = "__WS_URL__";

function riskColor(score) {
    if (score < 0.3) return '#22c55e';
    if (score < 0.65) return '#eab308';
    if (score < 0.85) return '#f97316';
    return '#ef4444';
}

function emotionClass(emotion) {
    const e = (emotion || '').toLowerCase();
    const high = ['angry', 'fearful', 'urgent', 'aggressive', 'distressed'];
    const moderate = ['anxious', 'frustrated', 'nervous', 'sad'];
    if (high.includes(e)) return 'vm-emotion-high';
    if (moderate.includes(e)) return 'vm-emotion-moderate';
    return 'vm-emotion-neutral';
}

function alertClass(type) {
    if (type === 'pii') return 'vm-alert-pii';
    if (type === 'emotion') return 'vm-alert-emotion';
    if (type === 'urgency') return 'vm-alert-urgency';
    return 'vm-alert-scam';
}

async function startListening() {
    firstUtterance = true;
    firstAlert = true;
    document.getElementById('vmTranscriptContent').innerHTML = '';
    document.getElementById('vmAlertsContent').innerHTML = '';
    document.getElementById('vmSummary').classList.remove('active');
    document.getElementById('vmRiskFill').style.width = '0%';
    document.getElementById('vmRiskFill').style.background = '#22c55e';
    document.getElementById('vmRiskLabel').textContent = 'Risk: 0%';

    try {
        mediaStream = await navigator.mediaDevices.getUserMedia({
            audio: { channelCount: 1, sampleRate: 16000 }
        });
    } catch (e) {
        document.getElementById('vmStatus').textContent = 'Microphone access denied';
        return;
    }

    ws = new WebSocket(WS_URL);
    ws.binaryType = 'arraybuffer';

    ws.onopen = () => {
        document.getElementById('vmStatus').textContent = 'Connecting to Velma-2...';
        document.getElementById('vmStart').disabled = true;
        document.getElementById('vmStop').disabled = false;
    };

    ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        handleMessage(msg);
    };

    ws.onclose = () => {
        document.getElementById('vmStatus').textContent = 'Disconnected';
        document.getElementById('vmStart').disabled = false;
        document.getElementById('vmStop').disabled = true;
        cleanup();
    };

    ws.onerror = () => {
        document.getElementById('vmStatus').textContent = 'Connection error';
    };

    audioContext = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 16000 });
    const source = audioContext.createMediaStreamSource(mediaStream);
    processor = audioContext.createScriptProcessor(4096, 1, 1);

    processor.onaudioprocess = (e) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            const float32 = e.inputBuffer.getChannelData(0);
            const int16 = new Int16Array(float32.length);
            for (let i = 0; i < float32.length; i++) {
                int16[i] = Math.max(-32768, Math.min(32767, Math.round(float32[i] * 32767)));
            }
            ws.send(int16.buffer);
        }
    };

    source.connect(processor);
    processor.connect(audioContext.destination);
}

function handleMessage(msg) {
    if (msg.type === 'connected') {
        document.getElementById('vmStatus').textContent = 'Listening — speak now...';
        return;
    }

    if (msg.type === 'utterance') {
        const d = msg.data;
        if (firstUtterance) {
            document.getElementById('vmTranscriptContent').innerHTML = '';
            firstUtterance = false;
        }
        const emCls = emotionClass(d.emotion);
        const html = `<div class="vm-utterance">
            <span class="vm-speaker">Speaker ${d.speaker}:</span> ${escapeHtml(d.text)}
            <span class="vm-emotion ${emCls}">${escapeHtml(d.emotion || 'neutral')}</span>
        </div>`;
        document.getElementById('vmTranscriptContent').insertAdjacentHTML('beforeend', html);
        const panel = document.getElementById('vmTranscript');
        panel.scrollTop = panel.scrollHeight;
    }

    if (msg.type === 'alert') {
        const d = msg.data;
        if (firstAlert) {
            document.getElementById('vmAlertsContent').innerHTML = '';
            firstAlert = false;
        }
        const cls = alertClass(d.signal_type);
        const html = `<div class="vm-alert ${cls}">
            <strong>${escapeHtml(d.signal_type.toUpperCase())}</strong> — ${escapeHtml(d.detail)}
            (severity: ${(d.severity * 100).toFixed(0)}%)
        </div>`;
        document.getElementById('vmAlertsContent').insertAdjacentHTML('beforeend', html);
    }

    if (msg.type === 'risk_update') {
        const score = msg.data.risk_score || 0;
        const pct = (score * 100).toFixed(0);
        const decision = msg.data.decision || 'safe';
        document.getElementById('vmRiskFill').style.width = pct + '%';
        document.getElementById('vmRiskFill').style.background = riskColor(score);
        document.getElementById('vmRiskLabel').textContent = `Risk: ${pct}% — ${decision.toUpperCase()}`;
    }

    if (msg.type === 'session_summary') {
        const d = msg.data;
        const summaryDiv = document.getElementById('vmSummary');
        summaryDiv.classList.add('active');
        document.getElementById('vmSummaryContent').innerHTML = `
            <p><strong>Duration:</strong> ${((d.session_duration_ms || 0)/1000).toFixed(1)}s
               | <strong>Utterances:</strong> ${d.total_utterances || 0}
               | <strong>Speakers:</strong> ${d.speaker_count || 0}</p>
            <p><strong>Final Risk:</strong> ${((d.risk_score || 0)*100).toFixed(0)}% — ${(d.decision||'safe').toUpperCase()}</p>
            <p><strong>Reasons:</strong> ${(d.risk_reasons||[]).join(', ') || 'None'}</p>
            <p><strong>Emotions:</strong> ${(d.emotions_detected||[]).join(', ') || 'None'}</p>
        `;
    }

    if (msg.type === 'error') {
        document.getElementById('vmStatus').textContent = 'Error: ' + (msg.data.detail || 'Unknown');
    }
}

function stopListening() {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'stop' }));
        document.getElementById('vmStatus').textContent = 'Stopping...';
    }
    setTimeout(() => {
        if (ws) ws.close();
        cleanup();
    }, 2000);
}

function cleanup() {
    if (processor) { processor.disconnect(); processor = null; }
    if (audioContext) { audioContext.close(); audioContext = null; }
    if (mediaStream) { mediaStream.getTracks().forEach(t => t.stop()); mediaStream = null; }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}
</script>
""".replace("__WS_URL__", WS_URL)

components.html(VOICE_HTML, height=680, scrolling=True)

# ── Batch analysis ──────────────────────────────────────────────────────

st.markdown("---")
st.subheader("Batch Audio Analysis")
st.caption("Upload an audio clip for offline analysis via Velma-2 Batch API.")

audio_file = st.file_uploader(
    "Upload audio file (MP3, WAV, OGG, FLAC, MP4, WebM)",
    type=["mp3", "wav", "ogg", "flac", "mp4", "webm"],
    key="voice_upload",
)

if audio_file is not None:
    st.audio(audio_file)
    if st.button("Analyze Recording", key="analyze_voice_btn"):
        if not batch_ok:
            st.error("MODULATE_API_KEY not configured — cannot run batch analysis.")
        else:
            with st.spinner("Sending to Velma-2 Batch API..."):
                try:
                    resp = requests.post(
                        f"{VOICE_API}/voice/analyze",
                        files={"file": (audio_file.name, audio_file.getvalue(), audio_file.type)},
                        timeout=120,
                    )
                    resp.raise_for_status()
                    result = resp.json()

                    score = float(result.get("risk_score", 0))
                    decision = result.get("decision", "safe")
                    color = "#22c55e" if decision == "safe" else "#f97316" if decision == "suspicious" else "#ef4444"

                    st.markdown(
                        f"**Risk Score:** <span style='color:{color};font-size:20px;font-weight:700;'>"
                        f"{score:.0%} — {decision.upper()}</span>",
                        unsafe_allow_html=True,
                    )

                    if result.get("risk_reasons"):
                        st.write("**Risk Reasons:**")
                        for r in result["risk_reasons"]:
                            st.write(f"- {r}")

                    if result.get("transcript_text"):
                        with st.expander("Full Transcript", expanded=True):
                            st.write(result["transcript_text"])

                    if result.get("utterances"):
                        with st.expander("Utterance Details", expanded=False):
                            for utt in result["utterances"]:
                                st.write(
                                    f"**Speaker {utt.get('speaker', 0)}:** {utt.get('text', '')} "
                                    f"| emotion={utt.get('emotion', 'neutral')} "
                                    f"| accent={utt.get('accent', 'N/A')}"
                                )

                    if result.get("alerts"):
                        with st.expander("Alerts", expanded=True):
                            for alert in result["alerts"]:
                                st.warning(
                                    f"**{alert.get('signal_type', '').upper()}** — "
                                    f"{alert.get('detail', '')} (severity: {alert.get('severity', 0):.0%})"
                                )

                    st.json(result)

                except requests.RequestException as exc:
                    st.error(f"Batch analysis failed: {exc}")
