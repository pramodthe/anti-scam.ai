"""Standalone Voice Threat Monitor API — powered by Modulate Velma-2.

This is a separate FastAPI application from the email risk API.
It runs on its own port and has no dependency on Gmail or email risk features.
"""

import asyncio
import json
import logging
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Load .env from project root before any from_env() calls
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from backend.app.modulate_client import ModulateBatchClient, ModulateStreamClient
from backend.app.voice_risk_analyzer import VoiceRiskAnalyzer
from backend.app.voice_schemas import VoiceAnalysisResult, WSMessage

logger = logging.getLogger(__name__)

app = FastAPI(title="Voice Threat Monitor API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

modulate_stream = ModulateStreamClient.from_env()
modulate_batch = ModulateBatchClient.from_env()


@app.get("/health")
def health() -> dict[str, str | bool]:
    """Health check with Modulate configuration status."""
    return {
        "status": "ok",
        "modulate_streaming_configured": modulate_stream.configured,
        "modulate_batch_configured": modulate_batch.configured,
    }


@app.websocket("/ws/voice")
async def voice_stream(ws: WebSocket) -> None:
    """Real-time voice threat monitoring via Modulate Velma-2 Streaming.

    Client protocol:
        - Send binary frames: PCM 16-bit 16kHz mono audio chunks
        - Receive JSON messages: WSMessage envelopes
          {type: "utterance"|"alert"|"risk_update"|"session_summary"|"error"|"connected", data: {...}}
    """
    await ws.accept()

    if not modulate_stream.configured:
        await ws.send_text(WSMessage(
            type="error",
            data={"detail": "MODULATE_API_KEY not configured on server"},
        ).model_dump_json())
        await ws.close(code=1008, reason="MODULATE_API_KEY not configured")
        return

    analyzer = VoiceRiskAnalyzer()

    try:
        async with modulate_stream.connect() as session:
            await ws.send_text(WSMessage(
                type="connected",
                data={"message": "Connected to Velma-2 streaming"},
            ).model_dump_json())

            async def forward_audio() -> None:
                """Receive audio from browser WebSocket, forward to Velma-2."""
                try:
                    while True:
                        data = await ws.receive()
                        if data.get("type") == "websocket.disconnect":
                            break
                        if "bytes" in data and data["bytes"]:
                            await session.send_audio(data["bytes"])
                        elif "text" in data and data["text"]:
                            msg = json.loads(data["text"])
                            if msg.get("type") == "stop":
                                break
                except WebSocketDisconnect:
                    pass
                finally:
                    await session.send_eos()

            async def process_transcripts() -> None:
                """Receive utterances from Velma-2, analyze, send back to client."""
                try:
                    async for utt in session.receive():
                        risk_update = analyzer.process_utterance(utt)

                        await ws.send_text(WSMessage(
                            type="utterance",
                            data={
                                "utterance_uuid": utt.utterance_uuid,
                                "text": utt.text,
                                "speaker": utt.speaker,
                                "emotion": utt.emotion,
                                "accent": utt.accent,
                                "start_ms": utt.start_ms,
                                "duration_ms": utt.duration_ms,
                                "language": utt.language,
                            },
                        ).model_dump_json())

                        for alert in risk_update.alerts:
                            await ws.send_text(WSMessage(
                                type="alert",
                                data=alert.model_dump(),
                            ).model_dump_json())

                        await ws.send_text(WSMessage(
                            type="risk_update",
                            data=risk_update.model_dump(),
                        ).model_dump_json())
                except Exception as exc:
                    logger.error("Error processing Velma-2 transcripts: %s", exc)

            audio_task = asyncio.create_task(forward_audio())
            transcript_task = asyncio.create_task(process_transcripts())

            await audio_task
            try:
                await asyncio.wait_for(transcript_task, timeout=5.0)
            except asyncio.TimeoutError:
                transcript_task.cancel()

    except WebSocketDisconnect:
        logger.info("Voice WebSocket client disconnected")
    except Exception as exc:
        logger.error("Voice WebSocket error: %s", exc)
        try:
            await ws.send_text(WSMessage(
                type="error",
                data={"detail": str(exc)},
            ).model_dump_json())
        except Exception:
            pass

    # Send session summary before closing
    try:
        summary = analyzer.get_session_summary()
        await ws.send_text(WSMessage(
            type="session_summary",
            data=summary,
        ).model_dump_json())
    except Exception:
        pass


@app.post("/voice/analyze", response_model=VoiceAnalysisResult)
async def analyze_voice(file: UploadFile) -> VoiceAnalysisResult:
    """Batch voice analysis — upload an audio file for transcription + risk scoring."""
    if not modulate_batch.configured:
        raise HTTPException(status_code=503, detail="MODULATE_API_KEY not configured")

    try:
        audio_bytes = await file.read()
        filename = file.filename or "audio.wav"

        result = await modulate_batch.transcribe(
            audio_bytes=audio_bytes,
            filename=filename,
            speaker_diarization=True,
            emotion_signal=True,
        )

        if result.error:
            raise HTTPException(status_code=502, detail=f"Modulate API error: {result.error}")

        analyzer = VoiceRiskAnalyzer()
        analysis = analyzer.analyze_full(
            transcript_text=result.text,
            utterances=result.utterances,
            duration_ms=result.duration_ms,
        )
        return analysis

    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to analyze voice: {exc}") from exc
