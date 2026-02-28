"""Client for the Modulate Velma-2 Speech-to-Text APIs.

Streaming: Velma-2 STT Streaming via WebSocket
Batch:     Velma-2 STT Batch via REST

Follows the same client-class pattern used by YutoriBrowserClient.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

import httpx
import websockets
import websockets.asyncio.client

logger = logging.getLogger(__name__)


# ── Data containers ─────────────────────────────────────────────────────


@dataclass
class ModulateUtterance:
    """Parsed utterance from a Velma-2 response."""

    utterance_uuid: str = ""
    text: str = ""
    speaker: int = 0
    emotion: str = "neutral"
    accent: str | None = None
    start_ms: int = 0
    duration_ms: int = 0
    language: str = "en"


@dataclass
class ModulateTranscriptResult:
    """Full result from a batch transcription call."""

    text: str = ""
    duration_ms: int = 0
    utterances: list[ModulateUtterance] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


# ── Streaming client ────────────────────────────────────────────────────


class ModulateStreamClient:
    """Async WebSocket client for Velma-2 STT Streaming.

    Usage::

        client = ModulateStreamClient.from_env()
        async with client.connect() as session:
            await session.send_audio(chunk)
            async for utterance in session.receive():
                print(utterance.text)
    """

    def __init__(
        self,
        api_key: str,
        ws_url: str = "wss://modulate-developer-apis.com/api/velma-2-stt-streaming",
    ) -> None:
        self.api_key = api_key
        self.ws_url = ws_url

    @classmethod
    def from_env(cls) -> ModulateStreamClient:
        api_key = os.getenv("MODULATE_API_KEY", "")
        ws_url = os.getenv(
            "MODULATE_WS_URL",
            "wss://modulate-developer-apis.com/api/velma-2-stt-streaming",
        )
        return cls(api_key=api_key, ws_url=ws_url)

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def connect(self) -> _StreamSession:
        """Return a context-managed streaming session."""
        return _StreamSession(api_key=self.api_key, ws_url=self.ws_url)


class _StreamSession:
    """Async context manager wrapping a single WebSocket session to Velma-2."""

    def __init__(self, api_key: str, ws_url: str) -> None:
        self._api_key = api_key
        self._ws_url = ws_url
        self._ws: websockets.asyncio.client.ClientConnection | None = None

    async def __aenter__(self) -> _StreamSession:
        url = f"{self._ws_url}?api_key={self._api_key}"
        self._ws = await websockets.asyncio.client.connect(url)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    async def send_audio(self, chunk: bytes) -> None:
        """Send a binary audio frame to Velma-2."""
        if self._ws is None:
            raise RuntimeError("Session not connected")
        await self._ws.send(chunk)

    async def send_eos(self) -> None:
        """Signal end-of-stream so Velma-2 flushes final utterances."""
        if self._ws is None:
            return
        try:
            await self._ws.send(json.dumps({"type": "eos"}))
        except Exception:
            pass

    async def receive(self) -> AsyncIterator[ModulateUtterance]:
        """Yield parsed utterances as they arrive from Velma-2."""
        if self._ws is None:
            raise RuntimeError("Session not connected")
        try:
            async for raw_msg in self._ws:
                if isinstance(raw_msg, bytes):
                    continue
                try:
                    data = json.loads(raw_msg)
                except json.JSONDecodeError:
                    logger.warning("Non-JSON message from Velma-2: %s", raw_msg[:200])
                    continue

                # Velma-2 may send either a single utterance or a list of utterances
                utterances_data = data.get("utterances", [])
                if not utterances_data and "text" in data:
                    utterances_data = [data]

                for utt in utterances_data:
                    yield ModulateUtterance(
                        utterance_uuid=str(utt.get("utterance_uuid", "")),
                        text=str(utt.get("text", "")),
                        speaker=int(utt.get("speaker", 0)),
                        emotion=str(utt.get("emotion", "neutral")),
                        accent=utt.get("accent"),
                        start_ms=int(utt.get("start_ms", 0)),
                        duration_ms=int(utt.get("duration_ms", 0)),
                        language=str(utt.get("language", "en")),
                    )
        except websockets.exceptions.ConnectionClosed:
            logger.info("Velma-2 WebSocket connection closed")
        except Exception as exc:
            logger.error("Error receiving from Velma-2: %s", exc)

    async def close(self) -> None:
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None


# ── Batch client ────────────────────────────────────────────────────────


class ModulateBatchClient:
    """Sync/async REST client for Velma-2 STT Batch.

    Usage::

        client = ModulateBatchClient.from_env()
        result = await client.transcribe(audio_bytes, "recording.mp3")
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://modulate-developer-apis.com",
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    @classmethod
    def from_env(cls) -> ModulateBatchClient:
        api_key = os.getenv("MODULATE_API_KEY", "")
        base_url = os.getenv("MODULATE_BASE_URL", "https://modulate-developer-apis.com")
        return cls(api_key=api_key, base_url=base_url)

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    async def transcribe(
        self,
        audio_bytes: bytes,
        filename: str = "audio.wav",
        speaker_diarization: bool = True,
        emotion_signal: bool = True,
    ) -> ModulateTranscriptResult:
        """Send audio to Velma-2 Batch and return the parsed result."""
        if not self.api_key:
            return ModulateTranscriptResult(error="MODULATE_API_KEY not configured")

        url = f"{self.base_url}/api/velma-2-stt-batch"
        headers = {"X-API-Key": self.api_key}
        files = {"upload_file": (filename, audio_bytes)}
        form_data = {
            "speaker_diarization": str(speaker_diarization).lower(),
            "emotion_signal": str(emotion_signal).lower(),
        }

        try:
            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(url, headers=headers, files=files, data=form_data)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            return ModulateTranscriptResult(
                error=f"Modulate API error {exc.response.status_code}: {exc.response.text[:500]}",
                raw={"status_code": exc.response.status_code},
            )
        except Exception as exc:
            return ModulateTranscriptResult(error=f"Modulate API request failed: {exc}")

        utterances = [
            ModulateUtterance(
                utterance_uuid=str(u.get("utterance_uuid", "")),
                text=str(u.get("text", "")),
                speaker=int(u.get("speaker", 0)),
                emotion=str(u.get("emotion", "neutral")),
                accent=u.get("accent"),
                start_ms=int(u.get("start_ms", 0)),
                duration_ms=int(u.get("duration_ms", 0)),
                language=str(u.get("language", "en")),
            )
            for u in data.get("utterances", [])
        ]

        return ModulateTranscriptResult(
            text=str(data.get("text", "")),
            duration_ms=int(data.get("duration_ms", 0)),
            utterances=utterances,
            raw=data,
        )
