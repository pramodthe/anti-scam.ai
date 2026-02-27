import json
from pathlib import Path
from threading import RLock

from backend.app.schemas import QuarantineRecord


class QuarantineStore:
    def __init__(self, quarantine_path: str, feedback_path: str) -> None:
        self.quarantine_path = Path(quarantine_path)
        self.feedback_path = Path(feedback_path)
        self._lock = RLock()
        self._records: dict[str, QuarantineRecord] = {}

        self.quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_quarantine_state()

    def _load_quarantine_state(self) -> None:
        if not self.quarantine_path.exists():
            return

        with self.quarantine_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                try:
                    record = QuarantineRecord.model_validate(json.loads(payload))
                except Exception:
                    continue
                self._records[record.id] = record

    def _append_jsonl(self, path: Path, payload: dict) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def get(self, message_id: str) -> QuarantineRecord | None:
        with self._lock:
            return self._records.get(message_id)

    def list(self, include_released: bool = False) -> list[QuarantineRecord]:
        with self._lock:
            items = list(self._records.values())
            if not include_released:
                items = [record for record in items if record.status != "released"]
            return sorted(items, key=lambda rec: rec.updated_at, reverse=True)

    def upsert(self, record: QuarantineRecord) -> QuarantineRecord:
        with self._lock:
            self._records[record.id] = record
            self._append_jsonl(self.quarantine_path, record.model_dump())
            return record

    def append_feedback(self, payload: dict) -> None:
        with self._lock:
            self._append_jsonl(self.feedback_path, payload)

