"""APIGuard — Baseline recorder (normal response times, status, size)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class EndpointBaseline:
    path: str
    method: str
    status_codes: List[int] = field(default_factory=list)
    response_times: List[float] = field(default_factory=list)
    body_sizes: List[int] = field(default_factory=list)
    content_type: str = ""

    @property
    def avg_time(self) -> float:
        return sum(self.response_times) / len(self.response_times) if self.response_times else 0

    @property
    def max_time(self) -> float:
        return max(self.response_times) if self.response_times else 0

    @property
    def min_time(self) -> float:
        return min(self.response_times) if self.response_times else 0

    @property
    def typical_status(self) -> int:
        return max(set(self.status_codes), key=self.status_codes.count) if self.status_codes else 0

    @property
    def typical_size(self) -> int:
        return max(set(self.body_sizes), key=self.body_sizes.count) if self.body_sizes else 0

    def is_anomalous(self, status: int, time_sec: float, size: int) -> Tuple[bool, List[str]]:
        """Check if a response deviates significantly from baseline."""
        flags: List[str] = []
        if self.typical_status and status != self.typical_status:
            flags.append(f"status:{self.typical_status}->{status}")
        if self.avg_time and time_sec > self.avg_time * 3 and time_sec > 1.0:
            flags.append(f"slow:{self.avg_time:.2f}s->{time_sec:.2f}s")
        if self.avg_time and time_sec < self.avg_time * 0.1 and self.avg_time > 0.5:
            flags.append(f"fast:{self.avg_time:.2f}s->{time_sec:.2f}s")
        if self.typical_size and size > self.typical_size * 5 and size > 5000:
            flags.append(f"large:{self.typical_size}->{size}")
        if self.typical_size and size < self.typical_size * 0.1 and self.typical_size > 1000:
            flags.append(f"small:{self.typical_size}->{size}")
        return bool(flags), flags


class BaselineTracker:
    """Tracks baselines per endpoint/method combo."""

    def __init__(self) -> None:
        self._baselines: Dict[str, EndpointBaseline] = {}

    def _key(self, method: str, path: str) -> str:
        return f"{method}:{path}"

    def record(self, method: str, path: str, status: int, time_sec: float, size: int, content_type: str = "") -> None:
        k = self._key(method, path)
        if k not in self._baselines:
            self._baselines[k] = EndpointBaseline(path=path, method=method, content_type=content_type)
        bl = self._baselines[k]
        bl.status_codes.append(status)
        bl.response_times.append(time_sec)
        bl.body_sizes.append(size)
        bl.content_type = content_type

    def get(self, method: str, path: str) -> Optional[EndpointBaseline]:
        return self._baselines.get(self._key(method, path))

    def check(self, method: str, path: str, status: int, time_sec: float, size: int) -> Tuple[bool, List[str]]:
        bl = self.get(method, path)
        if bl is None:
            return False, []
        return bl.is_anomalous(status, time_sec, size)
