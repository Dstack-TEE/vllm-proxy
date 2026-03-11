import os
import time

from app.logger import log

from .local_cache import LocalCache
from .redis import RedisCache

MODEL_NAME = os.getenv("MODEL_NAME", "unknown")
REPLAY_PREFIX = "e2ee_replay"
REPLAY_WINDOW_SECONDS = int(os.getenv("E2EE_REPLAY_WINDOW_SECONDS", "300"))


class ReplayCache:
    """
    Replay protection cache with Redis-first, local fallback behavior.
    """

    def __init__(self, expiration: int = REPLAY_WINDOW_SECONDS) -> None:
        self._expiration = expiration
        self._local = LocalCache(expiration=expiration)
        self._redis = self._init_redis()

    def _init_redis(self):
        if not os.getenv("REDIS_HOST"):
            return None
        return RedisCache(expiration=self._expiration)

    def _make_key(self, signing_algo: str, timestamp: int, nonce: str) -> str:
        return f"{MODEL_NAME}:{REPLAY_PREFIX}:{signing_algo}:{timestamp}:{nonce}"

    def claim(self, signing_algo: str, timestamp: int, nonce: str) -> bool:
        """
        Claim a nonce+timestamp tuple.
        Returns True if first-seen, False if replayed.
        """
        key = self._make_key(signing_algo, timestamp, nonce)

        if self._redis:
            try:
                if self._redis.set_if_absent(key, "1", expiration=self._expiration):
                    return True
                return False
            except Exception as exc:
                log.warning("Replay Redis claim failed for %s: %s", key, exc)

        if self._local.get(key):
            return False

        self._local.set(key, "1")
        return True

    def validate_timestamp_window(self, timestamp: int) -> bool:
        now = int(time.time())
        return abs(now - timestamp) <= self._expiration


replay_cache = ReplayCache()
