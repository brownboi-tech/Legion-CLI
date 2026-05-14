from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable, Any


class JobQueue:
    def __init__(self, max_workers: int = 4):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def submit(self, fn: Callable[..., Any], *args, **kwargs) -> Future:
        return self._executor.submit(fn, *args, **kwargs)

    def shutdown(self, wait: bool = False):
        self._executor.shutdown(wait=wait)
