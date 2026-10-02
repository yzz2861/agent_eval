from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..subprocess import DEFAULT_SUBPROCESS_TIME_LIMIT
from .middleware import Middleware

if TYPE_CHECKING:
    from ..actor import Actor
    from ..broker import MessageProxy


class Subprocess(Middleware):
    """Configures actors that must execute in isolated worker subprocesses."""

    def __init__(self, *, default_time_limit: Optional[float] = DEFAULT_SUBPROCESS_TIME_LIMIT) -> None:
        self.default_time_limit = default_time_limit

    @property
    def actor_options(self) -> set[str]:
        return {"subprocess", "subprocess_time_limit"}

    def get_time_limit(self, actor: "Actor", message: "MessageProxy") -> Optional[float]:
        return (
            message.options.get("subprocess_time_limit")
            or message.options.get("time_limit")
            or actor.options.get("subprocess_time_limit")
            or actor.options.get("time_limit")
            or self.default_time_limit
        )
