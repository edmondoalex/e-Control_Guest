from __future__ import annotations

import asyncio
import signal

import uvicorn

from .admin_api import create_admin_app
from .guest_api import create_guest_app
from .runtime import build_runtime


async def main() -> None:
    runtime = build_runtime()
    admin = uvicorn.Server(uvicorn.Config(create_admin_app(runtime), host="0.0.0.0",
                                         port=runtime.settings.admin_port, access_log=False,
                                         proxy_headers=False))
    guest = uvicorn.Server(uvicorn.Config(create_guest_app(runtime), host="0.0.0.0",
                                         port=runtime.settings.guest_port, access_log=False,
                                         proxy_headers=False))
    admin.install_signal_handlers = lambda: None
    guest.install_signal_handlers = lambda: None
    loop = asyncio.get_running_loop()

    def stop() -> None:
        admin.should_exit = True
        guest.should_exit = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop)
        except NotImplementedError:
            pass
    await asyncio.gather(admin.serve(), guest.serve())


if __name__ == "__main__":
    asyncio.run(main())
