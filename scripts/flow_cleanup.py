import time
from mitmproxy import ctx


CLEAR_INTERVAL = 300  # 5 minutes


class FlowCleanup:
    def __init__(self):
        self.last_clear = time.time()

    def response(self, flow):
        now = time.time()

        if now - self.last_clear < CLEAR_INTERVAL:
            return

        self.last_clear = now

        try:
            ctx.master.commands.call("view.clear")
            ctx.log.info("Flow view cleared.")

        except Exception as e:
            ctx.log.error(f"Flow clear failed: {e}")


addons = [
    FlowCleanup()
]
