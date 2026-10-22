"""One harmless question, as fast as each simulated user can send it.

Run by the load workflow through the gated proxy. It is outside src/ and tests/, so
mypy does not check it: Locust is installed in its own environment, not in uv.lock.
"""

from locust import HttpUser, constant, task


class AskUser(HttpUser):
    wait_time = constant(0)

    @task
    def ask(self) -> None:
        self.client.post("/query", json={"question": "What is the refund policy?"})
