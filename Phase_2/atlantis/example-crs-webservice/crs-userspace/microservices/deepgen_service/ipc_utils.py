import asyncio
import uuid
import zmq
import zmq.asyncio
import logging
from abc import abstractmethod
from typing import Dict

class TaskContext:
    @abstractmethod
    async def on_task(self, task: dict):
        pass

class SyncSender:
    def __init__(self, task_addr: str, ack_addr: str,
                 timeout: float = 5.0, max_retries: int = 10):
        self.ctx = zmq.Context()
        self.task_sock = self.ctx.socket(zmq.PUSH)
        self.task_sock.connect(task_addr)

        self.ack_sock = self.ctx.socket(zmq.PULL)
        self.ack_sock.bind(ack_addr)

        self.timeout_ms = int(timeout * 1000)
        self.max_retries = max_retries

        self.poller = zmq.Poller()
        self.poller.register(self.ack_sock, zmq.POLLIN)

    def send(self, payload: Dict) -> bool:
        task_id = str(uuid.uuid4())
        payload["id"] = task_id

        for attempt in range(1, self.max_retries + 1):
            logging.info(f"[SEND] Attempt {attempt}, task_id={task_id}")
            self.task_sock.send_json(payload)

            socks = dict(self.poller.poll(self.timeout_ms))
            if socks.get(self.ack_sock) == zmq.POLLIN:
                ack = self.ack_sock.recv_json(flags=zmq.NOBLOCK)
                if ack.get("ack") == task_id:
                    logging.info(f"[ACK] Received for task_id={task_id}")
                    return True
                # logging.info(f"[ACK] Mismatch: expected {task_id}, got {ack}")
            else:
                logging.info("[TIMEOUT] No ACK, retrying...")

        # logging.info(f"[FAIL] Task {task_id} failed after {self.max_retries} attempts")
        return False

    def close(self) -> None:
        self.task_sock.close()
        self.ack_sock.close()
        self.ctx.term()

class AsyncSender:
    def __init__(self, task_addr, ack_addr, timeout=5.0, max_retries=10):
        self.ctx = zmq.asyncio.Context()
        self.task_sock = self.ctx.socket(zmq.PUSH)
        self.task_sock.connect(task_addr)

        self.ack_sock = self.ctx.socket(zmq.PULL)
        self.ack_sock.bind(ack_addr)

        self.timeout = timeout
        self.max_retries = max_retries

    async def send(self, payload: dict) -> bool:
        task_id = str(uuid.uuid4())
        payload["id"] = task_id

        for attempt in range(1, self.max_retries + 1):
            logging.info(f"[SEND] Attempt {attempt}, task_id={task_id}")
            await self.task_sock.send_json(payload)

            try:
                ack = await asyncio.wait_for(
                    self.ack_sock.recv_json(), timeout=self.timeout
                )
                if ack.get("ack") == task_id:
                    logging.info(f"[ACK] Received for task_id={task_id}")
                    return True
                else:
                    pass
                    # logging.info(f"[ACK] Mismatch: expected {task_id}, got {ack}")
            except asyncio.TimeoutError:
                logging.info("[TIMEOUT] No ACK, retrying...")

        logging.info(f"[FAIL] Task {task_id} failed after {self.max_retries} attempts")
        return False


class AsyncReceiver:
    def __init__(self, task_addr, ack_addr, context):
        self.ctx = zmq.asyncio.Context()
        self.task_sock = self.ctx.socket(zmq.PULL)
        self.task_sock.bind(task_addr)

        self.ack_sock = self.ctx.socket(zmq.PUSH)
        self.ack_sock.connect(ack_addr)

        self.context = context

    async def _handle_task(self, task: dict):
        """Helper to safely run on_task in the background."""
        try:
            await self.context.on_task(task)
        except Exception as e:
            logging.error(f"Task processing failed for {task.get('id')}: {e}", exc_info=True)

    async def run(self):
        """
        Main loop to receive tasks.
        It ACKs immediately and hands off processing to a background task.
        """
        logging.info("AsyncReceiver is running.")
        min_interval = 0.02
        max_interval = 10
        cur_interval = min_interval
        while True:
            try:
                logging.error(f"enabled_harnesses: {self.context.enabled_harnesses}")
                task = await self.task_sock.recv_json(flags=zmq.NOBLOCK)
                task_id = task.get("id")
                logging.info(f"[RECV] Task: {task}")
                cur_interval = min_interval

                # 1. Acknowledge immediately so the sender doesn't time out.
                await self.ack_sock.send_json({"ack": task_id})
                logging.info(f"[ACK] Sent for task_id={task_id}")

                # 2. Schedule the actual work to run in the background.
                #    This frees the receiver loop to immediately handle the next message.
                asyncio.create_task(self._handle_task(task))
            except zmq.Again:
                cur_interval = min(cur_interval * 2, max_interval)
                await asyncio.sleep(cur_interval)
            except Exception as e:
                logging.error(f"Error receiving message: {e}", exc_info=True)
                await asyncio.sleep(0.01)