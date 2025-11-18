#!/usr/bin/env python3
"""
Example of running the dealer using multiprocessing.Process
"""

import multiprocessing
import asyncio
import signal
import sys
import time
import logging
from typing import Optional, Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from .dealer import Dealer
except ImportError:
    logger.error("Failed to import Dealer. Make sure the dealer module is available.")
    raise


def run_dealer_process(
    router_addr: str, harness: str, dealer_id: str, stop_event: multiprocessing.Event
):
    """Function to run in the dealer process"""

    async def _run_dealer():
        # Create dealer instance
        dealer = Dealer(router_addr, harness, dealer_id)

        # Create a task to monitor the stop event
        async def monitor_stop():
            while not stop_event.is_set():
                await asyncio.sleep(0.5)
            # Signal the dealer to stop
            raise KeyboardInterrupt("Stop event set")

        # Run dealer with stop monitoring
        monitor_task = asyncio.create_task(monitor_stop())
        try:
            await dealer.run()
        except KeyboardInterrupt:
            logger.info(f"Dealer {dealer_id} stopping...")
        finally:
            monitor_task.cancel()

    # Run the async function
    try:
        asyncio.run(_run_dealer())
    except Exception as e:
        logger.error(f"Dealer {dealer_id} error: {e}")


class DealerManager:
    """Manages multiple dealer processes"""

    def __init__(self, router_addr: str = "ipc:///tmp/ipc/haha"):
        self.router_addr = router_addr
        # Changed to store lists of processes per harness
        self.processes: Dict[str, List[Tuple[str, multiprocessing.Process]]] = {}
        self.stop_events: Dict[str, List[Tuple[str, multiprocessing.Event]]] = {}

    def start_dealer(
        self, harness: str, dealer_id: Optional[str] = None
    ) -> multiprocessing.Process:
        """Start a single dealer process"""
        if dealer_id is None:
            # Generate unique dealer_id based on existing dealers for this harness
            existing_count = len(self.processes.get(harness, []))
            dealer_id = f"{harness}-dealer-{existing_count}"

        # Check if this specific dealer_id already exists
        if harness in self.processes:
            for did, proc in self.processes[harness]:
                if did == dealer_id and proc.is_alive():
                    logger.info(
                        f"Dealer {dealer_id} for harness {harness} already running, skipping"
                    )
                    return proc

        # Create stop event for this process
        stop_event = multiprocessing.Event()

        # Create and start the process
        process = multiprocessing.Process(
            target=run_dealer_process,
            args=(self.router_addr, harness, dealer_id, stop_event),
            name=f"Dealer-{dealer_id}",
        )

        process.start()
        logger.info(f"Started dealer process: {dealer_id} (PID: {process.pid})")

        # Initialize lists if harness not seen before
        if harness not in self.processes:
            self.processes[harness] = []
            self.stop_events[harness] = []

        # Append to the lists
        self.processes[harness].append((dealer_id, process))
        self.stop_events[harness].append((dealer_id, stop_event))

        return process

    def stop_dealer(self, harness: str, dealer_id: Optional[str] = None):
        """Stop dealer process(es) for a harness"""
        if harness not in self.processes:
            logger.warning(f"No dealers found for harness {harness}")
            return

        if dealer_id is None:
            # Stop all dealers for this harness
            # Create a mapping for quick event lookup
            event_map = {did: event for did, event in self.stop_events.get(harness, [])}

            for did, process in self.processes[harness]:
                # Set stop event if exists
                if did in event_map:
                    event_map[did].set()

                # Wait for process to stop
                process.join(timeout=5)
                if process.is_alive():
                    logger.warning(
                        f"Process {process.name} didn't stop gracefully, terminating..."
                    )
                    process.terminate()
                    process.join(timeout=2)
                    if process.is_alive():
                        logger.error(
                            f"Process {process.name} didn't terminate, killing..."
                        )
                        process.kill()
                        process.join()

            # Clear all dealers for this harness and remove from dicts if empty
            del self.processes[harness]
            if harness in self.stop_events:
                del self.stop_events[harness]
        else:
            # Stop specific dealer
            # Find the dealer and its event
            dealer_index = None
            event_index = None

            for i, (did, process) in enumerate(self.processes[harness]):
                if did == dealer_id:
                    dealer_index = i
                    # Find corresponding event
                    for j, (eid, event) in enumerate(self.stop_events.get(harness, [])):
                        if eid == dealer_id:
                            event_index = j
                            event.set()
                            break

                    # Wait for process to stop
                    process.join(timeout=5)
                    if process.is_alive():
                        logger.warning(
                            f"Process {process.name} didn't stop gracefully, terminating..."
                        )
                        process.terminate()
                        process.join(timeout=2)
                        if process.is_alive():
                            logger.error(
                                f"Process {process.name} didn't terminate, killing..."
                            )
                            process.kill()
                            process.join()
                    break

            # Remove the dealer and event if found
            if dealer_index is not None:
                self.processes[harness].pop(dealer_index)
                if event_index is not None and harness in self.stop_events:
                    self.stop_events[harness].pop(event_index)

                # Clean up empty lists
                if not self.processes[harness]:
                    del self.processes[harness]
                if harness in self.stop_events and not self.stop_events[harness]:
                    del self.stop_events[harness]

    def start_multiple_dealers(self, harness: str, count: int):
        """Start multiple dealer processes"""
        logger.info(f"Starting {count} dealer processes for harness: {harness}")

        for i in range(count):
            self.start_dealer(harness, f"{harness}-dealer-{i}")
            time.sleep(0.1)  # Small delay between starts

    def stop_all(self):
        """Stop all dealer processes gracefully"""
        logger.info("Stopping all dealer processes...")

        # Set all stop events
        for harness, events in self.stop_events.items():
            for dealer_id, event in events:
                event.set()

        # Wait for processes to finish
        for harness, processes in self.processes.items():
            for dealer_id, process in processes:
                process.join(timeout=5)
                if process.is_alive():
                    logger.warning(
                        f"Process {process.name} didn't stop gracefully, terminating..."
                    )
                    process.terminate()
                    process.join(timeout=2)
                    if process.is_alive():
                        logger.error(
                            f"Process {process.name} didn't terminate, killing..."
                        )
                        process.kill()
                        process.join()

        logger.info("All dealer processes stopped")
        self.processes.clear()
        self.stop_events.clear()

    def get_status(self):
        """Get status of all dealer processes"""
        status = []
        for harness, processes in self.processes.items():
            for dealer_id, process in processes:
                status.append(
                    {
                        "harness": harness,
                        "dealer_id": dealer_id,
                        "name": process.name,
                        "pid": process.pid,
                        "alive": process.is_alive(),
                        "exitcode": process.exitcode,
                    }
                )
        return status

    def get_dealer_count(self, harness: Optional[str] = None) -> int:
        """Get count of active dealers for a harness or all harnesses"""
        if harness is not None:
            if harness not in self.processes:
                return 0
            return sum(1 for _, proc in self.processes[harness] if proc.is_alive())
        else:
            # Count all active dealers across all harnesses
            total = 0
            for processes in self.processes.values():
                total += sum(1 for _, proc in processes if proc.is_alive())
            return total


def main():
    """Example usage"""
    manager = DealerManager(router_addr="ipc:///tmp/ipc/haha")

    # Handle signals for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        manager.stop_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Start multiple dealers for different harnesses
        manager.start_multiple_dealers("Harness1", 3)
        manager.start_multiple_dealers("Harness2", 2)

        # Monitor processes
        while True:
            time.sleep(10)
            status = manager.get_status()
            active_count = manager.get_dealer_count()
            logger.info(f"Process status (Total active: {active_count}):")

            # Group by harness for better readability
            harness_groups = {}
            for s in status:
                if s["harness"] not in harness_groups:
                    harness_groups[s["harness"]] = []
                harness_groups[s["harness"]].append(s)

            for harness, dealers in harness_groups.items():
                active_in_harness = sum(1 for d in dealers if d["alive"])
                logger.info(f"  {harness} ({active_in_harness} active):")
                for s in dealers:
                    status_str = (
                        "ALIVE" if s["alive"] else f"DEAD (exit={s['exitcode']})"
                    )
                    logger.info(
                        f"    {s['dealer_id']}: PID={s['pid']}, Status={status_str}"
                    )

            # Clean up dead processes and restart failed ones
            for harness, processes in list(manager.processes.items()):
                for dealer_id, process in list(processes):
                    if not process.is_alive():
                        if process.exitcode == 0:
                            # Process exited normally, just clean up
                            logger.info(
                                f"Process {process.name} exited normally, cleaning up..."
                            )
                            manager.stop_dealer(harness, dealer_id)
                        elif process.exitcode is not None:
                            # Process crashed, restart it
                            logger.warning(
                                f"Process {process.name} died with code {process.exitcode}, restarting..."
                            )
                            # Stop this specific dealer (will remove it from lists)
                            manager.stop_dealer(harness, dealer_id)
                            # Start new one with same dealer_id
                            manager.start_dealer(harness, dealer_id)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        manager.stop_all()


if __name__ == "__main__":
    main()
