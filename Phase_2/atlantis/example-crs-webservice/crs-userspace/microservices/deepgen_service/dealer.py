#!/usr/bin/env python3
"""
Seed-Consumer (DEALER, asyncio) with Shared Memory Support
Similar to the C consumer.c implementation
"""

import asyncio
import uuid
import zmq.asyncio as azmq
import zmq
import json
import logging
import mmap
import struct
import os
import time
from dataclasses import dataclass, asdict
from typing import Optional, List
from pathlib import Path


# Constants matching C implementation
MAX_SEED_SIZE = 1048576  # 1MB max per seed
BUFFER_SIZE = 104857600  # 100MB buffer for seeds
HEARTBEAT_INTERVAL = 5  # seconds
RECV_TIMEOUT = 100  # milliseconds
MAX_SHM_POOLS = 10  # Maximum number of concurrent shared memory pools

# Shared memory pool header constants
SHM_HEADER_SIZE = 8
SHM_LEN_FIELD_SIZE = 4

# Batch storage constants
BATCH_SIZE = 5000  # Number of seeds per batch file
SEED_COUNT_THRESHOLD = 10000  # Trigger batch storage when this many seeds are buffered
BUFFER_USAGE_THRESHOLD = 0.9  # Trigger batch storage when buffer is 90% full
ENSEMBLER_TMPFS = os.getenv("ENSEMBLER_TMPFS", "/tmpfs")
STORAGE_DIR = os.getenv(
    "SEED_STORAGE_DIR", f"{ENSEMBLER_TMPFS}/seeds"
)  # Default storage directory (tmpfs for ensembler)


@dataclass(frozen=True, slots=True)
class SubmitBundle:
    """A bundle of seed IDs organized by harness name and seed pool shared memory name."""

    script_id: int
    harness_name: str
    shm_name: str
    seed_ids: list[int]

    @staticmethod
    def serialize(bundle: "SubmitBundle") -> bytes:
        """Serialize list of seed IDs"""
        return json.dumps(asdict(bundle)).encode()

    @staticmethod
    def deserialize(data: bytes) -> "SubmitBundle":
        """Deserialize to list of seed IDs"""
        obj = json.loads(data.decode())
        return SubmitBundle(**obj)


class SharedMemoryConsumer:
    """Manages reading from a shared memory pool"""

    def __init__(self, shm_name: str):
        self.name = shm_name
        self.shm_path = f"/dev/shm/{shm_name}"
        self.fd = None
        self.mmap_obj = None
        self.item_size = 0
        self.item_num = 0
        self.file_size = 0

    def open(self) -> bool:
        """Open and map the shared memory file"""
        try:
            # Open the shared memory file
            self.fd = os.open(self.shm_path, os.O_RDONLY)

            # Get file size
            stat_info = os.fstat(self.fd)
            self.file_size = stat_info.st_size

            # Memory map the file
            self.mmap_obj = mmap.mmap(self.fd, self.file_size, access=mmap.ACCESS_READ)

            # Read header (item_size, item_num) - both are u32
            header_data = self.mmap_obj[:SHM_HEADER_SIZE]
            self.item_size, self.item_num = struct.unpack("II", header_data)

            # Verify size consistency
            expected_size = SHM_HEADER_SIZE + self.item_size * self.item_num
            if expected_size != self.file_size:
                logging.error(
                    f"Shared memory size mismatch: expected={expected_size}, actual={self.file_size}"
                )
                self.close()
                return False

            logging.info(
                f"Shared memory opened: {self.shm_path}, items={self.item_num}, item_size={self.item_size}"
            )
            return True

        except Exception as e:
            logging.error(f"Failed to open shared memory {self.shm_path}: {e}")
            self.close()
            return False

    def read_seed(self, seed_id: int) -> Optional[bytes]:
        """Read a seed from shared memory by ID"""
        if not self.mmap_obj:
            return None

        if seed_id < 0 or seed_id >= self.item_num:
            logging.warning(f"Invalid seed_id {seed_id} (max: {self.item_num})")
            return None

        try:
            # Calculate offset
            offset = SHM_HEADER_SIZE + seed_id * self.item_size

            # Read data length (u32)
            len_data = self.mmap_obj[offset : offset + SHM_LEN_FIELD_SIZE]
            data_len = struct.unpack("I", len_data)[0]

            # Validate length
            if data_len == 0 or data_len > self.item_size - SHM_LEN_FIELD_SIZE:
                return None

            # Read actual seed data
            data_start = offset + SHM_LEN_FIELD_SIZE
            seed_data = self.mmap_obj[data_start : data_start + data_len]

            return bytes(seed_data)

        except Exception as e:
            logging.error(f"Error reading seed {seed_id}: {e}")
            return None

    def close(self):
        """Close the shared memory mapping"""
        if self.mmap_obj:
            self.mmap_obj.close()
            self.mmap_obj = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class CircularBuffer:
    """Thread-safe circular buffer for storing seeds"""

    def __init__(self, size: int = BUFFER_SIZE):
        self.buffer = bytearray(size)
        self.size = size
        self.write_pos = 0
        self.read_pos = 0
        self.data_available = 0
        self.lock = asyncio.Lock()
        self.not_empty = asyncio.Condition(self.lock)

    async def add_seed(self, seed_data: bytes) -> bool:
        """Add a seed to the buffer"""
        seed_len = len(seed_data)
        if seed_len > MAX_SEED_SIZE:
            seed_len = MAX_SEED_SIZE
            seed_data = seed_data[:seed_len]

        async with self.lock:
            # Check if we have enough space
            free_space = self.size - self.data_available
            needed_space = 4 + seed_len  # 4 bytes for length + data

            if needed_space > free_space:
                return False  # Buffer full

            # Write seed length (4 bytes, little endian)
            len_bytes = struct.pack("<I", seed_len)
            for b in len_bytes:
                self.buffer[self.write_pos] = b
                self.write_pos = (self.write_pos + 1) % self.size

            # Write seed data
            for b in seed_data:
                self.buffer[self.write_pos] = b
                self.write_pos = (self.write_pos + 1) % self.size

            self.data_available += needed_space
            self.not_empty.notify()

        return True

    async def get_seed(self, timeout: Optional[float] = None) -> Optional[bytes]:
        """Get a seed from the buffer"""
        async with self.lock:
            # Wait for data if buffer is empty
            if self.data_available < 4:
                try:
                    await asyncio.wait_for(
                        self.not_empty.wait_for(lambda: self.data_available >= 4),
                        timeout=timeout,
                    )
                except asyncio.TimeoutError:
                    return None

            if self.data_available < 4:
                return None

            # Read seed length
            len_bytes = bytearray(4)
            for i in range(4):
                len_bytes[i] = self.buffer[self.read_pos]
                self.read_pos = (self.read_pos + 1) % self.size

            seed_len = struct.unpack("<I", len_bytes)[0]

            # Sanity check
            if seed_len > MAX_SEED_SIZE or seed_len > self.data_available - 4:
                # Corrupted buffer, reset
                self.read_pos = self.write_pos
                self.data_available = 0
                return None

            # Read seed data
            seed_data = bytearray(seed_len)
            for i in range(seed_len):
                seed_data[i] = self.buffer[self.read_pos]
                self.read_pos = (self.read_pos + 1) % self.size

            self.data_available -= 4 + seed_len

        return bytes(seed_data)

    async def get_status(self) -> tuple[int, int]:
        """Get buffer status (data_available, buffer_size)"""
        async with self.lock:
            return self.data_available, self.size


class SeedStorage:
    """Handles batch storage of seeds to filesystem"""

    def __init__(self, storage_dir: str = STORAGE_DIR, harness: str = "default"):
        self.storage_dir = Path(storage_dir)
        self.harness = harness
        self.batch_counter = 0
        self.logger = logging.getLogger(f"{__name__}.SeedStorage")

        # Create storage directory if it doesn't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Seed storage initialized at: {self.storage_dir}")

    async def store_batch(self, seeds: List[bytes]) -> Optional[str]:
        """Store a batch of seeds to a directory following the convention"""
        if not seeds:
            return None

        try:
            # Generate batch directory name following convention
            batch_uuid = uuid.uuid4()
            dir_name = f"{self.harness}-{self.batch_counter}-{{{batch_uuid}}}"
            batch_dir = self.storage_dir / dir_name
            batch_dir.mkdir(parents=True, exist_ok=True)
            self.batch_counter += 1

            # Write each seed to a separate file
            for idx, seed in enumerate(seeds):
                seed_file = batch_dir / f"seed_{idx}.bin"
                with open(seed_file, "wb") as f:
                    f.write(seed)

            # Write DONE file to indicate batch is complete
            done_file = batch_dir / "DONE"
            with open(done_file, "w") as f:
                f.write("DONE")

            # Calculate total size
            total_size = sum(f.stat().st_size for f in batch_dir.iterdir())

            self.logger.info(
                f"Stored batch {dir_name}: {len(seeds)} seeds, {total_size} bytes"
            )

            return str(batch_dir)

        except Exception as e:
            self.logger.error(f"Failed to store batch: {e}")
            return None

    async def load_batch(self, batch_dir: str) -> List[bytes]:
        """Load a batch of seeds from a directory"""
        seeds = []
        try:
            batch_path = Path(batch_dir)

            # Check if DONE file exists
            done_file = batch_path / "DONE"
            if not done_file.exists():
                self.logger.warning(f"Batch {batch_dir} is incomplete (no DONE file)")
                return seeds

            # Load all seed files
            seed_files = sorted(batch_path.glob("seed_*.bin"))
            for seed_file in seed_files:
                with open(seed_file, "rb") as f:
                    seeds.append(f.read())

            self.logger.info(f"Loaded {len(seeds)} seeds from {batch_dir}")

        except Exception as e:
            self.logger.error(f"Failed to load batch from {batch_dir}: {e}")

        return seeds

    def get_stored_batches(self) -> List[Path]:
        """Get list of stored batch directories"""
        batches = []

        # Look for directories matching our pattern and containing DONE file
        for item in self.storage_dir.iterdir():
            if item.is_dir() and (item / "DONE").exists():
                # Check if it matches our naming pattern
                if item.name.startswith(f"{self.harness}-"):
                    batches.append(item)

        # Sort by modification time
        return sorted(batches, key=lambda p: p.stat().st_mtime)

    def get_storage_stats(self) -> dict:
        """Get storage statistics"""
        batch_dirs = self.get_stored_batches()

        total_size = 0
        total_seeds = 0

        for batch_dir in batch_dirs:
            # Count seed files and calculate size
            seed_files = list(batch_dir.glob("seed_*.bin"))
            total_seeds += len(seed_files)
            total_size += sum(f.stat().st_size for f in batch_dir.iterdir())

        return {
            "batch_count": len(batch_dirs),
            "total_seeds": total_seeds,
            "total_size": total_size,
            "storage_dir": str(self.storage_dir),
            "oldest_batch": str(batch_dirs[0]) if batch_dirs else None,
            "newest_batch": str(batch_dirs[-1]) if batch_dirs else None,
        }


class Dealer:
    """Main dealer class with shared memory support"""

    def __init__(
        self,
        router_addr: str,
        harness: str,
        dealer_id: Optional[str] = None,
        enable_storage: bool = True,
    ):
        self.router_addr = router_addr
        self.harness = harness
        self.dealer_id = dealer_id or f"Python-{uuid.uuid4().hex[:8]}"

        # ZMQ setup
        self.ctx = azmq.Context.instance()
        self.socket = None

        # Shared memory consumers
        self.shm_consumers: dict[str, SharedMemoryConsumer] = {}

        # Circular buffer for seeds
        self.seed_buffer = CircularBuffer()

        # Seed storage
        self.enable_storage = enable_storage
        self.seed_storage = (
            SeedStorage(harness=self.harness) if enable_storage else None
        )

        # Statistics
        self.total_seeds = 0
        self.seeds_processed = 0
        self.bytes_received = 0
        self.last_printed_count = 0
        self.seeds_in_buffer = 0  # Track number of seeds currently in buffer
        self.seeds_stored = 0  # Track number of seeds stored to disk

        # Overflow handling
        self.overflow_task = None
        self.last_overflow_check = time.time()

        # Configure logging
        self.logger = logging.getLogger(__name__)

    async def connect(self):
        """Connect to the router"""
        self.socket = self.ctx.socket(zmq.DEALER)
        self.socket.setsockopt_string(zmq.IDENTITY, self.dealer_id)
        self.socket.setsockopt(zmq.RCVTIMEO, RECV_TIMEOUT)

        self.socket.connect(self.router_addr)
        self.logger.info(
            f"Connected to router at {self.router_addr} with ID {self.dealer_id}"
        )

    async def disconnect(self):
        """Disconnect and cleanup"""
        if self.socket:
            self.socket.close()

        # Close all shared memory consumers
        for consumer in self.shm_consumers.values():
            consumer.close()
        self.shm_consumers.clear()

    def get_or_create_consumer(self, shm_name: str) -> Optional[SharedMemoryConsumer]:
        """Get existing consumer or create new one"""
        if shm_name in self.shm_consumers:
            return self.shm_consumers[shm_name]

        # Create new consumer
        consumer = SharedMemoryConsumer(shm_name)
        if consumer.open():
            self.shm_consumers[shm_name] = consumer
            return consumer
        else:
            return None

    async def check_and_handle_overflow(self):
        """Check buffer status and handle overflow if needed"""
        if not self.enable_storage:
            return

        # Get buffer status
        data_available, buffer_size = await self.seed_buffer.get_status()
        usage_ratio = data_available / buffer_size if buffer_size > 0 else 0

        # Check if we should trigger overflow handling
        should_overflow = (
            self.seeds_in_buffer >= SEED_COUNT_THRESHOLD
            or usage_ratio >= BUFFER_USAGE_THRESHOLD
        )

        if should_overflow and self.overflow_task is None:
            self.logger.info(
                f"Triggering overflow handler: seeds={self.seeds_in_buffer}, "
                f"buffer_usage={usage_ratio:.1%}"
            )
            self.overflow_task = asyncio.create_task(self.handle_overflow())

    async def handle_overflow(self):
        """Handle buffer overflow by storing seeds to disk"""
        try:
            if not self.seed_storage:
                return

            # Extract seeds in batches
            total_extracted = 0
            while (
                self.seeds_in_buffer > SEED_COUNT_THRESHOLD / 2
            ):  # Keep extracting until buffer is half empty
                seeds = []
                for _ in range(BATCH_SIZE):
                    seed = await self.seed_buffer.get_seed(timeout=0.01)
                    if seed is None:
                        break
                    seeds.append(seed)
                    self.seeds_in_buffer -= 1

                if not seeds:
                    break

                # Store the batch
                batch_dir = await self.seed_storage.store_batch(seeds)
                if batch_dir:
                    total_extracted += len(seeds)
                    self.seeds_stored += len(seeds)
                else:
                    # Failed to store, put seeds back
                    for seed in seeds:
                        if not await self.seed_buffer.add_seed(seed):
                            self.logger.error(
                                "Failed to return seed to buffer after storage failure"
                            )
                        else:
                            self.seeds_in_buffer += 1
                    break

            if total_extracted > 0:
                self.logger.info(
                    f"Overflow handled: extracted {total_extracted} seeds, "
                    f"buffer now has {self.seeds_in_buffer} seeds"
                )

                # Log storage stats
                if self.seed_storage:
                    stats = self.seed_storage.get_storage_stats()
                    self.logger.info(
                        f"Storage stats: {stats['batch_count']} batches, "
                        f"{stats['total_size'] / 1024 / 1024:.1f} MB total"
                    )

        except Exception as e:
            self.logger.error(f"Error in overflow handler: {e}")
        finally:
            self.overflow_task = None

    async def process_seed_bundle(self, bundle: SubmitBundle) -> int:
        """Process a seed bundle by reading seeds from shared memory"""
        consumer = self.get_or_create_consumer(bundle.shm_name)
        if not consumer:
            self.logger.error(f"Failed to get consumer for {bundle.shm_name}")
            return 0

        seeds_added = 0
        for seed_id in bundle.seed_ids:
            seed_data = consumer.read_seed(seed_id)
            if seed_data:
                if await self.seed_buffer.add_seed(seed_data):
                    seeds_added += 1
                    self.total_seeds += 1
                    self.seeds_in_buffer += 1
                    self.bytes_received += len(seed_data)
                else:
                    self.logger.warning("Buffer full, dropping seed")

        # Check for overflow after processing bundle
        if seeds_added > 0:
            await self.check_and_handle_overflow()

        return seeds_added

    async def heartbeat_loop(self):
        """Send periodic heartbeats"""
        self.logger.info(f"Starting heartbeat loop (interval: {HEARTBEAT_INTERVAL}s)")
        heartbeat_count = 0

        try:
            while True:
                self.logger.debug(f"Sending HEARTBEAT {heartbeat_count}")
                await self.socket.send_multipart([b"HEARTBEAT", self.harness.encode()])
                heartbeat_count += 1

                if heartbeat_count % 10 == 0:
                    data_available, buffer_size = await self.seed_buffer.get_status()
                    buffer_pct = (data_available * 100) // buffer_size

                    status_msg = (
                        f"Status: {heartbeat_count} heartbeats, "
                        f"{self.total_seeds} seeds received, "
                        f"{self.seeds_in_buffer} in buffer, "
                        f"buffer: {buffer_pct}% ({data_available}/{buffer_size} bytes)"
                    )

                    if self.enable_storage and self.seeds_stored > 0:
                        status_msg += f", {self.seeds_stored} seeds stored to disk"

                    self.logger.info(status_msg)

                await asyncio.sleep(HEARTBEAT_INTERVAL)

        except asyncio.CancelledError:
            self.logger.info("Heartbeat loop cancelled")
            raise

    async def message_loop(self):
        """Main message processing loop"""
        self.logger.info("Starting message processing loop")

        try:
            while True:
                try:
                    # Non-blocking receive with timeout
                    cmd, *frames = await self.socket.recv_multipart()
                    self.logger.debug(f"Received command: {cmd}")

                    if cmd == b"SEED":
                        msg_id, bundle_b = frames
                        self.logger.debug(f"Received SEED bundle: msg_id={msg_id}")

                        # Deserialize bundle
                        bundle = SubmitBundle.deserialize(bundle_b)

                        # Process seeds from shared memory
                        seeds_added = await self.process_seed_bundle(bundle)
                        self.logger.debug(
                            f"Added {seeds_added}/{len(bundle.seed_ids)} seeds from bundle"
                        )

                        # Send ACK
                        await self.socket.send_multipart([b"ACK", msg_id, bundle_b])
                        self.logger.debug(f"ACK sent for {msg_id}")

                        # Print progress
                        if self.total_seeds - self.last_printed_count >= 1000:
                            self.logger.info(
                                f"Processed {self.total_seeds} seeds so far"
                            )
                            self.last_printed_count = self.total_seeds

                    else:
                        self.logger.warning(f"Unknown command: {cmd}")

                except zmq.Again:
                    # Timeout, no message available
                    await asyncio.sleep(0.01)

        except asyncio.CancelledError:
            self.logger.info("Message loop cancelled")
            raise

    async def run(self):
        """Run the dealer"""
        await self.connect()

        # Create tasks
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        message_task = asyncio.create_task(self.message_loop())

        try:
            # Run both tasks concurrently
            await asyncio.gather(heartbeat_task, message_task)
        finally:
            # Cleanup
            heartbeat_task.cancel()
            message_task.cancel()
            await self.disconnect()

            self.logger.info(
                f"Dealer shutdown complete. "
                f"Total seeds: {self.total_seeds}, "
                f"Seeds processed: {self.seeds_processed}, "
                f"Seeds stored: {self.seeds_stored}, "
                f"Bytes received: {self.bytes_received}"
            )

            if self.seed_storage:
                stats = self.seed_storage.get_storage_stats()
                self.logger.info(
                    f"Storage summary: {stats['batch_count']} batch files, "
                    f"{stats['total_size'] / 1024 / 1024:.1f} MB total in {stats['storage_dir']}"
                )

    async def get_seed(self, timeout: Optional[float] = 0.1) -> Optional[bytes]:
        """Get a seed from the buffer (for external consumers)"""
        seed = await self.seed_buffer.get_seed(timeout)
        if seed:
            self.seeds_processed += 1
            self.seeds_in_buffer -= 1
        return seed

    async def reload_seeds_from_storage(self, max_batches: int = 5) -> int:
        """Reload seeds from storage back into the buffer"""
        if not self.seed_storage:
            return 0

        reloaded = 0
        batch_dirs = self.seed_storage.get_stored_batches()[:max_batches]

        for batch_dir in batch_dirs:
            seeds = await self.seed_storage.load_batch(str(batch_dir))

            added = 0
            for seed in seeds:
                if await self.seed_buffer.add_seed(seed):
                    added += 1
                    self.seeds_in_buffer += 1
                else:
                    # Buffer full, stop loading
                    break

            reloaded += added

            # Delete the batch directory after loading
            if added == len(seeds):
                try:
                    # Remove all files in the directory
                    for item in batch_dir.iterdir():
                        item.unlink()
                    # Remove the directory itself
                    batch_dir.rmdir()
                    self.logger.debug(f"Deleted batch directory: {batch_dir}")
                except Exception as e:
                    self.logger.error(
                        f"Failed to delete batch directory {batch_dir}: {e}"
                    )

            # Check if buffer is getting full
            data_available, buffer_size = await self.seed_buffer.get_status()
            if data_available / buffer_size > 0.8:
                break

        if reloaded > 0:
            self.logger.info(f"Reloaded {reloaded} seeds from storage")

        return reloaded


async def main():
    """Main entry point"""
    # Get configuration from environment or use defaults
    router_addr = os.getenv("AFL_ZMQ_ROUTER", "ipc:///tmp/haha")
    harness = os.getenv("FUZZER", "Python-AFL")

    # Create and run dealer
    dealer = Dealer(router_addr, harness)
    await dealer.run()


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    logger = logging.getLogger("main")
    logger.info("Starting ZMQ dealer with shared memory support")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Dealer stopped by user")
    except Exception as e:
        logger.error(f"Dealer failed with error: {e}", exc_info=True)
