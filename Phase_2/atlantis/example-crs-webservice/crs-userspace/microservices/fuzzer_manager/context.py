import threading
import os
import base64
from typing import Dict, Tuple

from .fuzzer_session import (
    BaseFuzzerSession,
    LibAFLFuzzerSession,
    LibFuzzerSession,
    AFLFuzzerSession,
    UBSanFuzzerSession,
    MSanFuzzerSession,
    SansFuzzerSession,
)

def string_to_id(data: str, length: int=8) -> str:
    b64 = base64.b64encode(data.encode('utf-8'))
    return str(int.from_bytes(b64, byteorder='big') % (10 ** length)).zfill(length)

class FuzzerManagerContext:
    def __init__(self):
        self.lock = threading.Lock()
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        self.sessions: Dict[str, BaseFuzzerSession] = {}

    @classmethod
    def _get_fuzzer_session_id(cls, nonce: str, harness_id: str, node_idx: int) -> str:
        return string_to_id(
            "fuzzer_session_id" + str(nonce) + str(harness_id) + str(node_idx)
        )

    def create_session(self, mode: str, nonce: str, harness_id: str, **kwargs) -> Tuple[BaseFuzzerSession, str]:
        """Create a new fuzzer session with the specified mode and parameters."""
        session_id = self._get_fuzzer_session_id(nonce, harness_id, self.node_idx)
        session_kwargs = {
            "harness_id": harness_id, 
            "session_id": session_id,
            "nonce": nonce,
            **kwargs
        }

        if mode == "libafl":
            session = LibAFLFuzzerSession(**session_kwargs)
        elif mode == "libfuzzer":
            session = LibFuzzerSession(**session_kwargs)
        elif mode == "afl":
            session = AFLFuzzerSession(**session_kwargs)
        elif mode == "ubsan":
            session = UBSanFuzzerSession(**session_kwargs)
        elif mode == "msan":
            session = MSanFuzzerSession(**session_kwargs)
        elif mode == "sans":
            session = SansFuzzerSession(**session_kwargs)
        else:
            raise ValueError(f"Unknown fuzzer mode: {mode}")

        self.sessions[session_id] = session
        return session, session_id

    def stop_session(self, session_id: str = None):
        if session_id:
            if session_id in self.sessions:
                self.sessions[session_id].stop()
                del self.sessions[session_id]
        else:
            # Stop all sessions if no specific session_id provided
            for session in self.sessions.values():
                session.stop()
            self.sessions.clear()

    def get_session(self, session_id: str) -> BaseFuzzerSession | None:
        return self.sessions.get(session_id)

    def get_cores(self, session_id: str = None) -> list[int]:
        if session_id:
            session = self.sessions.get(session_id)
            return session.cores if session else []
        else:
            # Return all cores from all sessions if no specific session_id provided
            all_cores = []
            for session in self.sessions.values():
                all_cores.extend(session.cores)
            return all_cores
