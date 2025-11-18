from threading import Lock
from pathlib import Path
import tarfile
import shutil
import logging
from libatlantis.protobuf import FileWrite, ExtractTar, FileOps

logger = logging.getLogger(__name__)

class BootstrapContext:
    def __init__(self):
        self.lock = Lock()

    def __process_file_write(self, message: FileWrite):
        file_path = Path(message.file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(message.content)
        logger.info(f"Wrote to {file_path}")
        
    def __process_extraction(self, message: ExtractTar):
        tarball = Path(message.tarball)
        destination = Path(message.destination)

        # Remove destination directory if it exists
        if destination.exists():
            shutil.rmtree(destination, ignore_errors=True)

        destination.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(tarball, "r:gz") as tar:
            tar.extractall(destination)
            logger.info(f"Extracted tarball {tarball} to {destination}")
        
    def process_file_writes(self, message: FileOps):
        with self.lock:
            for op in message.writes:
                self.__process_file_write(op)
            for op in message.extractions:
                self.__process_extraction(op)
