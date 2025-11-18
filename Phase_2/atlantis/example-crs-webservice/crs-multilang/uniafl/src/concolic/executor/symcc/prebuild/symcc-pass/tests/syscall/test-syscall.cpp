#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 32) {
    return 0;
  }

  // 1. Create temporary file
  char filename[] = "/tmp/fuzztempXXXXXX";
  int fd = mkstemp(filename);
  if (fd == -1) {
    perror("mkstemp failed");
    return 0;
  }

  // 2. Write fuzz input to file
  if (write(fd, data, size) != static_cast<ssize_t>(size)) {
    perror("write failed");
    close(fd);
    unlink(filename);
    return 0;
  }

  // 3. Rewind and read (optional, shown for demonstration)
  lseek(fd, 0, SEEK_SET);
  int buffer[8] = {0}; // read first 32 bytes
  read(fd, buffer, 32);

  // 4. Cleanup
  close(fd);
  unlink(filename); // delete file from disk

  // Trigger condition
  if (buffer[0] + buffer[1] == 0x1337 * 0x1338 &&
      buffer[0] + buffer[1] == 0x1337 + 0x1338) {
    abort();
  }

  return 0;
}
