#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <variant>

class PipeFd {
public:
  PipeFd(int underlying_memfd, bool read_side, int other_side_fd)
      : pipe_buffer(nullptr), pipe_buffer_size(0),
        underlying_memfd(underlying_memfd), read_side(read_side),
        other_side_fd(other_side_fd) {};
  ~PipeFd() { // don't close the underlying memfd here
  }
  uint8_t *pipe_buffer;
  std::size_t pipe_buffer_size;
  int underlying_memfd;
  bool read_side;
  int other_side_fd;

  int write(const uint8_t *buf, size_t count);
  int read(uint8_t *buf, size_t count);
  int close();
};

class Dup2Fd {
public:
  Dup2Fd(int redirect_fd) : redirect_fd(redirect_fd) {};
  ~Dup2Fd() {};
  int redirect_fd;
};

using FdVariant = std::variant<PipeFd, Dup2Fd>;

enum Mode { READ, WRITE };

class CloseFd {
public:
  int operator()(PipeFd &fd) { return fd.close(); }
  int operator()(Dup2Fd &fd) { return 0; }
};

class ReadWriteFd {
public:
  Mode mode;
  uint8_t *buf;
  size_t count;
  ReadWriteFd(Mode mode, uint8_t *buf, size_t count)
      : mode(mode), buf(buf), count(count) {}

  int operator()(PipeFd &fd);
  int operator()(Dup2Fd &fd);
};

int ioEmuPipe(int pipefd[2]);
int ioEmuDup2(int oldfd, int newfd);
int ioEmuClose(int fd);
int ioEmuWrite(int fd, uint8_t *buf, int ret);
int ioEmuRead(int fd, uint8_t *buf, int ret);
