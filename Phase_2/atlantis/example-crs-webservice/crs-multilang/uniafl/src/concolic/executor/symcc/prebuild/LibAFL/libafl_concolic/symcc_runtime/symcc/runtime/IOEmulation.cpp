// clang-format off
#include <Runtime.h>
#include "RuntimeCommon.h"
// clang-format on
#include <IOEmulation.h>
#include <iostream>
#include <map>
#include <memory>
#include <sys/syscall.h>

std::map<int, std::unique_ptr<FdVariant>> emuFds;

int PipeFd::write(const uint8_t *buf, size_t count) {
  if (this->pipe_buffer_size > 0) {
    std::cerr << "PipeFd::write: pipe_buffer_size > 0\n";
    return -1;
  }
  if (this->read_side) {
    std::cerr << "PipeFd::write: pipe is readonly\n";
    return -1;
  }
  if (auto *pipeFd = std::get_if<PipeFd>(emuFds[this->other_side_fd].get())) {
    pipeFd->pipe_buffer = new uint8_t[count];
    pipeFd->pipe_buffer_size = count;
    std::memcpy(pipeFd->pipe_buffer, buf, count);
    _sym_memcpy(pipeFd->pipe_buffer, buf, count);
    return count;
  } else {
    std::cerr << "PipeFd::write: other_side_fd is not a PipeFd\n";
    return -1;
  }
}
int PipeFd::read(uint8_t *buf, size_t count) {
  if (this->pipe_buffer_size == 0) {
    std::cerr << "PipeFd::read: pipe_buffer_size == 0\n";
    return -1;
  }
  // Measure offset via lssek. The reason we do this is because
  // some file reads bypass PipeFd::read. One example of this is when
  // the target program uses <stdio.h> methods such as fgets or scanf
  // If we maintain an offset variable in PipeFd, it may get out of sync
  // with the actual fd offset.
  off_t offset = 0;
  if ((offset = lseek(this->underlying_memfd, 0, SEEK_CUR)) == -1) {
    std::cerr << "PipeFd::read: lseek failed\n";
    return -1;
  }
  // we need to reset the offset to the previous offset after reading
  offset -= count;
  std::memcpy(buf, this->pipe_buffer + offset, count);
  _sym_memcpy(buf, this->pipe_buffer + offset, count);
  return count;
}

int PipeFd::close() {
  if (this->pipe_buffer != nullptr) {
    delete[] this->pipe_buffer;
  }
  this->pipe_buffer = nullptr;
  this->pipe_buffer_size = 0;
  ::close(this->underlying_memfd);
  return 0;
}

int ReadWriteFd::operator()(PipeFd &fd) {
  if (this->mode == Mode::WRITE) {
    return fd.write(buf, count);
  } else {
    return fd.read(buf, count);
  }
}

int ReadWriteFd::operator()(Dup2Fd &fd) {
  if (emuFds.find(fd.redirect_fd) == emuFds.end()) {
    return -1;
  } else {
    return std::visit(*this, *emuFds[fd.redirect_fd]);
  }
}

int ioEmuPipe(int pipefd[2]) {
  int memfd_r, memfd_w;
  memfd_w = syscall(SYS_memfd_create, "_sym_input_data", 0);
  if (memfd_w == -1) {
    std::cerr << "ioEmuPipe: Failed to create memfd" << std::endl;
    return -1;
  }
  if ((memfd_r = dup(memfd_w)) == -1) {
    close(memfd_w);
    std::cerr << "ioEmuPipe: Failed to dup memfd" << std::endl;
    return -1;
  }
  pipefd[0] = memfd_r;
  pipefd[1] = memfd_w;
  PipeFd pipeFdWrite(memfd_w, false, memfd_r);
  PipeFd pipeFdRead(memfd_r, true, memfd_w);
  emuFds[memfd_r] = std::make_unique<FdVariant>(std::move(pipeFdRead));
  emuFds[memfd_w] = std::make_unique<FdVariant>(std::move(pipeFdWrite));
  return 0;
}

// Note: count is the ACTUAL nubmer of bytes written, not the user provided
// argument. It may be smaller than arg3
int ioEmuWrite(int fd, uint8_t *buf, int ret) {
  if (emuFds.find(fd) == emuFds.end()) {
    return ret;
  }
  ReadWriteFd resolveFd(Mode::WRITE, buf, (size_t)ret);
  int finalRet = std::visit(resolveFd, *emuFds[fd]);
  if (finalRet == -1) {
    std::cerr << "ioEmuWrite: failed to write to memfd" << std::endl;
    return -1;
  }
  // reset the offset to zero
  if (lseek(fd, 0, SEEK_SET) == -1) {
    std::cerr << "ioEmuWrite: failed to lseek the memfd to 0" << std::endl;
    return -1;
  }
  return finalRet;
}

int ioEmuRead(int fd, uint8_t *buf, int ret) {
  if (emuFds.find(fd) == emuFds.end()) {
    std::cerr << "ioEmuRead: fd " << fd << " is not symbolic, returning "
              << (int)ret << std::endl;
    return ret;
  }
  ReadWriteFd resolveFd(Mode::READ, buf, (size_t)ret);
  return std::visit(resolveFd, *emuFds[fd]);
}

int ioEmuDup2(int oldFd, int newFd) {
  if (emuFds.find(oldFd) == emuFds.end()) {
    return newFd;
  }
  emuFds[newFd] = std::make_unique<FdVariant>(Dup2Fd(oldFd));
  return 0;
}

int ioEmuClose(int fd) {
  if (emuFds.find(fd) == emuFds.end()) {
    // This function is called only when the target program's close() system
    // call has been successful, so we don't need to print an error message
    // here.
    return 0;
  }
  CloseFd closeFd;
  std::visit(closeFd, *emuFds[fd]);
  emuFds.erase(fd);
  return 0;
}
