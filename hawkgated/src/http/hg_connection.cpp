#include "hg_connection.h"
#include "../util/hg_log.h"
#include <errno.h>
#include <unistd.h>

void HgConnection::on_readable()
{
  char buf[4096];
  while (true)
  {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n == 0)
    {
      state = ConnectionState::CLOSED;
      return;
    }
    if (n == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break;
      log_error("on_readable: read error");
      state = ConnectionState::CLOSED;
      return;
    }
    ParseState ps = parser.feed(buf, static_cast<size_t>(n));
    if (ps == ParseState::COMPLETE)
    {
      state = ConnectionState::WRITING;
      return;
    }
    if (ps == ParseState::ERROR)
    {
      log_error("on_readable: parse error");
      state = ConnectionState::CLOSED;
      return;
    }
  }
}

void HgConnection::on_writable()
{
  while (write_offset < write_buf.size())
  {
    ssize_t n = write(fd, write_buf.c_str() + write_offset,
                      write_buf.size() - write_offset);
    if (n == -1)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
      log_error("on_writable: write error");
      state = ConnectionState::CLOSED;
      return;
    }
    write_offset += static_cast<size_t>(n);
  }
  state = ConnectionState::CLOSED;
}

void HgConnection::queue_response(const std::string &response)
{
  write_buf = response;
  write_offset = 0;
  state = ConnectionState::WRITING;
}