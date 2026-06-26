#ifndef HG_CONNECTION_H
#define HG_CONNECTION_H

#include "hg_parser.h"
#include <unistd.h>
#include <cstdint>
enum class ConnectionState
{
  READING,
  WRITING,
  CLOSED
};

class HgConnection
{
public:
  int fd = -1;
  std::string write_buf;
  std::string client_ip;
  uint16_t client_port = 0;
  HgParser parser;
  ConnectionState state = ConnectionState::READING;
  size_t write_offset = 0;

  HgConnection(int fd, const std::string& ip, uint16_t port)
    : fd(fd), 
    client_ip(ip), 
    client_port(port),
    state(ConnectionState::READING), write_offset(0){}
  ~HgConnection(){ close(fd); }
  
  HgConnection(const HgConnection&) = delete;
  HgConnection& operator=(const HgConnection&) = delete;

  void on_readable();
  void on_writable();
  void queue_response(const std::string &response);
};
#endif /* HG_CONNECTION_H */