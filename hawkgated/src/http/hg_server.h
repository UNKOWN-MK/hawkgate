#ifndef HG_SERVER_H
#define HG_SERVER_H
#include "hg_connection.h"
#include <unordered_map>
#include <memory> // std::unique_ptr
#include <atomic> // std::atomic

class HgServer
{
public:
  bool init();
  void run();
  void stop();

private:
  int epoll_fd = -1;
  int listen_fd = -1;
  std::atomic<bool> running{false};
  std::unordered_map<int, std::unique_ptr<HgConnection>> connections;

  void accept_connections();
  void handle_readable(int fd);
  void handle_writable(int fd);
  void remove_connection(int fd);
};

#endif /* HG_SERVER_H */