#include "hg_server.h"
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include "../util/hg_log.h"
#include "../util/hg_config.h"

#define MAX_EVENTS 64
#define TIMEOUT -1 // Wait indefinitely for events

bool HgServer::init()
{
  // Create listening socket
  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0)
  {
    log_error("Failed to create socket");
    return false;
  }

  // Set socket options
  int opt = 1;
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
  {
    log_error("init: setsockopt() failed");
    close(listen_fd);
    return false;
  }
  // Set non-blocking mode
  if (fcntl(listen_fd, F_SETFL, O_NONBLOCK) == -1)
  {
    log_error("init: fcntl() failed");
    close(listen_fd);
    return false;
  }

  // Bind to configured port
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(g_config.http_port);
  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    log_error("Failed to bind socket");
    close(listen_fd);
    return false;
  }

  // Start listening
  if (listen(listen_fd, SOMAXCONN) < 0)
  {
    log_error("Failed to listen on socket");
    close(listen_fd);
    return false;
  }

  // Create epoll instance
  epoll_fd = epoll_create1(0);
  if (epoll_fd < 0)
  {
    log_error("Failed to create epoll instance");
    close(listen_fd);
    return false;
  }

  // Add listening socket to epoll
  struct epoll_event ev;
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = listen_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0)
  {
    log_error("Failed to add listen socket to epoll");
    close(listen_fd);
    close(epoll_fd);
    return false;
  }

  log_info("HTTP server initialized");
  return true;
}

void HgServer::run()
{
  running = true;
  struct epoll_event events[MAX_EVENTS];
  while (running)
  {
    int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, TIMEOUT);
    if (num_events == -1)
    {
      if (errno == EINTR)
        continue;
      log_error("run: epoll_wait failed");
      break;
    }

    for (int i = 0; i < num_events; i++)
    {
      int fd = events[i].data.fd;
      if (fd == listen_fd)
      {
        accept_connections();
      }
      else if (events[i].events & EPOLLIN)
      {
        handle_readable(fd);
      }
      else if (events[i].events & EPOLLOUT)
      {
        handle_writable(fd);
      }
    }
  }
}

void HgServer::stop()
{
  running = false;
}

void HgServer::accept_connections()
{
  while (true)
  {
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        break; // No more connections
      log_error("accept_connections: accept failed");
      break;
    }

    // Set non-blocking mode
    if (fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1)
    {
      log_error("accept_connections: fcntl() failed");
      close(client_fd);
      continue;
    }

    // Add new connection to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0)
    {
      log_error("accept_connections: Failed to add client socket to epoll");
      close(client_fd);
      continue;
    }

    // Create HgConnection object for this client
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str));
    connections[client_fd] = std::make_unique<HgConnection>(client_fd, std::string(ip_str));
    std::string msg = "new connection: " + std::string(ip_str);
    log_debug(msg.c_str());
  }
}
void HgServer::handle_readable(int fd)
{
  auto it = connections.find(fd);
  if (it == connections.end())
    return;

  HgConnection *conn = it->second.get();
  conn->on_readable();

  if (conn->state == ConnectionState::WRITING)
  {
    // TODO: call router here, queue_response — wire in when hg_router is done
    // For now switch epoll to EPOLLOUT
    struct epoll_event ev;
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
  }
  else if (conn->state == ConnectionState::CLOSED)
  {
    remove_connection(fd);
  }
}

void HgServer::handle_writable(int fd)
{
  auto it = connections.find(fd);
  if (it == connections.end())
    return;

  HgConnection *conn = it->second.get();
  conn->on_writable();

  if (conn->state == ConnectionState::CLOSED)
  {
    remove_connection(fd);
  }
}

void HgServer::remove_connection(int fd)
{
  auto it = connections.find(fd);
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
  if (it != connections.end())
  {
    connections.erase(it);
  }
}
