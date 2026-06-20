#include "hg_parser.h"

void HgParser::reset()
{
  state = ParseState::REQUEST_LINE;
  request = HttpRequest();
  buffer.clear();
}

const HttpRequest &HgParser::get_request() const
{
  return request;
}

ParseState HgParser::feed(const char *data, size_t len)
{
  buffer.append(data, len);

  while (true)
  {
    switch (state)
    {
    case ParseState::REQUEST_LINE:
    {
      size_t pos = buffer.find("\r\n");
      if (pos == std::string::npos)
        return state;

      std::string line = buffer.substr(0, pos);
      buffer.erase(0, pos + 2);

      size_t p1 = line.find(' ');
      size_t p2 = line.find(' ', p1 + 1);
      if (p1 == std::string::npos || p2 == std::string::npos)
      {
        state = ParseState::ERROR;
        return state;
      }
      request.method = line.substr(0, p1);
      request.path = line.substr(p1 + 1, p2 - p1 - 1);
      request.version = line.substr(p2 + 1);
      state = ParseState::HEADERS;
      break;
    }
    case ParseState::HEADERS:
    {
      size_t pos = buffer.find("\r\n");
      if (pos == std::string::npos)
        return state;

      std::string line = buffer.substr(0, pos);
      buffer.erase(0, pos + 2);

      if (line.empty())
      {
        state = (request.content_length > 0)
                    ? ParseState::BODY
                    : ParseState::COMPLETE;
        break;
      }

      size_t colon = line.find(':');
      if (colon == std::string::npos)
      {
        state = ParseState::ERROR;
        return state;
      }
      std::string key = line.substr(0, colon);
      std::string value = line.substr(colon + 1);
      if (!value.empty() && value[0] == ' ')
        value.erase(0, 1);

      request.headers[key] = value;

      if (key == "Content-Length")
      {
        try
        {
          request.content_length = std::stoul(value);
        }
        catch (...)
        {
          state = ParseState::ERROR;
          return state;
        }
      }
      break;
    }
    case ParseState::BODY:
    {
      if (buffer.size() >= request.content_length)
      {
        request.body = buffer.substr(0, request.content_length);
        buffer.erase(0, request.content_length);
        state = ParseState::COMPLETE;
      }
      else
        return state;
      break;
    }
    case ParseState::COMPLETE:
    case ParseState::ERROR:
      return state;
    }
  }
}
