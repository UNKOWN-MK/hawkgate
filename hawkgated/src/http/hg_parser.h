#ifndef HG_PARSER_H
#define HG_PARSER_H
#include <string>
#include <unordered_map>

typedef struct HttpRequest
{
  std::string method;
  std::string path;
  std::unordered_map<std::string, std::string> headers;
  std::string body;
  size_t content_length = 0;
  std::string version;
};

enum class ParseState
{
  REQUEST_LINE,
  HEADERS,
  BODY,
  COMPLETE,
  ERROR
};

class HgParser
{
  private:
    ParseState state =  ParseState::REQUEST_LINE;
    HttpRequest request;
    std::string buffer;
  public:
    ParseState feed(const char *data, size_t len);
    const HttpRequest& get_request() const;
    void reset();
};

#endif // end of HG_PARSER_H