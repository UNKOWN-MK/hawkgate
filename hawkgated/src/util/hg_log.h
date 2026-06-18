#ifndef HG_LOG_H
#define HG_LOG_H

#include <source_location>

typedef std::source_location src_loc;

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

void log_message(LogLevel level, const char* message,src_loc loc);
void log_info(const char* message,src_loc loc = src_loc::current());
void log_error(const char* message,src_loc loc = src_loc::current());
void log_warning(const char* message,src_loc loc = src_loc::current());
void log_debug(const char* message,src_loc loc = src_loc::current());
#endif // HG_LOG_H