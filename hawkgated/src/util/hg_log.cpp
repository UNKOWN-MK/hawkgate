#include "hg_log.h"
#include <cstdio>
#include <ctime>

void log_message(LogLevel level, const char* message, src_loc loc)
{
    const char* prefix = "[UNKNOWN]";
    switch (level)
    {
        case LogLevel::DEBUG:
            prefix = "[DEBUG]";
            break;
        case LogLevel::INFO:
            prefix = "[INFO]";
            break;
        case LogLevel::WARNING:
            prefix = "[WARNING]";
            break;
        case LogLevel::ERROR:
            prefix = "[ERROR]";
            break;
    }
    std::time_t current= std::time(nullptr);
    char time_str[20];
    std::strftime(time_str, sizeof(time_str), \
    "%Y-%m-%d %H:%M:%S", std::localtime(&current));
    fprintf(stderr, "[%s] %s %s:%u %s\n",
        time_str, prefix,
        loc.file_name(), 
        loc.line(),
        message);

}

void log_info(const char* message,src_loc loc)
{
    log_message(LogLevel::INFO, message,loc);
}

void log_error(const char* message,src_loc loc)
{
    log_message(LogLevel::ERROR, message,loc);
}

void log_warning(const char* message,src_loc loc)
{
    log_message(LogLevel::WARNING, message,loc);
}

void log_debug(const char* message,src_loc loc)
{
    log_message(LogLevel::DEBUG, message,loc);
}