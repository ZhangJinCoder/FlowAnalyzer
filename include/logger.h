#ifndef LOGGER_H
#define LOGGER_H
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <cstdarg>
#include <mutex>
#include <map>
#include <queue>
#include <thread>
#include <fstream>
#include <algorithm>
#include <condition_variable>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
// #include <sys/stat.h>
#include <io.h>
#include <direct.h>
#else
#include <chrono>
#include <ctime>
#include <unistd.h>
#include <iomanip>
#include <sstream>
#include <string.h>
#include <sys/types.h>
#include <iomanip>
#endif

// 日志级别枚举
enum LogLevel {
    LV_TRACE,  // 跟踪信息
    LV_DEBUG,  // 调试信息
    LV_INFO,   // 普通信息
    LV_WARN,   // 告警信息
    LV_ERROR,  // 错误信息
    LV_FATAL,  // 严重错误
    LV_CLOSE,  // 关闭日志
};

// 日志级别名称
const std::string LogLevelNames[] = {
    "TRACE",    // 跟踪信息
    "DEBUG",    // 调试信息
    "INFO*",    // 普通信息
    "WARN*",    // 告警信息
    "ERROR",    // 错误信息
    "FATAL",    // 严重错误
    "CLOSE",    // 关闭日志
};

// 日志内容结构体
struct LogMessage {
    LogLevel level;         // 日志级别
    std::string time;       // 日志时间
    std::string message;    // 日志内容
};

#if defined(_WIN32) || defined(_WIN64)  
#define LOG_SLEEP(n) Sleep(n);  // 单位为毫秒    
#else 
#define LOG_SLEEP(n) usleep(1000 * n);  // 单位为毫秒
#endif

class Logger {
private:
    bool running;           // 是否运行
    bool outputToTerminal;  // 是否输出到终端
    LogLevel logLevel;      // 日志级别
    std::string logDir;     // 日志目录
    std::string logModuleName;  // 日志模块名称
    std::string logFileName;    // 日志文件名
    std::string logCreateDate;  // 日志创建日期
    std::string logConfigFile;  // 日志配置文件

public:
    // 禁止拷贝构造函数和赋值运算符
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger() = delete;
    Logger(std::string logDir, std::string logModuleName, LogLevel logLevel, bool outputToTerminal);
    ~Logger();
    static Logger* getInstance(std::string logDir = "./logs", std::string logModuleName = "default", LogLevel logLevel = LogLevel::LV_INFO, bool outputToTerminal = true); // 获取单例对象
    void start();

public:
    void log(LogLevel level, const char* fmt, ...);
    void createLogDir();  // 创建日志目录 
    void createLogFile();  // 创建日志文件
    void closeLogFile();  // 关闭日志文件
    void needCreateNewLogFile();  // 判断是否需要创建新的日志文件
    void writeLog(LogLevel level, const std::string date, const std::string& message);  // 写入日志
    void addLogQueue(LogLevel level, const std::string& message); // 添加到日志队列中

protected:
    std::string format(const char *fmt, va_list args); // 格式化日志消息
    bool checkConfigFileChange();  // 检查日志配置文件是否有变化
    void loadConfig();  // 加载日志配置文件
    std::string getCurrentLogFileName();  // 获取当前日志文件名
    std::string getDate();   // 获取当前日期
    std::string getDateTime(); // 获取当前日期和时间
    std::pair<std::string, std::string> splitByEqual(const std::string& str);

private:
    static Logger* instance;    // 单例实例指针(需要c++14以上版本支持)

#if defined(_WIN32) || defined(_WIN64)
    HANDLE logFileHandle;  // 日志文件句柄
#else
    std::ofstream logfp{nullptr};       // 日志文件流
#endif
    std::mutex configMtx;               // 配置变量互斥锁
    std::mutex logQueueMtx;             // 日志队列互斥锁
    std::queue<LogMessage> logQueue;    // 日志队列
    std::thread logThread;              // 日志线程成员变量
    std::thread timerThread;            // 定时器线程成员变量
    std::condition_variable cv;         // 条件变量(日志队列)用于线程同步
    std::map<std::string, std::string> log_map;     // 配置检查信息
};

inline static const char* my_basename(const char* path) {
#if defined(_WIN32) || defined(_WIN64)
    const char* base = strrchr(path, '\\');
    return base? base+1 : path;
#else
    const char* base = strrchr(path, '/');
    return base? base+1 : path;
#endif
}
#define __FILENAME__ my_basename(__FILE__)
// 定义一个通用的日志宏
#define LOG(level, fmt, ...) \
    do { \
        Logger* logger = Logger::getInstance(); \
        if (logger) { \
            logger->log(level, "[%s:%d] " fmt, __FILENAME__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)
// 使用通用日志宏定义具体的日志级别宏
#define LOG_TRACE(fmt, ...) LOG(LV_TRACE, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) LOG(LV_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  LOG(LV_INFO, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  LOG(LV_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) LOG(LV_ERROR, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) LOG(LV_FATAL, fmt, ##__VA_ARGS__)

#endif // LOGGER_H