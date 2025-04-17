#include "logger.h"

Logger* Logger::instance = nullptr;

Logger::Logger(std::string logDir, std::string logModuleName, LogLevel logLevel, bool outputToTerminal) {
    this->logDir = logDir;
    this->logModuleName = logModuleName;
    this->logLevel = logLevel;
    this->outputToTerminal = outputToTerminal;
    logConfigFile = "./logger.conf";   // 日志配置文件名称
}
Logger::~Logger() {
    running = false; 
}

Logger* Logger::getInstance(std::string logDir, std::string logModuleName, LogLevel logLevel, bool outputToTerminal) // 获取单例对象
{
    if (instance == nullptr) {
        instance = new Logger(logDir, logModuleName, logLevel, outputToTerminal);
    }
    return instance;    
}

void Logger::start() 
{
    running = true;
    logCreateDate = getDate();  // 获取当前日期
    createLogDir();     // 创建日志目录
    createLogFile();    // 创建日志文件
    // 启动日志处理线程
    logThread = std::thread([this]() {
        // std::cout << "日志处理线程启动" << std::endl;
        while(running) {
            while(!logQueue.empty())  {
                std::unique_lock<std::mutex> lock(logQueueMtx);  // 加锁
                cv.wait(lock, [this]() { return !logQueue.empty() || !running; });
                if (!running) break;
                auto& msg = logQueue.front();
                if(msg.level >= logLevel) writeLog(msg.level, msg.time, msg.message); // 写入日志
                logQueue.pop();
            }
            LOG_SLEEP(10); // 等待10毫秒
        }
        // std::cout << "日志处理线程结束" << std::endl;
    });
    // 启动定时器线程,定时读取日志配置文件
    timerThread = std::thread([this]() {
        // std::cout << "定时器线程启动" << std::endl;
        while(running) {
            if (this->checkConfigFileChange()) {
                this->loadConfig();
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        // std::cout << "定时器线程结束" << std::endl;
    });
    LOG_SLEEP(100); // 等待日志处理线程启动
}

void Logger::log(LogLevel level, const char* fmt, ...) 
    {
        if(!running) return;
        va_list args;
        va_start(args, fmt);
        std::string message = format(fmt, args);
        va_end(args);
        addLogQueue(level, message);
    }
void Logger::createLogDir()  // 创建日志目录 
{
#if defined(_WIN32) || defined(_WIN64)
    if (logDir.empty()) {
        logDir = "./logs";  // 默认日志目录为当前目录下的 logs 文件夹
    }
    if (logDir.back() != '\\') {
        logDir += "\\";  // 如果日志目录不以反斜杠结尾，则添加反斜杠
    }
    if (CreateDirectory(logDir.c_str(), NULL)) {
        std::cout << "目录创建成功: " << logDir.c_str() << std::endl;
    } else {
        DWORD error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
            std::cout << "目录已存在: " << logDir.c_str() << std::endl;
        } else {
            std::cout << "创建目录失败，错误码: " << error << std::endl;
        }
    }
#else
    std::stringstream ss(logDir);
    std::string dir;
    std::string currentPath = "";
    while (std::getline(ss, dir, '/')) {
        if (dir.empty()) continue;
        if (currentPath.empty()) {
            currentPath = dir;
        } else {
            currentPath += "/" + dir;
        }
        if (access(currentPath.c_str(), F_OK) != 0) {
            if (mkdir(currentPath.c_str(), 0755) == -1) {
                std::cerr << "Failed to create directory: " << currentPath << std::endl;
                return;
            }
        }
    }
#endif
}
void Logger::createLogFile()  // 创建日志文件
{
#if defined(_WIN32) || defined(_WIN64)
    logFileName = getCurrentLogFileName();
    // 创建并打开日志文件
    logFileHandle = CreateFile(logFileName.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (logFileHandle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create log file: " << logFileName << std::endl;
        return;
    }
    // 设置文件指针到文件末尾
    SetFilePointer(logFileHandle, 0, NULL, FILE_END);
#else
    logFileName = getCurrentLogFileName();
    // 创建并打开日志文件
    logfp.open(logFileName, std::ios::app);
    if (!logfp.is_open()) {
        std::cerr << "Failed to create log file: " << logFileName << std::endl;
    }
#endif
}
void Logger::closeLogFile()  // 关闭日志文件
{
#if defined(_WIN32) || defined(_WIN64)
    if (logFileHandle != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(logFileHandle);
        CloseHandle(logFileHandle);
        std::cout << L"closeLogFile: " << logFileName << std::endl;
    }
#else
    if (logfp.is_open()) {
        logfp.flush();
        logfp.close();
        std::cout << "closeLogFile: " << logFileName << std::endl;
    }
#endif
}
void Logger::needCreateNewLogFile()  // 判断是否需要创建新的日志文件
{
    if(getDate().compare(logCreateDate) != 0) {
        // 创建新的日志文件
        createLogFile();
        logCreateDate = getDate();
        // std::cout << "create new log file: " << logCreateDate << std::endl;
    }
}
void Logger::writeLog(LogLevel level, const std::string date, const std::string& message)  // 写入日志
{
    needCreateNewLogFile();
#if defined(_WIN32) || defined(_WIN64)
    if (logFileHandle!= INVALID_HANDLE_VALUE) {      // 输出到文件
        if(level < LV_CLOSE) {
            std::string logMessage = "[" + date + "] [" + LogLevelNames[level] + "] " + message + "\r\n";
            DWORD bytesWritten = 0;
            WriteFile(logFileHandle, logMessage.c_str(), logMessage.length(), &bytesWritten, NULL);  
        }
    }
#else
    if (logfp.is_open()) {      // 输出到文件
        if(level < LV_CLOSE) logfp << "[" << date << "] [" << LogLevelNames[level] << "] " << message << std::endl;
        else logfp << "[" << date << "] " << message << std::endl;
        logfp.flush();
    }
#endif 
    if (outputToTerminal) {     // 输出到终端
        if(level < LV_CLOSE) std::cout << "[" << date << "] [" << LogLevelNames[level] << "] " << message << std::endl;
        else std::cout << "[" << date << "] " << message << std::endl;
    }
}
void Logger::addLogQueue(LogLevel level, const std::string& message) // 添加到日志队列中
{
    std::string datetime = getDateTime();
    std::unique_lock<std::mutex> lock(logQueueMtx);
    logQueue.push({level, datetime, message});
    cv.notify_one(); // 唤醒等待的线程
}

std::string Logger::format(const char *fmt, va_list args) // 格式化日志消息
    {
        va_list args_copy;
        va_copy(args_copy, args);
        int size = std::vsnprintf(NULL, 0, fmt, args_copy);
        va_end(args_copy);
        
        std::string result(size+1, '\0');
        std::vsnprintf(&result.front(), size+1, fmt, args);

        return result;
    }
bool Logger::checkConfigFileChange()  // 检查日志配置文件是否有变化
{
#if defined(_WIN32) || defined(_WIN64)
    // 在 Windows 下使用 GetFileAttributesEx 和 FILETIME
    FILE_BASIC_INFO fileInfo;
    HANDLE hFile = CreateFileA(
        logConfigFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        // std::cerr << "日志配置文件不存在: " << logConfigFile << std::endl;
        return false;
    }
    FILETIME lastWriteTime;
    if (!GetFileTime(hFile, NULL, NULL, &lastWriteTime)) {
        CloseHandle(hFile);
        // std::cerr << "无法获取文件时间: " << logConfigFile << std::endl;
        return false;
    }
    CloseHandle(hFile);

    // 将 FILETIME 转换为 std::time_t
    ULARGE_INTEGER ull;
    ull.LowPart = lastWriteTime.dwLowDateTime;
    ull.HighPart = lastWriteTime.dwHighDateTime;
    // FILETIME 是 100 纳秒单位，转换为秒
    std::time_t lastModified = ull.QuadPart / 10000000ULL - 11644473600ULL;
    // 检查配置文件是否被修改
    static std::time_t configFileLastModified = 0;
    if (lastModified != configFileLastModified) {
        configFileLastModified = lastModified;
        // std::cout << "日志配置文件已修改，重新加载配置文件" << std::endl;
        return true;
    }
#else
    // 检查配置文件是否存在
    struct stat fileStat;
    if (stat(logConfigFile.c_str(), &fileStat) != 0) {
        // std::cerr << "日志配置文件不存在: " << logConfigFile << std::endl;
        return false;
    }
    // 检查配置文件是否被修改
    static std::time_t configFileLastModified = 0;
    std::time_t lastModified = fileStat.st_mtime;
    if (lastModified != configFileLastModified) {
        configFileLastModified = lastModified;
        // std::cout << "日志配置文件已修改，重新加载配置文件" << std::endl;
        return true;
    }
#endif
    return false;
}
void Logger::loadConfig()  // 加载日志配置文件
{
    log_map.clear();
    std::ifstream configFile(logConfigFile);
    if (configFile.is_open()) {
        std::string line;
        while (std::getline(configFile, line)) {
            // 去除空格
            line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
            // 跳过注释行和空行
            if(line.c_str()[0] == '#' || line.c_str()[0] == ';' || line.empty()) {
                continue;
            }
            auto result = splitByEqual(line);    // 按"="拆分配置项
            if(result.first.empty() || result.second.empty()) continue;
            log_map.insert(std::pair<std::string, std::string>(result.first, result.second));
        }
        configFile.close();
        // 更新配置
        try {
            std::lock_guard<std::mutex> lock(configMtx); // 加锁，防止多线程同时修改配置
            int _logLevel = std::stoi(log_map["log_level"].c_str());
            if(_logLevel >= LV_TRACE && _logLevel <= LV_CLOSE) {
                this->logLevel = static_cast<LogLevel>(_logLevel);
                // log(LV_CLOSE, "日志输出级别变更为: %s", LogLevelNames[_logLevel].c_str()); // 记录日志级别变更日志
            }
        }
        catch(const std::exception& e) {
            std::cerr << e.what() << '\n';
        }            
    }
}
std::string Logger::getCurrentLogFileName()  // 获取当前日志文件名
{
#if defined(_WIN32) || defined(_WIN64)
    return logDir + "\\" + logModuleName + "." + getDate() + ".log";
#else
    return logDir + "/" + logModuleName + "." + getDate() + ".log";
#endif
}
std::string Logger::getDate()   // 获取当前日期
{
#if defined(_WIN32) || defined(_WIN64)
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);
    char buffer[16] = {0};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d", localTime);
    return std::string(buffer);
#else
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    // std::stringstream ss;
    // ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d");
    // return ss.str();
    // C++11兼容版本
    std::tm tm_snapshot;
    localtime_r(&in_time_t, &tm_snapshot); // 线程安全版本
    char buffer[16] = {0};
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d", &tm_snapshot);
    return std::string(buffer);
#endif
}
std::string Logger::getDateTime() // 获取当前日期和时间
{
#if defined(_WIN32) || defined(_WIN64)
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localTime);
    return std::string(buffer);
#else
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    // std::stringstream ss;
    // ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    // return ss.str();
    // C++11兼容版本
    std::tm tm_snapshot;
    localtime_r(&in_time_t, &tm_snapshot); // 线程安全版本
    char buffer[20] = {0};  // 扩大缓冲区大小
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_snapshot); // 添加时间格式
    return std::string(buffer);
#endif
}
std::pair<std::string, std::string> Logger::splitByEqual(const std::string& str) {
        size_t pos = str.find('=');
        if (pos == std::string::npos) {
            // 没有找到等号，返回空字符串作为key和value
            return std::make_pair(std::string(), std::string());
        }
        return std::make_pair(str.substr(0, pos), str.substr(pos + 1));
    }