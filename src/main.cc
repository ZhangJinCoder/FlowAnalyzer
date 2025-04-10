#include <iostream>
#include "logger.h"
#include "analyzer.h"

int main() {
    // 初始化日志模块
    Logger::getInstance("./logs", "logger", LV_TRACE, false)->start();
    // 初始化分析器
    Analyzer::getInstance()->start();
    // 等待分析器结束
    while (true) {
        Analyzer::getInstance()->clearScreen();
        Analyzer::getInstance()->printMacIpInfo();  // 打印MAC/IP信息
        // Analyzer::getInstance()->printIpCount();    // 打印访问次数
        sleep(1);
    }
    return 0;
}