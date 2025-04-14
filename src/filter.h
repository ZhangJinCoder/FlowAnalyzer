#ifndef FILTER_H
#define FILTER_H

#include "header.h"

class Filter {
public:
    Filter() {};
    ~Filter() {};

public:
    bool parse(unsigned char* buffer, unsigned int length); // 解析数据包
    bool parseIP(unsigned char* buffer, unsigned int length); // 解析数据包
    std::string getOnlyFlag();          // 获取唯一标识
    std::string getReverseOnlyFlag();   // 获取反向唯一标识

public:
    bool isTcpHandleShake(); // 检测是否为TCP握手包
    bool isTcpHandleClose(); // 检测是否为TCP挥手包

    std::string getSrcMac();    // 获取源MAC地址
    std::string getDstMac();   // 获取目标MAC地址
    std::string getIPVersion(); // 获取IP版本号
    std::string getProtocol();  // 获取协议类型
    std::string getSourceIP();  // 获取源IP地址
    std::string getDestIP();    // 获取目标IP地址
    std::string getURI();       // 获取URI

    unsigned short getSourcePort(); // 获取源端口号
    unsigned short getDestPort();   // 获取目标端口号

public:
    void setLocalMac(std::string localMac) {    // 设置本地MAC地址
        m_localMac = localMac;
    }
    void setLocalIp(std::string localIP) {     // 设置本地IP地址
        m_localIP = localIP;
    }
protected:
    std::string trimRight(const std::string& str);

private:
    std::string m_srcMac;   // 源MAC地址
    std::string m_dstMac;   // 目标MAC地址
    std::string m_localMac; // 本地MAC地址
    std::string m_localIP;  // 本地IP地址
    IPHeader m_ipHeader;    // IP header
};


#endif // FILTER_H
