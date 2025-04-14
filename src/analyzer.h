#ifndef ANALYZER_H
#define ANALYZER_H
#include "filter.h"
#include <iostream>
#include <thread>
#include <map>

struct InterfaceInfo {
    std::string name;       // 网络接口名称
    std::string ipAddress;  // IP地址
    std::string macAddress; // MAC地址
};
typedef std::vector<InterfaceInfo> InterfaceInfoVector; // 网络接口信息向量

typedef struct {
    bool isVPN;             // 是否是VPN流量
    std::string srcMac;     // 源MAC地址
    std::string dstMac;     // 目标MAC地址
    std::string ipVersion;  // IP版本号 
    std::string protocol;   // 协议类型
    std::string srcIp;      // 源IP地址
    std::string dstIp;      // 目标IP地址
    std::string srcPort;    // 源端口
    std::string dstPort;    // 目标端口
    std::string uri;        // URI
} MacIpInfo;
typedef std::map<std::string, unsigned int> IpCountMap; // 唯一标识->访问次数的映射表
typedef std::map<std::string, MacIpInfo> MacIpMap;      // 唯一标识->MAC/IP信息的映射表

class Analyzer {
public:
    Analyzer() {};
    ~Analyzer() {};
    static Analyzer* getInstance();   // 获取单例对象
    static void destroyInstance();    // 销毁单例对象

public:
    int start();
    int flowThread();
    MacIpInfo getMacIpInfo(const std::string& onlyFlag);    // 获取MAC/IP信息
    unsigned int getIpCount(const std::string& onlyFlag);   // 获取访问次数

    void printIpCount();

protected:
    // 添加、删除MAC/IP信息到映射表
    void addMacIpInfo(const std::string& onlyFlag, const MacIpInfo& macIpInfo);
    bool delMacIpInfo(const std::string& onlyFlag);
    void setIsVPN(const std::string& onlyFlag);         // 设置为VPN流量
    void showMacIpInfo(const std::string& onlyFlag);    // 显示MAC/IP信息
    // 添加、删除访问次数到映射表
    void addIpCount(const std::string& onlyFlag);
    void updateIpCount(const std::string& onlyFlag);
    bool delIpCount(const std::string& onlyFlag);

    // 获取网卡信息
    InterfaceInfoVector getNetworkInfo();
    // 打印网卡信息
    void printNetworkInfo(const InterfaceInfoVector& interfaces);

    std::string getString(const std::string& prompt); // 获取字符串输入

public:
    void clearScreen(); // 清屏
    int str2int(const std::string& str); // 字符串转整数

private:
    Filter m_filter;            // 过滤器对象
    MacIpMap m_macIpMap;        // 唯一标识->MAC/IP信息的映射表
    IpCountMap m_ipCountMap;    // 唯一标识->访问次数的映射表
    InterfaceInfo m_interface;  // 网络接口信息
    static Analyzer* instance;  // 单例对象指针
    std::shared_ptr<std::thread> m_thread;  // 线程对象指针
};


#endif // ANALYZER_H
