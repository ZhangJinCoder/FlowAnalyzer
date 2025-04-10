#include "analyzer.h"
#include "filter.h"
#include "logger.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <string.h>  // 添加memset
#include <net/ethernet.h>  // 添加ETH_P_ALL
#include <netpacket/packet.h>  // 添加packet_mreq等定义
#include <sys/ioctl.h>  // 添加ioctl
#include <net/if.h>      // 添加ifreq和IFNAMSIZ

// 初始化静态成员变量
Analyzer* Analyzer::instance = nullptr;

Analyzer *Analyzer::getInstance()
{
    if (instance == nullptr) {
        instance = new Analyzer();
    }
    return instance;
}

void Analyzer::destroyInstance()
{
    if (instance != nullptr) {
        delete instance;
        instance = nullptr;
    }
}

int Analyzer::start()
{
    m_thread = std::make_shared<std::thread>(&Analyzer::flowThread, this);

    return 0;
}

int Analyzer::flowThread()
{
    LOG_INFO("Analyzer started.");
    // 获取网络接口索引
    struct ifreq ifr;
    // strncpy(ifr.ifr_name, "enp6s0", IFNAMSIZ);
    strncpy(ifr.ifr_name, "enp3s0", IFNAMSIZ);
    
    // 创建原始套接字
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    // 获取接口索引
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sockfd);
        return 1;
    }

    // 设置混杂模式
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifr.ifr_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    if (setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
        perror("setsockopt PACKET_ADD_MEMBERSHIP");
        close(sockfd);
        return 1;
    }

    // 修改绑定地址结构
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    char buffer[65535] = {0};
    while (true) {
        ssize_t bytes_received = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (bytes_received < 0) {
            perror("recvfrom");
            break;
        }
        // std::cout << "Received " << bytes_received << " bytes" << std::endl;
        
        bool ret = m_filter.parse((unsigned char*)buffer, bytes_received);
        if(!ret) { // 解析失败，跳过
            continue;
        }
        if (m_filter.isTcpHandleShake()) {          // 检测到TCP握手包
            addIpCount(m_filter.getOnlyFlag());     // 增加访问次数
            MacIpInfo macIpInfo;
            macIpInfo.isVPN = false;                                        // 默认为非VPN流量
            macIpInfo.srcMac = m_filter.getSrcMac();                        // 获取源MAC地址
            macIpInfo.dstMac = m_filter.getDstMac();                        // 获取目标MAC地址
            macIpInfo.ipVersion = m_filter.getIPVersion();                  // 获取IP版本号
            macIpInfo.protocol = m_filter.getProtocol();                    // 获取协议类型
            macIpInfo.srcIp = m_filter.getSourceIP();                       // 获取源IP地址
            macIpInfo.dstIp = m_filter.getDestIP();                         // 获取目标IP地址
            macIpInfo.srcPort = std::to_string(m_filter.getSourcePort());   // 获取源端口号
            macIpInfo.dstPort = std::to_string(m_filter.getDestPort());     // 获取目标端口号
            macIpInfo.uri = m_filter.getURI();                              // 获取URI            
            addMacIpInfo(m_filter.getOnlyFlag(), macIpInfo);                // 添加MAC/IP信息
            LOG_INFO("TCP连接建立 唯一标识: %s", m_filter.getOnlyFlag().c_str()); // 打印日志
        } else if (m_filter.isTcpHandleClose()) {   // 检测到TCP挥手包
#if 1
            if(getMacIpInfo(m_filter.getOnlyFlag()).isVPN || getMacIpInfo(m_filter.getReverseOnlyFlag()).isVPN) {
                LOG_INFO("VPN连接关闭 接收:%d, 发送:%d, 唯一标识:%s", 
                    getIpCount(m_filter.getOnlyFlag()), getIpCount(m_filter.getReverseOnlyFlag()), m_filter.getOnlyFlag().c_str());    // 打印日志
            } 
            else {
                LOG_INFO("TCP连接关闭 接收:%d, 发送:%d, 唯一标识:%s", 
                    getIpCount(m_filter.getOnlyFlag()), getIpCount(m_filter.getReverseOnlyFlag()), m_filter.getOnlyFlag().c_str());    // 打印日志
            }
            delIpCount(m_filter.getOnlyFlag());             // 删除访问次数
            delMacIpInfo(m_filter.getOnlyFlag());           // 删除MAC/IP信息
            delIpCount(m_filter.getReverseOnlyFlag());      // 删除访问次数
            delMacIpInfo(m_filter.getReverseOnlyFlag());    // 删除MAC/IP信息
#endif 
        } 
        if(bytes_received == 63 && std::string(buffer + 54, 9) == std::string("vpnclient")) {
            setIsVPN(m_filter.getOnlyFlag()); // 设置为VPN流量
        }
        addIpCount(m_filter.getOnlyFlag()); // 增加访问次数
    }

    close(sockfd);
    return 0;
}

MacIpInfo Analyzer::getMacIpInfo(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return MacIpInfo(); // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    MacIpMap::iterator it = m_macIpMap.find(onlyFlag);
    if (it!= m_macIpMap.end()) {
        return it->second;
    }
    return MacIpInfo();
}

unsigned int Analyzer::getIpCount(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return 0; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    IpCountMap::iterator it = m_ipCountMap.find(onlyFlag);
    if (it!= m_ipCountMap.end()) {
        return it->second; 
    }
    return 0;
}

void Analyzer::printMacIpInfo()
{
    for (MacIpMap::iterator it = m_macIpMap.begin(); it != m_macIpMap.end(); ++it) {
        std::cout << it->first << " " << it->second.srcMac << std::endl;
    }
}

void Analyzer::printIpCount()
{
    std::cout << std::left << std::setw(64) << "唯一标识" << "     " << "访问次数" << std::endl;
    for (IpCountMap::iterator it = m_ipCountMap.begin(); it!= m_ipCountMap.end(); ++it) {
        std::cout << std::left << std::setw(64) << it->first << " " << it->second << std::endl;
    }
}

void Analyzer::addMacIpInfo(const std::string &onlyFlag, const MacIpInfo &macIpInfo)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    MacIpMap::iterator it = m_macIpMap.find(onlyFlag);
    if (it!= m_macIpMap.end()) {
        it->second = macIpInfo;
    }
    m_macIpMap[onlyFlag] = macIpInfo;
}

bool Analyzer::delMacIpInfo(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    MacIpMap::iterator it = m_macIpMap.find(onlyFlag);
    if (it == m_macIpMap.end()) {
        return false;
    }
    m_macIpMap.erase(onlyFlag);
    return true;
}

void Analyzer::setIsVPN(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    MacIpMap::iterator it = m_macIpMap.find(onlyFlag);
    if (it!= m_macIpMap.end()) {
        it->second.isVPN = true;
        // LOG_INFO("设置VPN标志: %s isVPN: %d", onlyFlag.c_str(), it->second.isVPN);
    }
}

void Analyzer::showMacIpInfo(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    MacIpMap::iterator it = m_macIpMap.find(onlyFlag);
    if (it!= m_macIpMap.end()) {
        MacIpInfo macIpInfo = it->second;     
        LOG_DEBUG("[%s] -> [%s] IP版本: %s, 协议: %s, 源IP: %s, 目的IP: %s, 源端口: %s, 目的端口: %s, URI: %s", 
            macIpInfo.srcMac.c_str(), macIpInfo.dstMac.c_str(), macIpInfo.ipVersion.c_str(), macIpInfo.protocol.c_str(), macIpInfo.srcIp.c_str(), macIpInfo.dstIp.c_str(), macIpInfo.srcPort.c_str(), macIpInfo.dstPort.c_str(), macIpInfo.uri.c_str());
    } 
}

void Analyzer::addIpCount(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    IpCountMap::iterator it = m_ipCountMap.find(onlyFlag);
    if (it != m_ipCountMap.end()) {
        it->second++;
    } else {
        m_ipCountMap[onlyFlag] = 1;
    }
}

bool Analyzer::delIpCount(const std::string &onlyFlag)
{
    if(onlyFlag.empty()) return; // 空字符串不处理(可能是TCP握手包，不需要记录访问次数)
    IpCountMap::iterator it = m_ipCountMap.find(onlyFlag);
    if (it != m_ipCountMap.end()) {
        return false;
    }
    m_ipCountMap.erase(onlyFlag);
    return true;
}

void Analyzer::clearScreen()
{
    // ANSI escape code for clearing the screen
    std::cout << "\033[2J\033[H";
    std::cout.flush(); // 确保控制序列立即发送到终端
}
