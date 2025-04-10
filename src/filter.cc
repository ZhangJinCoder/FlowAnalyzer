#include "filter.h"
#include "logger.h"

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <string.h>         // 添加memset
#include <net/ethernet.h>   // 添加ETH_P_ALL
#include <netpacket/packet.h>  // 添加packet_mreq等定义
#include <sys/ioctl.h>      // 添加ioctl
#include <net/if.h>         // 添加ifreq和IFNAMSIZ

bool Filter::parse(unsigned char *buffer, unsigned int length)
{
    struct ethhdr* eth = (struct ethhdr*)buffer;
    // 输出MAC地址 60:db:15:73:46:01
    char srcMac[32] = {0}, dstMac[32] = {0};
    snprintf(srcMac, 32, "%02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    snprintf(dstMac, 32, "%02x:%02x:%02x:%02x:%02x:%02x\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    m_srcMac = trimRight(srcMac);
    m_dstMac = trimRight(dstMac);
    // ETH_P_IP: 0x0800, ETH_P_IPV6: 0x86dd, ETH_P_ARP: 0x0806
    if (ntohs(eth->h_proto) == ETH_P_IP || ntohs(eth->h_proto) == ETH_P_IPV6) { 
        // 跳过以太网头部(14字节)后才是IP头
        struct iphdr* ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        return parseIP((unsigned char*)(buffer+14), (length-14)); // 跳过以太网头部(14字节)后才是IP头
    } 
    else if(ntohs(eth->h_proto) == ETH_P_ARP) {
        // ARP协议
        LOG_DEBUG("ARP协议");
    }
    else if(ntohs(eth->h_proto) == ETH_P_8021Q) {
        // VLAN协议
        LOG_DEBUG("VLAN协议");
    }
    else if(ntohs(eth->h_proto) == ETH_P_PPP_MP) {
        // PPP协议
        LOG_DEBUG("PPP协议");
    }
    else {
        LOG_WARN("未知协议: 0x%04x", ntohs(eth->h_proto));
    }
    return false;
}

bool Filter::parseIP(unsigned char *buffer, unsigned int length)
{
    int parse_len = 0;
    if(length >= 8192) parse_len = 8192;   // 默认header头不得大于(8192-20byte)字节
    else if(length >= 60) parse_len = length; // ipv6_tcp协议
    else if(length >= 48) parse_len = 48;  // ipv6_udp协议      
    else if(length >= 40) parse_len = 40;  // ipv4_tcp|ipv6协议
    else if(length >= 28) parse_len = 28;  // udp协议
    else if(length >= 20) parse_len = 20;  // ipv4协议
    // LOG_DEBUG("len: %d, parse_len: %d\n", len, parse_len); // 日志太多，暂时注释
    m_ipHeader = IPHeader(buffer, parse_len);
    return true;
}

std::string Filter::getOnlyFlag()
{
    return m_ipHeader._onlyFlag;
}

std::string Filter::getReverseOnlyFlag()
{
    return m_ipHeader._reverseOnlyFlag;
}

bool Filter::isTcpHandleShake()
{
    // 判断是否是tcp握手包
    if( m_ipHeader._isHandleShake == 1) {
        return true;
    }
    return false;
}

bool Filter::isTcpHandleClose()
{
    // 判断是否是tcp挥手包
    if(m_ipHeader._isHandleShake == 2) {
        return true;
    }
    return false;
}

std::string Filter::getSrcMac()
{
    return m_srcMac;
}

std::string Filter::getDstMac()
{
    return m_dstMac;
}

std::string Filter::getIPVersion()
{
    if(m_ipHeader._version == 4) {
        return std::string("IPv4");
    }
    else if(m_ipHeader._version == 6) {
        return std::string("IPv6");
    }
    return std::string();
}

std::string Filter::getProtocol()
{
    return m_ipHeader._protocol;
}

std::string Filter::getSourceIP()
{
    return m_ipHeader._src_ip;
}

std::string Filter::getDestIP()
{
    return m_ipHeader._dst_ip;
}

std::string Filter::getURI()
{
    if(m_ipHeader._protocol == "HTTP" || m_ipHeader._protocol == "TCP") {
        return m_ipHeader.tcpheader.httpheader.uri;
    }
    return std::string();
}

unsigned short Filter::getSourcePort()
{
    if(m_ipHeader._protocol == "TCP" || m_ipHeader._protocol == "UDP" || m_ipHeader._protocol == "HTTP") {
        return m_ipHeader._src_port;
    }
    return 0;
}

unsigned short Filter::getDestPort()
{
    if(m_ipHeader._protocol == "TCP" || m_ipHeader._protocol == "UDP" || m_ipHeader._protocol == "HTTP") {
        return m_ipHeader._dst_port;
    }
    return 0;
}

std::string Filter::trimRight(const std::string &str)
{
    // 找到字符串中最后一个非空格和非换行符的字符位置
    auto it = std::find_if(
        str.rbegin(), str.rend(),
        [](char c) { return !std::isspace(static_cast<unsigned char>(c)); }
    );
    // 如果字符串为空或全是空格/换行符，返回空字符串
    if (it == str.rend()) {
        return "";
    }
    // 返回从字符串开头到找到的字符位置的子字符串
    return std::string(str.begin(), std::next(it).base());
}
