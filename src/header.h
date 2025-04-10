#ifndef _IP_PARSER_H_
#define _IP_PARSER_H_

#include <iostream>
#include <sstream>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>

struct HttpHeader 
{
    std::string method;            // 请求方法
    std::string uri;               // 请求URL
    std::string version;           // http版本
};


#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

struct TcpHeader 
{
    uint16_t  th_sport;     // 源端口(16位)
    uint16_t  th_dport;     // 目标端口(16位)
    // ...
    uint32_t  th_seq;       // 序列号(32位)
    uint32_t  th_ack;       // 确认号(32位)
    uint32_t  th_offx;      // 数据偏移(4位长度+6位保留字段)
    uint32_t  th_flags;     // 标志位(6位(URG、ACK、PSH、RST、SYN、FIN))
    uint16_t  th_win;       // 窗口大小(16位)
    uint16_t  th_sum;       // 校验和(16位)
    uint16_t  th_urp;       // 紧急指针(16位)

    uint8_t isHttpProtocol; // 是否是http协议(0:否, 1:是)
    uint8_t isHandleShake;  // 是否是握手/挥手数据包(0:否, 1:握手包, 2:挥手包)
    HttpHeader httpheader;  // http头信息

    void printHeader() 
    {
        std::stringstream ss;
        ss << std::endl;
        ss << "源端口: " << th_sport << std::endl;
        ss << "目的端口: " << th_dport << std::endl;
        ss << "序列号: " << th_seq << std::endl;
        ss << "确认号: " << th_ack << std::endl;
        ss << "长度: " << th_offx << std::endl;
        ss << "标志位: " << th_flags << std::endl;
        ss << "窗口大小: " << th_win << std::endl;
        ss << "校验和: " << th_sum << std::endl;
        ss << "紧急指针: " << th_urp << std::endl;
        std::string tcpHeaderStr = ss.str();
        // LOG_DEBUG("TCP_Header: %s", tcpHeaderStr.c_str());
    }
};

struct UdpHeader 
{
    uint16_t  uh_sport;     // 源端口
    uint16_t  uh_dport;     // 目标端口
    // ...
    uint16_t  uh_len;       // 数据长度
    uint16_t  uh_sum;       // 校验和

    void printHeader() 
    {
        std::stringstream ss;
        ss << std::endl;
        ss << "源端口: " << uh_sport << std::endl;
        ss << "目的端口: " << uh_dport << std::endl;
        std::string udpHeaderStr = ss.str();
        // LOG_DEBUG("UDP_Header: %s", udpHeaderStr.c_str());
    }
};

struct IPHeader 
{
#if 0
    // ipv4协议使用
    uint8_t version: 4;         // IP协议版本号
    uint8_t ihl:4;              // 头部长度
    uint8_t tos;                // 服务类型(3位优先权字段+4位TOS字段+1位保留字段(须为0))
    uint16_t tot_len;           // 总长度
    uint16_t id;                // 标识
    uint16_t frag_off;          // 标志(3位)位偏移(13位)
    uint8_t ttl;                // 生存时间
    uint8_t protocol;           // 协议(ICMP:1, TCP:6, UDP:17)
    uint16_t check;             // 头部校验和
    struct in_addr saddr;       // 源IP地址
    struct in_addr daddr;       // 目标IP地址
    unsigned char *options;     // 如果存在选项字段，就保存在这里
    // ipv6协议使用
#endif 
    // 通用
    uint16_t _isHandleShake;    // 是否所TCP握手协议包(true/false)
    uint16_t _version;          // 协议版本(4/6)
    std::string _protocol;      // 协议名称(TCP/UDP/ICMP/HTTP)
    std::string _src_ip;        // 源IP地址(ipv4/ipv6)
    std::string _dst_ip;        // 目标IP地址(ipv4/ipv6)
    uint16_t _src_port;         // 源端口
    uint16_t _dst_port;         // 目标端口

    // 解析协议头后的唯一标识码
    std::string _onlyFlag;          // 协议_源IP_源端口_目的IP_目的端口(_URI)
    std::string _reverseOnlyFlag;   // 协议_目的IP_目的端口_源IP_源端口(_URI)

    TcpHeader tcpheader;
    UdpHeader udpheader;

    int checkPacketVersion(unsigned char *buffer)
    {
        struct iphdr *ipv4h = (struct iphdr *) buffer;
        //  IP版本信息在首部的第一个字节，我们只需要查看前4个位
        int version = ipv4h->version; 
        if (version == 4) {
            return 4;
        } else if (version == 6) {
            return 6;
        }
        return version;
    }

    // 解析udp数据包
    bool udpData(unsigned char *buffer, unsigned int len) {
        if(len < 8) return false;
        struct udphdr *udph = (struct udphdr*)(buffer);
        udpheader.uh_sport = ntohs(udph->source);
        udpheader.uh_dport = ntohs(udph->dest);
        _src_port = udpheader.uh_sport;
        _dst_port = udpheader.uh_dport;
        // LOG_DEBUG("UDP Header: SourcePort: %d, DestPort: %d, Length: %d, Checksum: %d\n", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len), ntohs(udph->check));
        return true;
    }

    // 判断是否是TCP握手包
    bool tcpHelloHandle(unsigned char *buffer, unsigned int len) {
        if(len < 20) return false;
        // 判断是否为TCP握手协议包
        struct tcphdr *tcph = (struct tcphdr*)(buffer);
        tcpheader.th_sport = ntohs(tcph->source);
        tcpheader.th_dport = ntohs(tcph->dest);
        tcpheader.th_seq = ntohl(tcph->seq);
        tcpheader.th_ack = ntohl(tcph->ack_seq);            
        tcpheader.th_offx = tcph->doff;
        // tcpheader.th_flags = tcph->th_flags;     // centos-x86_64上缺少此项
        tcpheader.th_win = ntohs(tcph->window);
        tcpheader.th_sum = ntohs(tcph->check);
        tcpheader.th_urp = ntohs(tcph->urg_ptr);
        // tcpheader.printHeader();
        bool fin_flag = tcph->fin;
        bool syn_flag = tcph->syn;
        bool rst_flag = tcph->rst;
        bool psh_flag = tcph->psh;
        bool ack_flag = tcph->ack;
        bool urg_flag = tcph->urg;
        // LOG_INFO("fin_flag: %d, syn_flag: %d, rst_flag: %d, psh_flag: %d, ack_flag: %d, urg_flag: %d\n", fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag);
        // 端口填充
        _src_port = tcpheader.th_sport;
        _dst_port = tcpheader.th_dport;
        // LOG_DEBUG("TCP Header: SourcePort: %d, DestPort: %d\n", _src_port, _dst_port);
        // 判断数据包是否是握手数据包
        if(syn_flag == 1 && ack_flag == 0) {
            // LOG_DEBUG("建立连接请求的第一个数据包(握手)\n");
            tcpheader.isHandleShake = 1;
            return true;
        }
        else if(fin_flag == 1 && ack_flag == 1) {
            // LOG_DEBUG("客户端发送FIN包(挥手).\n");
            tcpheader.isHandleShake = 2;
            return true;
        }
        tcpheader.isHandleShake = 0;
        return false;
    }
    // 判断是否是HTTP数据包
    bool httpHandle(unsigned char *buffer, unsigned int len) {
        if(len < 0) return false;        
        // 解析HTTP协议(方法 URI HTTP/版本)
        std::string httpdata(reinterpret_cast<const char*>(buffer), len);
        // LOG_DEBUG("httpdata.length: %d, len: %d\n", httpdata.length(), len);
        // 查找HTTP请求行
        size_t found_1 = httpdata.find("HTTP/1.");
        if(found_1 != std::string::npos) {
            int i = 1;
            while(i--) {
                size_t firstFlag = httpdata.find("GET");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("POST");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("HEAD");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("PUT");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("DELETE");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("CONNECT");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("OPTIONS");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("TRACE");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
                firstFlag = httpdata.find("PATCH");
                if(firstFlag != std::string::npos) {
                    httpdata = httpdata.substr(firstFlag);
                    break;
                }
            }
            // LOG_DEBUG("http request: %s\n", httpdata.c_str());
            // 解析出http请求的method, uri, version
            std::string method, uri, version;
            std::istringstream iss(httpdata);
            if (!(iss >> method >> uri >> version)) {
                // LOG_ERROR("parse http request failed\n");
                return false;
            }
            // LOG_DEBUG("method: %s, uri: %s, version: %s\n", method.c_str(), uri.c_str(), version.c_str());
            tcpheader.httpheader.method = method;
            tcpheader.httpheader.uri = uri;
            tcpheader.httpheader.version = version;
            // 设置HTTP协议标识
            tcpheader.isHttpProtocol = 1;
            return true;
        }
        return false;
    }

    void parse_ipv4_header(unsigned char* data, unsigned int len)
    {
        if(len < 20) return;
        _version = 4;

        struct ipv4_header {
            uint8_t version_ihl;   // Version (4 bits) + Internet Header Length (4 bits)
            uint8_t tos;           // Type of Service
            uint16_t total_length; // Total length of the datagram
            uint16_t id;           // Identification
            uint16_t flags_fragoffset;
            uint8_t ttl;           // Time to Live
            uint8_t protocol;      // Protocol type
            uint16_t checksum;     // Header checksum
            uint32_t src_address;  // Source address
            uint32_t dst_address;  // Destination address
        } __attribute__((packed));

        if (len < sizeof(ipv4_header)) {
            std::cerr << "Data size is too small to contain an IPv4 header." << std::endl;
            return;
        }
        const ipv4_header* ipv4Hdr = reinterpret_cast<const ipv4_header*>(data);

        // Extract fields
        uint8_t version = (ipv4Hdr->version_ihl >> 4) & 0x0F; // Extracting version bits
        uint8_t ihl = ipv4Hdr->version_ihl & 0x0F;            // Extracting IHL bits
        uint8_t tos = ipv4Hdr->tos;
        uint16_t total_length = ntohs(ipv4Hdr->total_length);
        uint16_t id = ntohs(ipv4Hdr->id);
        uint16_t flags = (ipv4Hdr->flags_fragoffset >> 13) & 0x03FF; // Flags
        uint16_t fragoffset = (ipv4Hdr->flags_fragoffset & 0x1FFF);   // Fragment offset
        uint8_t ttl = ipv4Hdr->ttl;
        uint8_t protocol = ipv4Hdr->protocol;
        uint16_t checksum = ntohs(ipv4Hdr->checksum);
        uint32_t src_ip = ntohl(ipv4Hdr->src_address);
        uint32_t dst_ip = ntohl(ipv4Hdr->dst_address);

        char srcIpStr[INET_ADDRSTRLEN] = {0}; // INET_ADDRSTRLEN 是用于存储 IPv4 地址字符串的最大长度
        if (inet_ntop(AF_INET, &ipv4Hdr->src_address, srcIpStr, sizeof(srcIpStr)) != NULL) {
            _src_ip = srcIpStr;
        }
        char dstIpStr[INET_ADDRSTRLEN] = {0}; // INET_ADDRSTRLEN 是用于存储 IPv4 地址字符串的最大长度
        if (inet_ntop(AF_INET, &ipv4Hdr->dst_address, dstIpStr, sizeof(dstIpStr)) != NULL) {
            _dst_ip = dstIpStr;
        }

        // 解析下方协议具体数据长度不得小于20
        // 获取并打印使用的协议
        _isHandleShake = 0;
        int protocol2 = static_cast<int>(protocol);
        switch(protocol2) {
        case 1:
            _protocol = "ICMP";
            break;
        case 6:
            _protocol = "TCP"; 
            if(len < 40) break;
            if(true == tcpHelloHandle(data + 20, len - 20)) {
                _isHandleShake = tcpheader.isHandleShake;
            }
            if(len == 40) break;
            if(true == httpHandle(data + 40, len - 40)) {
                _protocol = "HTTP";
                break;
            }
            break;
        case 17:
            _protocol = "UDP";
            if(len < 28) break;
            udpData(data + 20, len - 20);
            break;
        default:
            _protocol = "UNKNOWN";
            break;
        }
        // 输出日志
        if(_protocol == "TCP" || _protocol == "UDP") {
            _onlyFlag = _protocol + "_" + _src_ip + ":" + std::to_string(_src_port) + "_" + _dst_ip + ":" + std::to_string(_dst_port);
            _reverseOnlyFlag = _protocol + "_" + _dst_ip + ":" + std::to_string(_dst_port) + "_" + _src_ip + ":" + std::to_string(_src_port);
        }
        else if(_protocol == "HTTP") {
            _onlyFlag = _protocol + "_" + _src_ip + ":" + std::to_string(_src_port) + "_" + _dst_ip + ":" + std::to_string(_dst_port) + "_" + tcpheader.httpheader.uri;
        }
        else if(_protocol == "ICMP") {
            _onlyFlag = _protocol + "_" + _src_ip + "_" + _dst_ip;
            _reverseOnlyFlag = _protocol + "_" + _dst_ip + "_" + _src_ip;
        }
        else {
            _onlyFlag = _protocol;
            _reverseOnlyFlag = _protocol;
        }
        // LOG_DEBUG("_onlyFlag: %s\n", _onlyFlag.c_str()); // 日志太多,暂时注释
        #if 0
        // Print header information
        std::cout << "IPv4 Header:" << std::endl;
        std::cout << "Version: " << static_cast<int>(version) << std::endl;
        std::cout << "Header Length: " << static_cast<int>(ihl) * 4 << " bytes" << std::endl;
        std::cout << "Type of Service: " << static_cast<int>(tos) << std::endl;
        std::cout << "Total Length: " << total_length << " bytes" << std::endl;
        std::cout << "Identification: " << id << std::endl;
        std::cout << "Flags: " << flags << std::endl;
        std::cout << "Fragment Offset: " << fragoffset << std::endl;
        std::cout << "Time to Live: " << static_cast<int>(ttl) << std::endl;
        std::cout << "Protocol: " << static_cast<int>(protocol) << std::endl;
        std::cout << "Checksum: " << checksum << std::endl;
        std::cout << "Source IP: " << inet_ntoa(*(struct in_addr*)&ipv4Hdr->src_address) << std::endl;
        std::cout << "Destination IP: " << inet_ntoa(*(struct in_addr*)&ipv4Hdr->dst_address) << std::endl;
#endif 
    }
    void parse_ipv6_header(unsigned char* data, unsigned int len)
    {
        // LOG_DEBUG("len: %d\n", len);
        if(len < 40) return;
        _version = 6;

        struct ipv6_hdr {
            uint8_t priority : 4,
                    version : 4;
            uint8_t flow_label[3];
            uint16_t payload_length;
            uint8_t next_header;
            uint8_t hop_limit;
            struct in6_addr src_addr, dst_addr; // IPv6源地址和目的地址
        } __attribute__((packed));


        ipv6_hdr *ipv6hdr = (ipv6_hdr *)data;
        // 获取源地址（现在正确地从recvfrom接收到的信息中提取）
        char src_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6hdr->src_addr, src_ip_str, sizeof(src_ip_str));
        _src_ip = src_ip_str;
        // 获取目的地址（直接从数据包头中提取）
        char dst_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6hdr->dst_addr, dst_ip_str, sizeof(dst_ip_str));
        _dst_ip = dst_ip_str;
        // LOG_DEBUG("源地址: %s -> 目的地址: %s\n", src_ip_str, dst_ip_str);

        // 获取并打印使用的协议
        _isHandleShake = 0;
        switch (ipv6hdr->next_header) {
            case IPPROTO_TCP:
                // LOG_DEBUG("使用的协议: TCP\n");
                _protocol = "TCP"; 
                if(len < 60) break;
                if(true == tcpHelloHandle(data + 40, len - 40)) {
                    _isHandleShake = tcpheader.isHandleShake;
                    break;
                }
                if(len == 60) break;
                if(true == httpHandle(data + 60, len - 60)) {
                    _protocol = "HTTP";
                    break;
                }
                break;
            case IPPROTO_UDP:
                // LOG_DEBUG("使用的协议: UDP\n");
                _protocol = "UDP";
                if(len < 48) break;
                udpData(data + 40, len - 40);
                break;
            case IPPROTO_ICMPV6:
                // LOG_DEBUG("使用的协议: ICMPv6\n");
                _protocol = "ICMPv6";
                break;
            case IPPROTO_HOPOPTS:
                // LOG_DEBUG("使用的协议: HOPOPTS\n");
                _protocol = "HOPOPTS";
                break;
            default:
                // LOG_DEBUG("使用的协议:未知 (%d)\n", ipv6hdr->next_header);
                _protocol = "UNKNOWN";
                break;
        }
        // 输出日志
        if(_protocol == "TCP" || _protocol == "UDP") {
            _onlyFlag = _protocol + "_" + _src_ip + ":" + std::to_string(_src_port) + "_" + _dst_ip + ":" + std::to_string(_dst_port);
        }
        else if(_protocol == "HTTP") {
            _onlyFlag = _protocol + "_" + _src_ip + ":" + std::to_string(_src_port) + "_" + _dst_ip + ":" + std::to_string(_dst_port) + "_" + tcpheader.httpheader.uri;
        }
        else if(_protocol == "ICMPv6") {
            _onlyFlag = _protocol + "_" + _src_ip + "_" + _dst_ip;
        }
        else {
            _onlyFlag = _protocol;
        }
        // LOG_DEBUG("_onlyFlag: %s\n", _onlyFlag.c_str());
    }

    // Constructor
    IPHeader() {
        
    }
    IPHeader(unsigned char* data, unsigned int len) 
    {
        if(len < 20) return;
        int ret = checkPacketVersion(data);
        if(ret == 4) {
            parse_ipv4_header(data, len);
        } 
        else if(ret == 6) {
            parse_ipv6_header(data, len);
        }
        else {
            // LOG_ERROR("Unknown IP version: %d, len: %d\n", ret, len);
        }
        // 测试使用
        // printHeader();
    }

    // Destructor
    ~IPHeader() 
    {

    }

    // 持续的IPHeader结构体部分
    void printHeader() 
    {
        std::stringstream ss;
        ss << std::endl;
        ss << "是否握手包: " << _isHandleShake << std::endl;
        ss << "IP版本号: " << _version << std::endl;
        ss << "协议: " << _protocol << std::endl;
        ss << "源IP地址: " << _src_ip << std::endl;
        ss << "目的IP地址: " << _dst_ip << std::endl;
        ss << "源端口: " << _src_port << std::endl;
        ss << "目的端口: " << _dst_port << std::endl;
        std::string ipHeaderStr = ss.str();
        // LOG_DEBUG("IP_Header: %s", ipHeaderStr.c_str());
    }
};

#endif //_IP_PARSER_H_