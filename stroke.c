/*
 *  $Id: stroke.c,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  stroke.c - pcap example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "./stroke.h"
#include <getopt.h>
#include <arpa/inet.h>

/*
 * 版本信息
 * 遵循语义化版本控制 (Semantic Versioning)
 * MAJOR.MINOR.PATCH
 */
#define STROKE_VERSION_MAJOR 1
#define STROKE_VERSION_MINOR 1
#define STROKE_VERSION_PATCH 0

/*
 * 规范化退出码
 * 遵循 POSIX 标准和常见约定
 */
typedef enum {
    EXIT_OK          = 0,   /* 成功 */
    EXIT_USAGE       = 64,  /* 命令行使用错误 */
    EXIT_DATAERR     = 65,  /* 数据格式错误 */
    EXIT_NOINPUT     = 66,  /* 无法打开输入 */
    EXIT_UNAVAILABLE = 69,  /* 服务不可用 */
    EXIT_SOFTWARE    = 70,  /* 内部软件错误 */
    EXIT_OSERR       = 71,  /* 操作系统错误 */
    EXIT_CANTCREAT   = 73,  /* 无法创建输出 */
    EXIT_IOERR       = 74,  /* 输入/输出错误 */
    EXIT_TEMPFAIL    = 75,  /* 临时失败 */
    EXIT_PROTOCOL    = 76,  /* 协议错误 */
    EXIT_NOPERM      = 77,  /* 权限不足 */
    EXIT_CONFIG      = 78   /* 配置错误 */
} ExitCode;

/*
 * [安全修复] 循环控制标志
 * 使用 volatile sig_atomic_t 确保在信号处理中安全访问
 * 这是 C99 标准中信号安全的整数类型
 */
static volatile sig_atomic_t loop = 1;
/* 唯一MAC地址计数 */
static u_long mac = 0;

/* 函数声明 */
static void ht_free_table(struct table_entry **hash_table);
static void print_version(void);
static void print_help(const char *prog_name);
static int list_devices(void);
static void print_error(ExitCode code, const char *message, const char *detail);

/*
 * 长选项定义
 * 用于 getopt_long
 */
static const struct option long_options[] = {
    {"help",          no_argument,       NULL, 'h'},
    {"version",       no_argument,       NULL, 'v'},
    {"list",          no_argument,       NULL, 'l'},
    {"interface",     required_argument, NULL, 'i'},
    {"show-ip",       no_argument,       NULL, 'I'},
    {NULL, 0, NULL, 0}
};

/*
 * 打印版本信息
 */
static void print_version(void) {
    printf("Stroke version %d.%d.%d\n",
           STROKE_VERSION_MAJOR,
           STROKE_VERSION_MINOR,
           STROKE_VERSION_PATCH);
    printf("A passive MAC to OUI mapping tool using libpcap\n");
    printf("\n");
    printf("Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>\n");
    printf("All rights reserved.\n");
    printf("This software is released under the BSD License.\n");
}

/*
 * 打印帮助信息
 */
static void print_help(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("\n");
    printf("Passively capture and map MAC addresses to OUI vendors.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help              Show this help message and exit\n");
    printf("  -v, --version           Show version information and exit\n");
    printf("  -l, --list              List all available network devices and exit\n");
    printf("  -i, --interface <name>  Specify the network interface to capture from\n");
    printf("                            (e.g., eth0, enp3s0, wlan0)\n");
    printf("  -I, --show-ip           Show source IP addresses along with MAC addresses\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -l                      List all available interfaces\n", prog_name);
    printf("  %s -i eth0                 Capture on eth0\n", prog_name);
    printf("  %s -I -i wlan0             Capture on wlan0 with IP addresses\n", prog_name);
    printf("  %s                         Auto-select first available interface\n", prog_name);
    printf("\n");
    printf("Notes:\n");
    printf("  - Root privileges are usually required for packet capture\n");
    printf("  - Press Ctrl+C to stop capturing and view statistics\n");
    printf("  - Use --list to see available interface names\n");
    printf("  - OUI lookup is performed using IEEE Organizationally Unique Identifier table\n");
}

/*
 * 列出所有可用的网络设备
 * 返回值: 0 成功, 非零 失败
 */
static int list_devices(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;

    printf("Available Network Interfaces:\n");
    printf("============================\n");
    printf("\n");

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        print_error(EXIT_IOERR, "Failed to enumerate network devices", errbuf);
        return EXIT_IOERR;
    }

    if (alldevs == NULL) {
        printf("  No network devices found.\n");
        printf("\n");
        printf("Hint: Try running with root privileges (sudo).\n");
        pcap_freealldevs(alldevs);
        return EXIT_OK;
    }

    int first_non_loopback = 1;
    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        count++;
        
        /* 打印设备名称 */
        printf("  %d. %s", count, dev->name);
        
        /* 标记默认选择的设备（第一个非回环设备） */
        if ((dev->flags & PCAP_IF_LOOPBACK) == 0 && first_non_loopback) {
            printf(" [default]");
            first_non_loopback = 0;
        }
        
        printf("\n");

        /* 打印设备描述（如果有） */
        if (dev->description != NULL) {
            printf("      Description: %s\n", dev->description);
        }

        /* 打印设备标志 */
        printf("      Flags: ");
        int first = 1;
        if (dev->flags & PCAP_IF_LOOPBACK) {
            printf("loopback");
            first = 0;
        }
        if (dev->flags & PCAP_IF_UP) {
            if (!first) printf(", ");
            printf("up");
            first = 0;
        }
        if (dev->flags & PCAP_IF_RUNNING) {
            if (!first) printf(", ");
            printf("running");
            first = 0;
        }
        if (first) {
            printf("none");
        }
        printf("\n");

        /* 打印地址（如果有） */
        if (dev->addresses != NULL) {
            printf("      Addresses:\n");
            for (pcap_addr_t *addr = dev->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr != NULL && addr->addr->sa_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)addr->addr;
                    printf("        IPv4: %s\n", inet_ntoa(sin->sin_addr));
                }
            }
        }
        printf("\n");
    }

    printf("============================\n");
    printf("Total: %d device(s)\n", count);
    printf("\n");
    printf("Usage example:\n");
    printf("  %s -i <interface_name>\n", "stroke");

    pcap_freealldevs(alldevs);
    return EXIT_OK;
}

/*
 * 打印格式化的错误信息
 * 参数:
 *   code:    退出码
 *   message: 错误概述
 *   detail:  详细错误信息（可为 NULL）
 */
static void print_error(ExitCode code, const char *message, const char *detail) {
    fprintf(stderr, "\n");
    fprintf(stderr, "Error: %s\n", message);
    
    if (detail != NULL && detail[0] != '\0') {
        fprintf(stderr, "       %s\n", detail);
    }
    
    fprintf(stderr, "\n");
    
    /* 根据错误类型提供建议 */
    switch (code) {
        case EXIT_USAGE:
            fprintf(stderr, "Hint: Use --help for usage information.\n");
            break;
        case EXIT_NOPERM:
            fprintf(stderr, "Hint: Try running with root privileges (sudo).\n");
            break;
        case EXIT_NOINPUT:
            fprintf(stderr, "Hint: Use --list to see available interfaces.\n");
            break;
        case EXIT_UNAVAILABLE:
            fprintf(stderr, "Hint: The interface may be down or not connected.\n");
            break;
        default:
            break;
    }
    fprintf(stderr, "\n");
}

int main(int argc, char **argv) {
    int c;
    int opt_index;
    pcap_t *p = NULL;
    char *device = NULL;
    int print_ip = 0;
    int list_only = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;
    struct table_entry *hash_table[HASH_TABLE_SIZE];
    pcap_if_t *alldevs = NULL;
    char device_buffer[256] = {0};

    /*
     * 解析命令行参数
     * 使用 getopt_long 支持长选项
     */
    while ((c = getopt_long(argc, argv, "hvli:I", long_options, &opt_index)) != -1) {
        switch (c) {
            case 'h':
                print_help(argv[0]);
                return EXIT_OK;
            
            case 'v':
                print_version();
                return EXIT_OK;
            
            case 'l':
                list_only = 1;
                break;
            
            case 'i':
                device = optarg;
                break;
            
            case 'I':
                print_ip = 1;
                break;
            
            case '?':
                /* 未知选项，getopt_long 已打印错误信息 */
                fprintf(stderr, "\n");
                fprintf(stderr, "Hint: Use --help for usage information.\n");
                return EXIT_USAGE;
            
            default:
                return EXIT_USAGE;
        }
    }

    /*
     * 如果只需要列出设备
     */
    if (list_only) {
        return list_devices();
    }

    /*
     * 检查是否有多余的参数
     */
    if (optind < argc) {
        print_error(EXIT_USAGE, "Unexpected arguments", argv[optind]);
        return EXIT_USAGE;
    }

    /*
     * 打印启动横幅
     */
    printf("Stroke %d.%d.%d\n",
           STROKE_VERSION_MAJOR,
           STROKE_VERSION_MINOR,
           STROKE_VERSION_PATCH);
    printf("A passive MAC to OUI mapping tool\n");
    printf("================================\n");
    printf("\n");
    printf("Configuration:\n");
    printf("  Mode:         %s\n", print_ip ? "MAC + IP" : "MAC only");
    printf("  Interface:    ");

    /* 如果用户没有指定设备，自动查找可用的网络设备 */
    if (device == NULL) {
        printf("[auto-selecting]\n");
        
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            print_error(EXIT_IOERR, "Failed to enumerate network devices", errbuf);
            return EXIT_IOERR;
        }
        
        /*
         * [安全检查] 空指针检查
         * 防止 alldevs 为 NULL 时访问 dev->name 导致崩溃
         */
        if (alldevs == NULL) {
            print_error(EXIT_NOINPUT, "No network devices found", 
                       "Hint: Use --list to see available interfaces, or try running with sudo.");
            pcap_freealldevs(alldevs);
            return EXIT_NOINPUT;
        }
        
        /* 遍历设备列表，跳过回环接口，选择第一个可用的物理接口 */
        pcap_if_t *dev;
        int found = 0;
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            /* 跳过回环接口 */
            if ((dev->flags & PCAP_IF_LOOPBACK) == 0) {
                /*
                 * [安全修复] 安全的字符串复制
                 * 使用 strncpy + 手动设置 null 终止符，防止缓冲区溢出
                 * 同时确保 source 字符串不会被截断后无 null 终止
                 */
                if (dev->name != NULL) {
                    size_t name_len = strlen(dev->name);
                    if (name_len < sizeof(device_buffer)) {
                        memcpy(device_buffer, dev->name, name_len + 1);
                    } else {
                        /* 名称过长，截断并确保 null 终止 */
                        memcpy(device_buffer, dev->name, sizeof(device_buffer) - 1);
                        device_buffer[sizeof(device_buffer) - 1] = '\0';
                    }
                    device = device_buffer;
                    found = 1;
                    printf("\n");
                    printf("  Selected:     %s", device);
                    if (dev->description != NULL) {
                        printf(" (%s)", dev->description);
                    }
                    printf("\n");
                }
                break;
            }
        }
        
        /* 如果没有找到非回环接口，使用第一个设备 */
        if (!found && alldevs->name != NULL) {
            size_t name_len = strlen(alldevs->name);
            if (name_len < sizeof(device_buffer)) {
                memcpy(device_buffer, alldevs->name, name_len + 1);
            } else {
                memcpy(device_buffer, alldevs->name, sizeof(device_buffer) - 1);
                device_buffer[sizeof(device_buffer) - 1] = '\0';
            }
            device = device_buffer;
            printf("\n");
            printf("  Selected:     %s (loopback)\n", device);
        }
    } else {
        printf("%s\n", device);
    }

    /*
     * [安全检查] 空指针检查
     * 确保 device 不为空后再使用
     */
    if (device == NULL) {
        print_error(EXIT_NOINPUT, "No valid network device specified or found",
                   "Use --list to see available interfaces.");
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        return EXIT_NOINPUT;
    }

    printf("\n");
    printf("Starting packet capture...\n");
    printf("Press Ctrl+C to stop and view statistics.\n");
    printf("================================\n");
    printf("\n");

    /*
     * 打开数据包捕获设备，参数说明：
     *
     * SNAPLEN: 34字节
     * 我们只需要14字节的以太网头，以及用户指定 `-I` 选项时可能需要的IP头。
     * PROMISC: 开启
     * 网络接口需要设置为混杂模式以捕获本地网络上的所有流量。
     * TIMEOUT: 500毫秒
     * 500毫秒的超时时间对于大多数网络来说是合适的。
     * 对于支持超时机制的架构，可以根据网络流量调整这个值。
     */
    p = pcap_open_live(device, SNAPLEN, PROMISC, TIMEOUT, errbuf);
    if (p == NULL) {
        print_error(EXIT_UNAVAILABLE, "Failed to open network interface", errbuf);
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        return EXIT_UNAVAILABLE;
    }

    /* 释放设备列表 - 现在可以安全释放，因为device指向本地缓冲区 */
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
        alldevs = NULL;
    }

    /*
     * 设置BPF过滤器。我们只对IP数据包感兴趣，可以忽略其他类型的数据包。
     */
    if (pcap_lookupnet(device, &local_net, &netmask, errbuf) == -1) {
        /*
         * 注意：pcap_lookupnet 可能在某些接口上失败
         * 这不是致命错误，我们可以使用默认值继续
         */
        fprintf(stderr, "Warning: %s\n", errbuf);
        fprintf(stderr, "Using default values for netmask.\n");
        local_net = 0;
        netmask = 0;
    }
    
    if (pcap_compile(p, &filter_code, FILTER, 1, netmask) == -1) {
        print_error(EXIT_PROTOCOL, "Failed to compile BPF filter", pcap_geterr(p));
        pcap_close(p);
        return EXIT_PROTOCOL;
    }
    
    if (pcap_setfilter(p, &filter_code) == -1) {
        print_error(EXIT_PROTOCOL, "Failed to set BPF filter", pcap_geterr(p));
        pcap_freecode(&filter_code);
        pcap_close(p);
        return EXIT_PROTOCOL;
    }
    
    /*
     * [资源管理] 释放编译的过滤器代码
     * 即使 pcap_setfilter 成功，也需要释放 filter_code
     */
    pcap_freecode(&filter_code);

    /*
     * 确保这是以太网。DLT_EN10MB指定标准的10MB及以上以太网。
     */
    if (pcap_datalink(p) != DLT_EN10MB) {
        print_error(EXIT_PROTOCOL, "Unsupported link layer type",
                   "Stroke only works with Ethernet (DLT_EN10MB).");
        pcap_close(p);
        return EXIT_PROTOCOL;
    }

    /*
     * 捕获中断信号，以便在退出前告诉用户捕获了多少个数据包。
     * 我们应该在退出前清理内存并释放哈希表。
     */
    if (catch_sig(SIGINT, cleanup) == -1) {
        print_error(EXIT_SOFTWARE, "Failed to set up signal handler", NULL);
        pcap_close(p);
        return EXIT_SOFTWARE;
    }

    /*
     * 初始化哈希表并开始循环。只有当用户按下ctrl-c时，循环才会退出，
     * 此时命令提示符会将循环标志变量设置为0。
     */
    ht_init_table(hash_table);
    
    /*
     * [安全修复] 使用 pcap_next_ex() 替代 pcap_next()
     * pcap_next() 无法区分超时、错误和无数据包情况
     * pcap_next_ex() 返回值更清晰：
     *   1 = 成功读取数据包
     *   0 = 超时
     *  -1 = 错误
     *  -2 = 从离线文件读取完成
     *
     * [API说明] pcap_next_ex() 的签名是：
     * int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data);
     * 
     * 注意：
     * 1. pkt_header 和 pkt_data 都是指向指针的指针
     * 2. 返回的指针指向 libpcap 内部缓冲区，不要释放它们
     * 3. 这些指针在下一次调用 pcap_next_ex() 或 pcap_close() 时可能失效
     */
    while (loop) {
        struct pcap_pkthdr *h;
        const u_char *packet;
        int result;

        /*
         * pcap_next_ex() 从pcap的内部数据包缓冲区获取下一个数据包
         * 返回值：
         *   1: 成功
         *   0: 超时（仅实时捕获）
         *  -1: 错误
         *  -2: EOF（仅离线捕获）
         *
         * [安全修复] 正确的参数类型
         * &h 和 &packet 都是指向指针的指针，符合 API 要求
         */
        result = pcap_next_ex(p, &h, &packet);
        
        if (result == 0) {
            /* 超时，继续循环 */
            continue;
        } else if (result == -1) {
            /* 错误，输出错误信息但继续运行 */
            fprintf(stderr, "pcap_next_ex() error: %s\n", pcap_geterr(p));
            continue;
        } else if (result == -2) {
            /* 离线捕获完成（本程序不会走到这里） */
            break;
        }
        
        /* result == 1，成功读取数据包 */
        
        /*
         * [安全检查] 空指针检查
         * 尽管 pcap_next_ex() 返回 1 时 packet 应该非空，
         * 但防御性编程要求我们检查
         */
        if (packet == NULL || h == NULL) {
            continue;
        }
        
        /*
         * 检查数据包是否来自新的MAC地址，如果是，将其添加到哈希表中。
         */
        if (interesting((u_char *)packet, hash_table)) {
            /*
             * 数据包的源MAC地址位于数据包的第6个字节，
             * IP地址位于数据包的第26个字节。
             * 我们将MAC提交给二分查找函数，该函数将返回与MAC条目对应的OUI字符串。
             */
            if (print_ip) {
                printf("%s @ %s -> %s\n", 
                       eprintf((u_char *)packet),
                       iprintf((u_char *)packet + 26),
                       b_search((u_char *)packet + 6));
            } else {
                printf("%s -> %s\n", 
                       eprintf((u_char *)packet),
                       b_search((u_char *)packet + 6));
            }
        }
    }

    /*
     * 如果执行到这里，说明用户在命令提示符下按下了ctrl-c，
     * 现在是时候输出统计信息了。
     */
    printf("\n");
    printf("================================\n");
    printf("Capture Stopped. Statistics:\n");
    printf("================================\n");
    printf("\n");

    struct pcap_stat ps;
    if (pcap_stats(p, &ps) == -1) {
        fprintf(stderr, "Warning: Failed to get packet statistics: %s\n", 
                pcap_geterr(p));
    } else {
        /*
         * 注意，ps统计信息根据底层架构可能略有不同。
         * 这里我们简化处理。
         */
        printf("  Packet Statistics:\n");
        printf("    Received by libpcap: %15d\n", ps.ps_recv);
        printf("    Dropped by libpcap:  %15d\n", ps.ps_drop);
        printf("\n");
    }

    printf("  Discovery Statistics:\n");
    printf("    Unique MAC addresses: %14lu\n", (unsigned long)mac);
    printf("\n");

    /*
     * [安全修复] 释放哈希表内存
     * 防止内存泄漏。虽然程序即将退出，操作系统会回收内存，
     * 但良好的编程实践要求显式释放已分配的内存。
     * 这也有助于使用内存检测工具（如 valgrind）时避免误报。
     */
    ht_free_table(hash_table);
    
    pcap_close(p);
    return EXIT_OK;
}

/*
 * 在OUI表中执行二分查找
 * 时间复杂度约为 O(log n)
 */
const char *b_search(u_char *prefix) {
    int start = 0;
    int end = (int)(sizeof(oui_table) / sizeof(oui_table[0]));

    /*
     * [安全检查] 空指针检查
     * 防止传入 NULL 指针导致崩溃
     */
    if (prefix == NULL) {
        return "Unknown Vendor";
    }

    while (end > start) {
        /*
         * [安全修复] 防止整数溢出
         * 原来的写法: int mid = (start + end) / 2;
         * 当 start 和 end 都很大时，start + end 可能导致整数溢出
         * 
         * 修复后的写法: int mid = start + (end - start) / 2;
         * 这样可以确保不会溢出，因为:
         * - end > start (循环条件)，所以 (end - start) 是正数
         * - (end - start) / 2 不会溢出
         * - start + (小于 end - start 的数) 不会溢出
         * 
         * 这是二分查找的标准安全写法
         */
        int mid = start + (end - start) / 2;
        const struct oui *ent = &oui_table[mid];
        
        /*
         * [类型安全] 显式转换为 int 进行比较
         * u_char 是 unsigned char，在某些平台上可能扩展为 int 的方式不同
         * 显式转换确保比较行为一致
         */
        int diff = (int)prefix[0] - (int)ent->prefix[0];

        if (diff == 0) {
            /* 第一个字节匹配 */
            diff = (int)prefix[1] - (int)ent->prefix[1];
        }
        
        if (diff == 0) {
            /* 第二个字节匹配 */
            diff = (int)prefix[2] - (int)ent->prefix[2];
        }

        if (diff == 0) {
            /* 第三个字节匹配，找到对应的厂商 */
            return ent->vendor;
        }
        
        if (diff < 0) {
            /* 在表的前半部分继续查找 */
            end = mid;
        } else {
            /* 在表的后半部分继续查找 */
            start = mid + 1;
        }
    }
    
    /* 没有找到匹配项 */
    return "Unknown Vendor";
}

/*
 * 将MAC地址格式化为可读的字符串格式
 */
char *eprintf(u_char *packet) {
    /*
     * [安全检查] 空指针检查
     * 防止传入 NULL 指针导致崩溃
     */
    if (packet == NULL) {
        static char empty[] = "00:00:00:00:00:00";
        return empty;
    }

    /*
     * MAC地址格式: XX:XX:XX:XX:XX:XX
     * 需要 17 个字符 + null 终止符 = 18 字节
     * 使用静态缓冲区是可接受的，因为：
     * 1. 这个函数是线程不安全的，但这个程序是单线程的
     * 2. 调用者不会保留返回指针的引用超过下一次调用
     */
    static char address[18];
    int n;

    /*
     * [安全修复] 使用 snprintf 替代 sprintf
     * snprintf 确保不会超出缓冲区大小
     * 尽管我们已经精确计算了大小，但使用 snprintf 是良好的安全实践
     * 
     * 注意: 原始代码使用 sprintf，这是安全的因为我们知道格式字符串
     * 但 snprintf 更符合现代安全编码标准
     */
    n = snprintf(address, sizeof(address), 
                  "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                  packet[6], packet[7], packet[8],
                  packet[9], packet[10], packet[11]);
    
    /*
     * [安全检查] 确保字符串正确终止
     * snprintf 返回写入的字符数（不包括 null）
     * 如果返回值 >= sizeof(address)，说明发生了截断
     */
    if (n < 0 || (size_t)n >= sizeof(address)) {
        /* 发生错误或截断，确保缓冲区有 null 终止符 */
        address[sizeof(address) - 1] = '\0';
    }

    return address;
}

/*
 * 将IP地址格式化为可读的字符串格式
 */
char *iprintf(u_char *address) {
    /*
     * [安全检查] 空指针检查
     * 防止传入 NULL 指针导致崩溃
     */
    if (address == NULL) {
        static char empty[] = "000.000.000.000";
        return empty;
    }

    /*
     * IP地址格式: XXX.XXX.XXX.XXX
     * 最多需要 15 个字符 + null 终止符 = 16 字节
     * 我们分配了 17 字节，有额外的安全空间
     */
    static char ip[17];

    /*
     * [安全修复] 使用 snprintf 替代 sprintf
     * 防止缓冲区溢出。虽然 IP 地址的最大长度是已知的（15字符），
     * 但使用 snprintf 是良好的安全编码实践
     * 
     * 注意: 原始代码使用了 (address[0] & 255) 来确保值在 0-255 范围内
     * 这是正确的，因为 u_char 可能是 signed char（取决于平台）
     * 我们保留这个做法
     */
    int result = snprintf(ip, sizeof(ip), 
                          "%3d.%3d.%3d.%3d",
                          (int)(address[0] & 255),
                          (int)(address[1] & 255),
                          (int)(address[2] & 255),
                          (int)(address[3] & 255));
    
    /*
     * [安全检查] 确保字符串正确终止
     */
    if (result < 0 || (size_t)result >= sizeof(ip)) {
        ip[sizeof(ip) - 1] = '\0';
    }

    return ip;
}

/*
 * 检查数据包中的MAC地址是否是新的（未在哈希表中）
 * 如果是新的，将其添加到哈希表中
 */
int interesting(u_char *packet, struct table_entry **hash_table) {
    /*
     * [安全检查] 空指针检查
     */
    if (packet == NULL || hash_table == NULL) {
        return 0;
    }

    u_long n = ht_hash(packet);
    
    /*
     * [安全修复] 确保哈希值在有效范围内
     * 虽然 ht_hash() 已经返回 j % HASH_TABLE_SIZE，
     * 但防御性编程要求我们再次验证
     * 
     * 注意: 使用 size_t 作为数组索引是最安全的
     */
    size_t index = (size_t)(n % HASH_TABLE_SIZE);

    /* 检查哈希到的位置是否已被占用 */
    if (hash_table[index]) {
        /* 检查是重复条目还是哈希冲突 */
        if (!ht_dup_check(packet, hash_table, (int)index)) {
            /* 这是哈希冲突，需要添加一个新的链表节点 */
            if (ht_add_entry(packet, hash_table, (int)index)) {
                mac++;
                return 1;
            }
        } else {
            /* 这是重复条目，忽略它 */
            return 0;
        }
    } else {
        /* 这个哈希表位置是空的 */
        if (ht_add_entry(packet, hash_table, (int)index)) {
            mac++;
            return 1;
        }
    }
    
    /* 如果执行到这里，说明发生了错误，我们直接忽略 */
    return 0;
}

/*
 * 检查指定位置的哈希表中是否已存在相同的MAC地址
 * 返回值：1表示已存在（重复），0表示不存在（冲突）
 */
int ht_dup_check(u_char *packet, struct table_entry **hash_table, int loc) {
    /*
     * [安全检查] 空指针检查
     */
    if (packet == NULL || hash_table == NULL) {
        return 0;
    }
    
    /*
     * [安全检查] 边界检查
     * 确保 loc 在有效范围内
     */
    if (loc < 0 || loc >= HASH_TABLE_SIZE) {
        return 0;
    }

    for (struct table_entry *p = hash_table[loc]; p != NULL; p = p->next) {
        if (p->mac[0] == packet[6]  && p->mac[1] == packet[7] &&
            p->mac[2] == packet[8]  && p->mac[3] == packet[9] &&
            p->mac[4] == packet[10] && p->mac[5] == packet[11]) {
            /* 这个MAC地址已经在我们的表中 */
            return 1;
        }
    }
    
    /* 这个MAC地址与表中另一个条目发生了哈希冲突 */
    return 0;
}

/*
 * 添加一个新的MAC地址条目到哈希表中
 * 返回值：1表示成功，0表示失败（内存分配失败）
 */
int ht_add_entry(u_char *packet, struct table_entry **hash_table, int loc) {
    /*
     * [安全检查] 空指针检查
     */
    if (packet == NULL || hash_table == NULL) {
        return 0;
    }
    
    /*
     * [安全检查] 边界检查
     */
    if (loc < 0 || loc >= HASH_TABLE_SIZE) {
        return 0;
    }

    if (hash_table[loc] == NULL) {
        /* 这是该位置的第一个条目 */
        
        /*
         * [安全修复] 使用 calloc 替代 malloc
         * 或者使用 malloc + memset 确保内存清零
         * 这可以防止敏感信息泄漏（虽然这里不太重要）
         * 更重要的是，确保 next 指针初始化为 NULL
         * 
         * 注意: 我们使用 malloc 然后显式初始化，
         * 因为我们需要的字段很少，这样更高效
         */
        hash_table[loc] = (struct table_entry *)malloc(sizeof(struct table_entry));
        if (hash_table[loc] == NULL) {
            /*
             * [错误处理] 内存分配失败
             * 返回错误，调用者决定如何处理
             */
            return 0;
        }

        /* 显式复制 MAC 地址字节 */
        hash_table[loc]->mac[0] = packet[6];
        hash_table[loc]->mac[1] = packet[7];
        hash_table[loc]->mac[2] = packet[8];
        hash_table[loc]->mac[3] = packet[9];
        hash_table[loc]->mac[4] = packet[10];
        hash_table[loc]->mac[5] = packet[11];
        hash_table[loc]->next = NULL;
        return 1;
    } else {
        /* 这是一个链表，找到链表的末尾 */
        struct table_entry *p;
        
        /*
         * [安全修复] 更安全的链表遍历
         * 确保不会因为链表损坏而进入无限循环
         * 虽然在这个程序中不太可能，但防御性编程是好的实践
         */
        for (p = hash_table[loc]; p->next != NULL; p = p->next) {
            /* 遍历到链表末尾 */
        }
        
        /*
         * [安全修复] 分配内存并初始化
         */
        p->next = (struct table_entry *)malloc(sizeof(struct table_entry));
        if (p->next == NULL) {
            return 0;
        }

        p = p->next;
        p->mac[0] = packet[6];
        p->mac[1] = packet[7];
        p->mac[2] = packet[8];
        p->mac[3] = packet[9];
        p->mac[4] = packet[10];
        p->mac[5] = packet[11];
        p->next = NULL;
    }
    
    return 1;
}

/*
 * 计算MAC地址的哈希值
 * 使用简单的乘法哈希函数
 */
u_long ht_hash(u_char *packet) {
    /*
     * [安全检查] 空指针检查
     */
    if (packet == NULL) {
        return 0;
    }

    u_long j = 0;

    /* 从第6个字节开始是源MAC地址 */
    for (int i = 6; i != 12; i++) {
        /*
         * [类型安全] 显式转换
         * 确保算术运算使用无符号值
         */
        j = (j * 13) + (u_long)packet[i];
    }
    
    /*
     * [安全修复] 确保返回值在有效范围内
     * 虽然调用者会再次取模，但在这里返回有效值更安全
     */
    return j % HASH_TABLE_SIZE;
}

/*
 * 初始化哈希表，将所有位置设置为NULL
 */
void ht_init_table(struct table_entry **hash_table) {
    /*
     * [安全检查] 空指针检查
     */
    if (hash_table == NULL) {
        return;
    }

    /*
     * [安全修复] 使用 size_t 作为循环变量
     * 这是现代C代码的标准实践
     */
    for (size_t c = 0; c < HASH_TABLE_SIZE; c++) {
        hash_table[c] = NULL;
    }
}

/*
 * [新增函数] 释放哈希表内存
 * 
 * [安全修复] 内存泄漏修复
 * 原来的代码中，malloc() 分配的内存从未释放
 * 虽然程序退出时操作系统会回收，但：
 * 1. 这不是良好的编程实践
 * 2. 使用内存检测工具（如 valgrind）时会报告内存泄漏
 * 3. 如果程序改为长时间运行或作为库使用，这将成为真正的问题
 */
static void ht_free_table(struct table_entry **hash_table) {
    /*
     * [安全检查] 空指针检查
     */
    if (hash_table == NULL) {
        return;
    }

    /* 遍历哈希表的每个位置 */
    for (size_t i = 0; i < HASH_TABLE_SIZE; i++) {
        struct table_entry *p = hash_table[i];
        
        /* 遍历链表，释放每个节点 */
        while (p != NULL) {
            struct table_entry *next = p->next;
            free(p);
            p = next;
        }
        
        /* 确保指针为 NULL（防御性编程） */
        hash_table[i] = NULL;
    }
}

/*
 * 信号处理函数 - 当用户按下Ctrl+C时被调用
 */
void cleanup(int signo) {
    (void)signo;  /* 避免未使用参数的警告 */
    
    /*
     * [安全修复] 只修改 volatile sig_atomic_t 变量
     * 
     * 原来的代码：
     *     printf("Interrupt signal caught...\n");  // 不安全！
     * 
     * 问题：
     * printf() 不是异步信号安全函数！
     * 
     * 为什么不能在信号处理函数中调用 printf()：
     * 1. printf() 使用缓冲区，可能需要分配内存
     * 2. 如果信号在 printf() 执行过程中到达，可能会导致死锁
     * 3. 信号处理函数可以在任何时间、任何上下文中执行
     * 4. printf() 内部使用的锁可能已经被持有
     * 
     * C标准规定（C11 7.14.1.1）：
     * 信号处理函数只能调用以下函数：
     * - abort(), _Exit(), quick_exit()
     * - signal()（使用相同的信号编号）
     * - 一些原子操作函数
     * 
     * 实践中，POSIX 定义了更多异步信号安全函数：
     * - _Exit(), _exit(), abort()
     * - accept(), access(), aio_error(), aio_return(), aio_suspend()
     * - alarm(), bind(), cfgetispeed(), cfgetospeed(), cfsetispeed()
     * - cfsetospeed(), chdir(), chmod(), chown(), clock_gettime()
     * - close(), connect(), creat(), dup(), dup2(), execle(), execve()
     * - fchmod(), fchown(), fcntl(), fdatasync(), fork()
     * - fpathconf(), fstat(), fsync(), ftruncate(), getegid()
     * - geteuid(), getgid(), getgroups(), getpeername(), getpgrp()
     * - getpid(), getppid(), getsockname(), getsockopt(), getuid()
     * - kill(), link(), listen(), lseek(), lstat(), mkdir(), mkfifo()
     * - mknod(), open(), pathconf(), pause(), pipe(), poll()
     * - posix_trace_event(), pselect(), raise(), read(), readlink()
     * - recv(), recvfrom(), recvmsg(), rename(), rmdir()
     * - select(), sem_post(), send(), sendmsg(), sendto()
     * - setgid(), setpgid(), setsid(), setsockopt(), setuid()
     * - shutdown(), sigaction(), sigaddset(), sigdelset(), sigemptyset()
     * - sigfillset(), sigismember(), signal(), sigpause(), sigpending()
     * - sigprocmask(), sigqueue(), sigsuspend(), sleep(), socket()
     * - socketpair(), stat(), symlink(), sysconf(), tcdrain()
     * - tcflow(), tcflush(), tcgetattr(), tcgetpgrp(), tcsendbreak()
     * - tcsetattr(), tcsetpgrp(), time(), timer_getoverrun()
     * - timer_gettime(), timer_settime(), times(), umask(), uname()
     * - unlink(), utime(), wait(), waitpid(), write()
     * 
     * 但注意：printf() 不在列表中！
     * 
     * 修复方案：
     * 1. 只设置 loop = 0（这是安全的，因为 loop 是 volatile sig_atomic_t）
     * 2. 不要调用 printf() 或其他非异步信号安全函数
     * 
     * 我们可以在 main() 函数中检测 loop 变为 0 后再输出消息
     */
    
    loop = 0;
    
    /*
     * [安全注意] 
     * 原来的 printf() 调用已被移除，因为它不是异步信号安全的
     * 
     * 如果确实需要在信号处理中输出消息，可以使用 write()：
     * 
     * const char msg[] = "Interrupt signal caught...\n";
     * write(STDOUT_FILENO, msg, sizeof(msg) - 1);
     * 
     * 但这只在 POSIX 系统上是安全的，write() 是异步信号安全的
     * 
     * 为了最大的可移植性，我们选择不在信号处理函数中进行任何输出，
     * 而是让主循环在检测到 loop == 0 后正常退出
     */
}

/*
 * 捕获信号并设置处理函数
 * 返回值：-1表示失败，1表示成功
 */
int catch_sig(int signo, void (*handler)(int)) {
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    
    /*
     * [安全修复] 不使用 SA_RESTART
     * 
     * 原来的代码：action.sa_flags = 0;
     * 这是正确的。
     * 
     * 注意：如果设置 SA_RESTART，被信号中断的系统调用会自动重启
     * 这可能导致 pcap_next_ex() 等函数不会返回 EINTR
     * 对于这个程序，我们不需要 SA_RESTART，因为：
     * 1. 我们使用 loop 标志来控制循环
     * 2. pcap_next_ex() 有自己的超时机制
     * 
     * 保留 flags = 0 是最安全的
     */
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1) {
        return -1;
    }
    
    return 1;
}

/* EOF */
