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

/* 循环控制标志 */
static volatile sig_atomic_t loop = 1;
/* 唯一MAC地址计数 */
static u_long mac = 0;

int main(int argc, char **argv) {
    int c;
    pcap_t *p = NULL;
    char *device = NULL;
    int print_ip = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter_code;
    bpf_u_int32 local_net, netmask;
    struct table_entry *hash_table[HASH_TABLE_SIZE];
    pcap_if_t *alldevs = NULL;
    char device_buffer[256] = {0};

    /* 解析命令行参数 */
    while ((c = getopt(argc, argv, "Ii:")) != -1) {
        switch (c) {
            case 'I':
                print_ip = 1;
                break;
            case 'i':
                device = optarg;
                break;
            default:
                exit(EXIT_FAILURE);
        }
    }

    printf("Stroke 1.0 [passive MAC -> OUI mapping tool]\n");
    printf("<ctrl-c> to quit\n");

    /* 如果用户没有指定设备，自动查找可用的网络设备 */
    if (device == NULL) {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        
        if (alldevs == NULL) {
            fprintf(stderr, "No network devices found.\n");
            exit(EXIT_FAILURE);
        }
        
        /* 遍历设备列表，跳过回环接口，选择第一个可用的物理接口 */
        pcap_if_t *dev;
        for (dev = alldevs; dev != NULL; dev = dev->next) {
            /* 跳过回环接口 */
            if ((dev->flags & PCAP_IF_LOOPBACK) == 0) {
                /* 复制设备名称到本地缓冲区 */
                strncpy(device_buffer, dev->name, sizeof(device_buffer) - 1);
                device_buffer[sizeof(device_buffer) - 1] = '\0';
                device = device_buffer;
                printf("Using device: %s\n", device);
                break;
            }
        }
        
        /* 如果没有找到非回环接口，使用第一个设备 */
        if (device == NULL) {
            strncpy(device_buffer, alldevs->name, sizeof(device_buffer) - 1);
            device_buffer[sizeof(device_buffer) - 1] = '\0';
            device = device_buffer;
            printf("Using device: %s\n", device);
        }
    }

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
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        if (alldevs != NULL) {
            pcap_freealldevs(alldevs);
        }
        exit(EXIT_FAILURE);
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
        fprintf(stderr, "pcap_lookupnet() failed: %s\n", errbuf);
        pcap_close(p);
        exit(EXIT_FAILURE);
    }
    
    if (pcap_compile(p, &filter_code, FILTER, 1, netmask) == -1) {
        fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p));
        pcap_close(p);
        exit(EXIT_FAILURE);
    }
    
    if (pcap_setfilter(p, &filter_code) == -1) {
        fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(p));
        pcap_freecode(&filter_code);
        pcap_close(p);
        exit(EXIT_FAILURE);
    }
    
    pcap_freecode(&filter_code);

    /*
     * 确保这是以太网。DLT_EN10MB指定标准的10MB及以上以太网。
     */
    if (pcap_datalink(p) != DLT_EN10MB) {
        fprintf(stderr, "Stroke only works with ethernet.\n");
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    /*
     * 捕获中断信号，以便在退出前告诉用户捕获了多少个数据包。
     * 我们应该在退出前清理内存并释放哈希表。
     */
    if (catch_sig(SIGINT, cleanup) == -1) {
        fprintf(stderr, "can't catch signal.\n");
        pcap_close(p);
        exit(EXIT_FAILURE);
    }

    /*
     * 初始化哈希表并开始循环。只有当用户按下ctrl-c时，循环才会退出，
     * 此时命令提示符会将循环标志变量设置为0。
     */
    ht_init_table(hash_table);
    
    while (loop) {
        struct pcap_pkthdr h;
        const u_char *packet;

        /*
         * pcap_next() 从pcap的内部数据包缓冲区获取下一个数据包。
         */
        packet = pcap_next(p, &h);
        if (packet == NULL) {
            /*
             * 这里需要小心，因为如果定时器超时但数据包缓冲区中没有数据，
             * 或者在Linux的某些特殊情况下，pcap_next()可能返回NULL。
             */
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
    struct pcap_stat ps;
    if (pcap_stats(p, &ps) == -1) {
        fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(p));
    } else {
        /*
         * 注意，ps统计信息根据底层架构可能略有不同。
         * 这里我们简化处理。
         */
        printf("\nPackets received by libpcap:\t%6d\n"
               "Packets dropped by libpcap:\t%6d\n"
               "Unique MAC addresses stored:\t%6lu\n",
               ps.ps_recv, ps.ps_drop, (unsigned long)mac);
    }
    
    pcap_close(p);
    return EXIT_SUCCESS;
}

/*
 * 在OUI表中执行二分查找
 * 时间复杂度约为 O(log n)
 */
const char *b_search(u_char *prefix) {
    int start = 0;
    int end = (int)(sizeof(oui_table) / sizeof(oui_table[0]));

    while (end > start) {
        int mid = (start + end) / 2;
        const struct oui *ent = &oui_table[mid];
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
    static char address[18];
    int n;

    n = sprintf(address, "%.2x:", packet[6]);
    n += sprintf(address + n, "%.2x:", packet[7]);
    n += sprintf(address + n, "%.2x:", packet[8]);
    n += sprintf(address + n, "%.2x:", packet[9]);
    n += sprintf(address + n, "%.2x:", packet[10]);
    n += sprintf(address + n, "%.2x", packet[11]);
    address[n] = '\0';

    return address;
}

/*
 * 将IP地址格式化为可读的字符串格式
 */
char *iprintf(u_char *address) {
    static char ip[17];

    sprintf(ip, "%3d.%3d.%3d.%3d", 
            (int)(address[0] & 255), 
            (int)(address[1] & 255),
            (int)(address[2] & 255), 
            (int)(address[3] & 255));

    return ip;
}

/*
 * 检查数据包中的MAC地址是否是新的（未在哈希表中）
 * 如果是新的，将其添加到哈希表中
 */
int interesting(u_char *packet, struct table_entry **hash_table) {
    u_long n = ht_hash(packet);

    /* 检查哈希到的位置是否已被占用 */
    if (hash_table[n]) {
        /* 检查是重复条目还是哈希冲突 */
        if (!ht_dup_check(packet, hash_table, (int)n)) {
            /* 这是哈希冲突，需要添加一个新的链表节点 */
            if (ht_add_entry(packet, hash_table, (int)n)) {
                mac++;
                return 1;
            }
        } else {
            /* 这是重复条目，忽略它 */
            return 0;
        }
    } else {
        /* 这个哈希表位置是空的 */
        if (ht_add_entry(packet, hash_table, (int)n)) {
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
    if (hash_table[loc] == NULL) {
        /* 这是该位置的第一个条目 */
        hash_table[loc] = (struct table_entry *)malloc(sizeof(struct table_entry));
        if (hash_table[loc] == NULL) {
            return 0;
        }

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
        for (p = hash_table[loc]; p->next != NULL; p = p->next) {
            /* 遍历到链表末尾 */
        }
        
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
    u_long j = 0;

    /* 从第6个字节开始是源MAC地址 */
    for (int i = 6; i != 12; i++) {
        /* 良好的熵值分布 */
        j = (j * 13) + (u_long)packet[i];
    }
    
    return j % HASH_TABLE_SIZE;
}

/*
 * 初始化哈希表，将所有位置设置为NULL
 */
void ht_init_table(struct table_entry **hash_table) {
    for (int c = 0; c < HASH_TABLE_SIZE; c++) {
        hash_table[c] = NULL;
    }
}

/*
 * 信号处理函数 - 当用户按下Ctrl+C时被调用
 */
void cleanup(int signo) {
    (void)signo;  /* 避免未使用参数的警告 */
    loop = 0;
    printf("Interrupt signal caught...\n");
}

/*
 * 捕获信号并设置处理函数
 * 返回值：-1表示失败，1表示成功
 */
int catch_sig(int signo, void (*handler)(int)) {
    struct sigaction action;

    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(signo, &action, NULL) == -1) {
        return -1;
    }
    
    return 1;
}

/* EOF */
