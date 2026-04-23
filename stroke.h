/*
 *  $Id: stroke.h,v 1.1.1.1 2001/11/29 00:16:48 route Exp $
 *
 *  Building Open Source Network Security Tools
 *  stroke.h - pcap example code
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

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include "./oui.h"

/* 捕获的数据包最大长度 */
#define SNAPLEN         34
/* 混杂模式 */
#define PROMISC         1
/* 超时时间(毫秒) */
#define TIMEOUT         500
/* BPF过滤器表达式 */
#define FILTER          ""
/* 哈希表大小(必须为素数) */
#define HASH_TABLE_SIZE 251

/* 哈希表条目结构 */
struct table_entry {
    u_char mac[6];              /* 存储MAC地址 */
    struct table_entry *next;   /* 指向链表中下一个条目 */
};

/* 二分查找OUI表 */
const char *b_search(u_char *);
/* 格式化MAC地址为字符串 */
char *eprintf(u_char *);
/* 格式化IP地址为字符串 */
char *iprintf(u_char *);
/* 检查MAC地址是否已存在 */
int interesting(u_char *, struct table_entry **);
/* 检查重复MAC地址 */
int ht_dup_check(u_char *, struct table_entry **, int);
/* 添加哈希表条目 */
int ht_add_entry(u_char *, struct table_entry **, int);
/* 计算哈希值 */
u_long ht_hash(u_char *);
/* 初始化哈希表 */
void ht_init_table(struct table_entry **);
/* 清理函数 */
void cleanup(int);
/* 信号捕获函数 */
int catch_sig(int, void(*handler)(int));

/* EOF */
