/*
 *  $Id$
 *
 *  Building Open Source Network Security Tools
 *  stroker_ace.c - builds an OUI header file for use with stroke.c
 *                  Use the ASCII file downloaded from:
 *                  http://standards.ieee.org/regauth/oui
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

/*
 * [安全修复] 这个程序需要 libnet，但实际上只使用了其中的类型定义
 * 如果没有 libnet，可以使用替代的类型定义
 *
 * 注意：如果系统中没有 libnet，可以手动定义这些类型：
 *   typedef unsigned char u_char;
 *   typedef unsigned short u_short;
 *   typedef unsigned int u_int;
 *   typedef unsigned long u_long;
 */
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/*
 * [安全修复] 原来的多行字符串宏写法不安全
 * 改为使用函数或 fputs 直接输出
 */
static const char OUI_PREAMBLE[] =
"/*\n"
" *  Organizationally Unique Identifier list.\n"
" *  This list contains all of the MAC address prefix to organization\n"
" *  identifier mappings.  This header file was auto-generated and should not\n"
" *  be modified.\n"
" *\n"
" */\n"
"\n"
"struct oui\n"
"{\n"
"    u_char prefix[3];       /* 24 bit global prefix */\n"
"    char *vendor;           /* vendor id string */\n"
"};\n"
"\n"
"struct oui oui_table[] = {\n";

/*
 * [安全修复] 使用合理的缓冲区大小
 * BUFSIZ 通常是 8192，但对于厂商名称可能不够
 * 我们使用更大的缓冲区，并添加严格的边界检查
 */
#define READ_BUFFER_SIZE  8192
#define WRITE_BUFFER_SIZE 16384

/*
 * [安全修复] 清理函数，用于确保文件正确关闭
 */
static FILE *g_fp_in = NULL;
static FILE *g_fp_ou = NULL;

static void cleanup_files(void) {
    if (g_fp_in != NULL) {
        fclose(g_fp_in);
        g_fp_in = NULL;
    }
    if (g_fp_ou != NULL) {
        fclose(g_fp_ou);
        g_fp_ou = NULL;
    }
}

int main(int argc, char **argv) {
    int entry_count = 0;
    int has_entries = 0;
    char read_buf[READ_BUFFER_SIZE];
    char writ_buf[WRITE_BUFFER_SIZE];
    long last_pos = 0;

    /*
     * [安全修复] 参数验证
     */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s oui.txt\n", argv[0]);
        fprintf(stderr, "Be sure to use an OUI file from: ");
        fprintf(stderr, "http://standards.ieee.org/regauth/oui\n");
        return EXIT_FAILURE;
    }

    /*
     * [安全修复] 注册清理函数
     * 确保程序正常或异常退出时文件都能正确关闭
     */
    atexit(cleanup_files);

    /*
     * [安全修复] 打开输入文件
     */
    g_fp_in = fopen(argv[1], "r");
    if (g_fp_in == NULL) {
        fprintf(stderr, "can't open %s : %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * [安全修复] 打开输出文件
     */
    g_fp_ou = fopen("oui.h", "w");
    if (g_fp_ou == NULL) {
        fprintf(stderr, "can't open \"oui.h\" : %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * [安全修复] 写入文件头
     * 使用 fputs 替代 write + strlen 宏
     */
    if (fputs(OUI_PREAMBLE, g_fp_ou) == EOF) {
        fprintf(stderr, "can't write preamble: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * 逐行读取输入文件
     */
    while (fgets(read_buf, READ_BUFFER_SIZE, g_fp_in) != NULL) {
        size_t line_len = strlen(read_buf);

        /*
         * [安全修复] 检查行是否被截断
         * 如果行长度等于缓冲区大小减 1，且最后一个字符不是换行符，
         * 说明这行被截断了
         */
        if (line_len == READ_BUFFER_SIZE - 1 && read_buf[line_len] != '\n') {
            /*
             * 行太长，跳过这行并警告
             * 或者读取剩余部分并丢弃
             */
            int ch;
            while ((ch = fgetc(g_fp_in)) != EOF && ch != '\n') {
                /* 丢弃剩余字符 */
            }
            fprintf(stderr, "\nWarning: line too long, skipped (truncated)\n");
            continue;
        }

        /*
         * 我们期望的格式: XX-XX-XX   (hex)    Vendor Name
         * 检查前两个字符是否是十六进制数字，第三个是连字符
         */
        if (isxdigit((unsigned char)read_buf[0]) &&
            isxdigit((unsigned char)read_buf[1]) &&
            read_buf[2] == '-') {
            
            entry_count++;
            fprintf(stderr, "Processing entries: %d\r", entry_count);
            
            /*
             * [安全修复] 解析 OUI
             * 原来的代码使用固定偏移量 memcpy，非常危险
             * 改为使用 sscanf 或手动解析并验证
             */
            unsigned int oui_bytes[3];
            
            /*
             * 解析格式: "XX-XX-XX"
             * 使用 sscanf 更安全且清晰
             */
            if (sscanf(read_buf, "%2X-%2X-%2X",
                       &oui_bytes[0], &oui_bytes[1], &oui_bytes[2]) != 3) {
                fprintf(stderr, "\nWarning: invalid OUI format in line: %.*s\n",
                        (int)line_len, read_buf);
                continue;
            }

            /*
             * [安全修复] 验证 OUI 字节范围
             */
            for (int i = 0; i < 3; i++) {
                if (oui_bytes[i] > 255) {
                    fprintf(stderr, "\nWarning: invalid OUI byte value %u\n",
                            oui_bytes[i]);
                    continue;
                }
            }

            /*
             * [安全修复] 提取厂商名称
             * 原来的代码使用危险的直接索引:
             *   for (j = 18 + 14, k = 29; read_buf[j] != '\n'; j++, k++)
             *   {
             *       writ_buf[k] = read_buf[j];
             *   }
             *
             * 问题:
             * 1. 固定偏移 18+14=32 不可靠
             * 2. k 可以无限增长，导致缓冲区溢出
             * 3. 没有检查 read_buf[j] 的边界
             *
             * 修复方案:
             * 1. 查找 "(hex)" 或 "(base 16)" 标记后的第一个非空白字符
             * 2. 限制厂商名称的最大长度
             * 3. 使用 snprintf 安全构建输出行
             */
            
            /*
             * 查找 "(hex)" 标记
             * 格式: "XX-XX-XX   (hex)\t\tVendor Name"
             * 或: "XX-XX-XX   (hex)    Vendor Name"
             */
            const char *hex_ptr = strstr(read_buf, "(hex)");
            const char *vendor_start = NULL;
            
            if (hex_ptr != NULL) {
                /* 跳过 "(hex)" 以及后面的空白字符 */
                vendor_start = hex_ptr + 5;  // 跳过 "(hex)"
                
                /* 跳过空白字符（制表符和空格） */
                while (*vendor_start != '\0' &&
                       (*vendor_start == '\t' || *vendor_start == ' ')) {
                    vendor_start++;
                }
            }
            
            /*
             * 如果没找到 "(hex)" 标记，使用原来的偏移作为后备方案
             * 但添加边界检查
             */
            if (vendor_start == NULL || *vendor_start == '\0') {
                /* 尝试原来的偏移，但要检查边界 */
                size_t fallback_offset = 32;
                if (fallback_offset < line_len) {
                    vendor_start = read_buf + fallback_offset;
                    /* 跳过前导空白 */
                    while (*vendor_start != '\0' &&
                           (*vendor_start == '\t' || *vendor_start == ' ')) {
                        vendor_start++;
                    }
                }
            }
            
            /*
             * [安全修复] 如果还是找不到厂商名称，使用默认值
             */
            if (vendor_start == NULL || *vendor_start == '\0' ||
                *vendor_start == '\n' || *vendor_start == '\r') {
                vendor_start = "Unknown Vendor";
            }
            
            /*
             * 查找厂商名称的结束位置（换行符或回车）
             */
            const char *vendor_end = vendor_start;
            while (*vendor_end != '\0' &&
                   *vendor_end != '\n' && *vendor_end != '\r') {
                vendor_end++;
            }
            
            /* 计算厂商名称长度 */
            size_t vendor_len = (size_t)(vendor_end - vendor_start);
            
            /*
             * [安全修复] 限制厂商名称的最大长度
             * 防止生成的 C 字符串过长
             */
            const size_t MAX_VENDOR_LEN = 256;
            if (vendor_len > MAX_VENDOR_LEN) {
                vendor_len = MAX_VENDOR_LEN;
            }
            
            /*
             * [安全修复] 转义厂商名称中的特殊字符
             * 需要转义的字符:
             * - 双引号 (") -> \"
             * - 反斜杠 (\) -> \\
             * - 换行符、制表符等控制字符
             */
            char vendor_escaped[MAX_VENDOR_LEN * 2 + 1];  // 最坏情况每个字符都要转义
            size_t escaped_len = 0;
            
            for (size_t i = 0; i < vendor_len && escaped_len < sizeof(vendor_escaped) - 1; i++) {
                char ch = vendor_start[i];
                
                switch (ch) {
                    case '\"':
                        vendor_escaped[escaped_len++] = '\\';
                        vendor_escaped[escaped_len++] = '\"';
                        break;
                    case '\\':
                        vendor_escaped[escaped_len++] = '\\';
                        vendor_escaped[escaped_len++] = '\\';
                        break;
                    case '\n':
                        vendor_escaped[escaped_len++] = '\\';
                        vendor_escaped[escaped_len++] = 'n';
                        break;
                    case '\r':
                        vendor_escaped[escaped_len++] = '\\';
                        vendor_escaped[escaped_len++] = 'r';
                        break;
                    case '\t':
                        vendor_escaped[escaped_len++] = '\\';
                        vendor_escaped[escaped_len++] = 't';
                        break;
                    default:
                        /*
                         * 检查是否是可打印字符
                         * 如果不是，使用八进制转义
                         */
                        if (isprint((unsigned char)ch)) {
                            vendor_escaped[escaped_len++] = ch;
                        } else {
                            /* 不可打印字符，使用八进制转义 */
                            if (escaped_len + 4 <= sizeof(vendor_escaped) - 1) {
                                snprintf(vendor_escaped + escaped_len, 5,
                                        "\\%03o", (unsigned char)ch);
                                escaped_len += 4;
                            }
                        }
                        break;
                }
            }
            
            /* 确保字符串终止 */
            vendor_escaped[escaped_len] = '\0';
            
            /*
             * [安全修复] 安全构建输出行
             * 使用 snprintf 替代手动的 memcpy 拼接
             *
             * 格式: "    { { 0xXX, 0xXX, 0xXX }, \"Vendor Name\" },\n"
             */
            int write_len = snprintf(writ_buf, WRITE_BUFFER_SIZE,
                    "    { { 0x%02X, 0x%02X, 0x%02X }, \"%s\" },\n",
                    oui_bytes[0], oui_bytes[1], oui_bytes[2],
                    vendor_escaped);
            
            /*
             * [安全修复] 检查 snprintf 返回值
             * 如果返回值 >= 缓冲区大小，说明发生了截断
             */
            if (write_len < 0) {
                fprintf(stderr, "\nWarning: snprintf error\n");
                continue;
            }
            
            if ((size_t)write_len >= WRITE_BUFFER_SIZE) {
                fprintf(stderr, "\nWarning: output line too long, truncated\n");
                /* 使用截断后的字符串，但要确保最后是换行符 */
                writ_buf[WRITE_BUFFER_SIZE - 2] = '\n';
                writ_buf[WRITE_BUFFER_SIZE - 1] = '\0';
                write_len = (int)strlen(writ_buf);
            }
            
            /*
             * 记录当前文件位置（用于之后回退删除最后的逗号）
             */
            last_pos = ftell(g_fp_ou);
            if (last_pos == -1) {
                fprintf(stderr, "\nWarning: ftell failed: %s\n", strerror(errno));
                /* 继续，但可能无法正确处理最后的逗号 */
            }
            
            /*
             * 写入输出文件
             */
            if (fputs(writ_buf, g_fp_ou) == EOF) {
                fprintf(stderr, "\ncan't write entry: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }
            
            has_entries = 1;
        }
    }

    /*
     * [安全修复] 检查 fgets 是因为 EOF 还是错误而结束
     */
    if (ferror(g_fp_in)) {
        fprintf(stderr, "\nWarning: error reading input file: %s\n", strerror(errno));
    }

    /*
     * [安全修复] 写入文件尾部
     * 原来的代码:
     *   1. fseek(fp_ou, -2, SEEK_CUR)  // 回退覆盖逗号
     *   2. 写入 ";\n\n/* EOF */\n"
     *
     * 问题:
     * 1. 如果没有任何条目，fseek(-2) 会失败或产生错误结果
     * 2. 使用固定偏移的 fseek 很脆弱
     *
     * 修复方案:
     * 1. 如果有条目，回退到最后一个位置，用分号替换逗号
     * 2. 如果没有条目，输出一个空的数组初始化
     */
    
    if (has_entries) {
        /*
         * 有条目，需要处理最后的逗号
         * 最后一行的格式是: "    { ... },\n"
         * 我们需要把逗号改为分号
         *
         * 实际上，更简单的方法是:
         * 1. 回退到记录的位置
         * 2. 重新写入最后一行，但把逗号改为分号
         *
         * 或者更简单的：
         * 1. 回退 2 个字符（覆盖 ",\n"）
         * 2. 写入 "\n};\n\n/* EOF */\n"
         *
         * 但这种方法依赖于最后一行的确切格式
         * 更安全的方法是使用我们记录的 last_pos
         */
        
        /*
         * 方案: 重新写入最后一行，但用分号结尾
         * 或者使用更简单的方法：
         * 每个条目都以 ",\n" 结尾，我们需要把最后的 ",\n" 改为 "\n"
         * 然后追加 "};\n\n/* EOF */\n"
         */
        
        /*
         * 回退 2 个字符（逗号和换行）
         * 但首先检查是否有足够的空间
         */
        long current_pos = ftell(g_fp_ou);
        if (current_pos >= 2) {
            if (fseek(g_fp_ou, -2, SEEK_CUR) == -1) {
                fprintf(stderr, "can't fseek: %s\n", strerror(errno));
                /* 继续，但可能产生无效的 C 代码 */
            } else {
                /*
                 * 现在我们指向了逗号，写入 "\n};\n\n/* EOF */\n"
                 * 这会覆盖 ",\n" 为 "\n}"
                 */
                const char *suffix = "\n};\n\n/* EOF */\n";
                if (fputs(suffix, g_fp_ou) == EOF) {
                    fprintf(stderr, "can't write suffix: %s\n", strerror(errno));
                    return EXIT_FAILURE;
                }
            }
        } else {
            /* 文件太小，直接写入后缀 */
            const char *suffix = "\n};\n\n/* EOF */\n";
            if (fputs(suffix, g_fp_ou) == EOF) {
                fprintf(stderr, "can't write suffix: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }
        }
    } else {
        /*
         * 没有条目，输出一个空的数组初始化
         */
        const char *empty_suffix = "\n};\n\n/* EOF */\n";
        if (fputs(empty_suffix, g_fp_ou) == EOF) {
            fprintf(stderr, "can't write empty suffix: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        
        fprintf(stderr, "\nWarning: no OUI entries found\n");
    }

    /*
     * [安全修复] 显式关闭文件
     * 虽然 atexit 会处理，但显式关闭是好的实践
     */
    cleanup_files();

    fprintf(stderr, "\nCompleted, built oui.h with %d entries\n", entry_count);
    return EXIT_SUCCESS;
}

/* EOF */
