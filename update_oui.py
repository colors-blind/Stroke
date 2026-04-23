#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OUI更新脚本 - 从IEEE官网下载最新的OUI数据并生成oui.h头文件
用于MAC地址前缀到厂商的映射
"""

import re
import requests
from datetime import datetime
import os
import sys

# IEEE OUI下载地址
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

# 输出文件路径
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.h")


def download_oui_data(url):
    """从IEEE官网下载OUI数据"""
    print(f"正在从 {url} 下载OUI数据...")
    
    try:
        # 设置超时和用户代理
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=60)
        response.raise_for_status()
        
        # 尝试使用utf-8解码，如果失败则使用latin-1
        try:
            content = response.text
        except UnicodeDecodeError:
            content = response.content.decode('latin-1', errors='ignore')
        
        print(f"下载完成，共 {len(content)} 字符")
        return content
        
    except requests.exceptions.RequestException as e:
        print(f"下载失败: {e}")
        sys.exit(1)


def parse_oui_data(content):
    """解析OUI数据，提取OUI前缀和厂商名称"""
    print("正在解析OUI数据...")
    
    oui_entries = []
    
    # 匹配OUI条目模式
    # 格式示例：
    # 00-00-00   (hex)		XEROX CORPORATION
    # 000000     (base 16)		XEROX CORPORATION
    #          地址信息...
    
    # 使用正则表达式匹配hex格式的行
    # 匹配: XX-XX-XX   (hex)  厂商名称
    hex_pattern = re.compile(
        r'^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$',
        re.MULTILINE
    )
    
    matches = hex_pattern.findall(content)
    
    for oui_hex, vendor in matches:
        # 解析OUI (如 "00-00-00")
        parts = oui_hex.split('-')
        if len(parts) == 3:
            # 转换为整数
            byte1 = int(parts[0], 16)
            byte2 = int(parts[1], 16)
            byte3 = int(parts[2], 16)
            
            # 清理厂商名称（去除首尾空白）
            vendor = vendor.strip()
            
            # 处理厂商名称中的特殊字符，避免C字符串问题
            # 转义双引号
            vendor = vendor.replace('"', '\\"')
            
            oui_entries.append({
                'bytes': (byte1, byte2, byte3),
                'vendor': vendor
            })
    
    print(f"共解析到 {len(oui_entries)} 个OUI条目")
    return oui_entries


def sort_oui_entries(entries):
    """按OUI值排序条目（二分法需要有序数组）"""
    print("正在排序OUI条目...")
    
    # 按字节值排序
    sorted_entries = sorted(entries, key=lambda x: x['bytes'])
    
    # 检查排序结果
    if len(sorted_entries) > 1:
        first = sorted_entries[0]['bytes']
        last = sorted_entries[-1]['bytes']
        print(f"排序完成：从 {first[0]:02X}-{first[1]:02X}-{first[2]:02X} "
              f"到 {last[0]:02X}-{last[1]:02X}-{last[2]:02X}")
    
    return sorted_entries


def generate_header_file(entries, output_path):
    """生成C头文件oui.h"""
    print(f"正在生成头文件: {output_path}")
    
    today = datetime.now().strftime("%Y.%m.%d")
    
    # 构建文件内容
    lines = []
    lines.append("")
    lines.append("/*")
    lines.append(f" *  Organizationally Unique Identifier list current as of {today}.")
    lines.append(" *  This list contains all of the MAC address prefix to organization")
    lines.append(" *  identifier mappings.  This header file was auto-generated and should not")
    lines.append(" *  be modified.")
    lines.append(" *")
    lines.append(" */")
    lines.append("")
    lines.append("struct oui")
    lines.append("{")
    lines.append("    u_char prefix[3];       /* 24 bit global prefix */")
    lines.append("    char *vendor;           /* vendor id string */")
    lines.append("};")
    lines.append("")
    lines.append("struct oui oui_table[] = {")
    
    # 生成条目
    for i, entry in enumerate(entries):
        b1, b2, b3 = entry['bytes']
        vendor = entry['vendor']
        
        # 格式: { { 0x00, 0x00, 0x00 }, "VENDOR NAME" },
        line = f"    {{ {{ 0x{b1:02X}, 0x{b2:02X}, 0x{b3:02X} }}, \"{vendor}\" }}"
        
        # 最后一个条目不需要逗号
        if i < len(entries) - 1:
            line += ","
        
        lines.append(line)
    
    lines.append("};")
    lines.append("")
    lines.append("/* EOF */")
    lines.append("")
    
    # 写入文件
    content = "\n".join(lines)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"头文件生成完成，共 {len(entries)} 个条目")
    return True


def verify_sorted(entries):
    """验证条目是否已正确排序（用于调试）"""
    for i in range(1, len(entries)):
        if entries[i]['bytes'] < entries[i-1]['bytes']:
            print(f"错误：排序失败！索引 {i-1} 和 {i} 顺序错误")
            return False
    print("排序验证通过")
    return True


def main():
    """主函数"""
    print("=" * 60)
    print("OUI更新脚本")
    print("=" * 60)
    
    # 1. 下载数据
    content = download_oui_data(IEEE_OUI_URL)
    
    # 2. 解析数据
    entries = parse_oui_data(content)
    
    if not entries:
        print("错误：没有解析到任何OUI条目")
        sys.exit(1)
    
    # 3. 排序数据
    sorted_entries = sort_oui_entries(entries)
    
    # 4. 验证排序
    verify_sorted(sorted_entries)
    
    # 5. 生成头文件
    if generate_header_file(sorted_entries, OUTPUT_FILE):
        print("=" * 60)
        print("更新成功！")
        print(f"新的OUI文件已保存至: {OUTPUT_FILE}")
        print("=" * 60)
        
        # 显示统计信息
        print("\n统计信息:")
        print(f"  总条目数: {len(sorted_entries)}")
        first = sorted_entries[0]['bytes']
        last = sorted_entries[-1]['bytes']
        print(f"  OUI范围: {first[0]:02X}-{first[1]:02X}-{first[2]:02X} "
              f"~ {last[0]:02X}-{last[1]:02X}-{last[2]:02X}")
    else:
        print("生成头文件失败！")
        sys.exit(1)


if __name__ == "__main__":
    main()
