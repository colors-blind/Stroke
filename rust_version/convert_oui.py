#!/usr/bin/env python3
"""
将 C 语言格式的 oui.h 转换为 Rust 格式的 oui.rs

用法:
    python3 convert_oui.py [输入文件] [输出文件]

默认:
    输入: ../oui.h
    输出: src/oui.rs
"""

import sys
import re
from datetime import datetime


def convert_oui_h_to_rust(input_path: str, output_path: str):
    """
    转换 oui.h 到 Rust 格式
    """
    print("=" * 60)
    print("OUI 转换脚本 (C -> Rust)")
    print("=" * 60)
    print(f"\n输入文件: {input_path}")
    print(f"输出文件: {output_path}")

    # 读取输入文件
    try:
        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"\n错误: 找不到输入文件 {input_path}")
        sys.exit(1)

    # 提取日期
    date_match = re.search(r'current as of (\d{4}\.\d{2}\.\d{2})', content)
    oui_date = date_match.group(1) if date_match else datetime.now().strftime("%Y.%m.%d")

    # 提取 OUI 条目
    # 格式: { { 0x00, 0x00, 0x00 }, "XEROX CORPORATION" },
    pattern = r'\{\s*\{\s*0x([0-9A-Fa-f]{2})\s*,\s*0x([0-9A-Fa-f]{2})\s*,\s*0x([0-9A-Fa-f]{2})\s*\}\s*,\s*"([^"]+)"\s*\}'
    
    matches = re.findall(pattern, content)
    
    print(f"\n找到 {len(matches)} 个 OUI 条目")

    if not matches:
        print("警告: 没有找到有效的 OUI 条目")
        sys.exit(1)

    # 转换为 Rust 格式
    # 格式: ([0x00, 0x00, 0x00], "XEROX CORPORATION"),
    rust_entries = []
    for byte1, byte2, byte3, vendor in matches:
        # 转义厂商名称中的特殊字符
        vendor_escaped = vendor.replace('\\', '\\\\').replace('"', '\\"')
        rust_entry = f'    ([0x{byte1}, 0x{byte2}, 0x{byte3}], "{vendor_escaped}"),'
        rust_entries.append(rust_entry)

    # 生成 Rust 代码
    rust_code = f"""//! OUI (Organizationally Unique Identifier) 表
//!
//! 此文件由 convert_oui.py 自动生成
//! 生成日期: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
//! OUI 数据日期: {oui_date}
//!
//! 此表包含 MAC 地址前缀到厂商的映射
//! 按 OUI 前缀排序，支持二分查找

/// OUI 表条目
/// (前缀字节, 厂商名称)
pub type OuiEntry = ([u8; 3], &'static str);

/// 静态 OUI 表
/// 按前缀升序排列，支持二分查找
pub static OUI_TABLE: &[OuiEntry] = &[
"""

    # 添加所有条目
    rust_code += '\n'.join(rust_entries)
    rust_code += """
];

/// 通过 MAC 地址前缀查找厂商
/// 使用二分查找，时间复杂度 O(log n)
pub fn lookup_vendor(mac: &[u8; 6]) -> &'static str {
    let prefix = [mac[0], mac[1], mac[2]];
    
    match OUI_TABLE.binary_search_by_key(&prefix, |&(p, _)| p) {
        Ok(idx) => OUI_TABLE[idx].1,
        Err(_) => "Unknown Vendor",
    }
}

/// 获取 OUI 表中的条目数量
pub fn oui_count() -> usize {
    OUI_TABLE.len()
}

/// 检查 OUI 表是否已排序（用于验证）
#[allow(dead_code)]
pub fn is_sorted() -> bool {
    for i in 1..OUI_TABLE.len() {
        if OUI_TABLE[i - 1].0 > OUI_TABLE[i].0 {
            return false;
        }
    }
    true
}
"""

    # 写入输出文件
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(rust_code)
    except IOError as e:
        print(f"\n错误: 无法写入输出文件 {output_path}: {e}")
        sys.exit(1)

    print(f"\n成功转换 {len(matches)} 个条目")
    print(f"输出文件已保存到: {output_path}")
    print("=" * 60)


if __name__ == '__main__':
    # 默认路径
    input_path = '../oui.h'
    output_path = 'src/oui.rs'

    # 命令行参数
    if len(sys.argv) > 1:
        input_path = sys.argv[1]
    if len(sys.argv) > 2:
        output_path = sys.argv[2]

    convert_oui_h_to_rust(input_path, output_path)
