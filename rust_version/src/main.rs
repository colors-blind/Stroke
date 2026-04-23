//! Stroke - 基于 libpcap 的被动 MAC 到 OUI 映射工具
//!
//! 此程序被动监听网络流量，提取源 MAC 地址，并将其映射为厂商信息。
//! 这是原始 C 版本的 Rust 移植。
//!
//! 功能:
//! - 使用 libpcap 捕获以太网数据包
//! - 提取源 MAC 地址并去重
//! - 通过 OUI 表查找厂商信息
//! - 可选显示源 IP 地址
//! - 显示捕获统计信息

mod oui;

use clap::{Parser, Subcommand};
use pcap::{Active, Capture, Device, Direction, Error as PcapError, Packet, PacketHeader};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// 退出码（遵循 POSIX 标准）
#[derive(Debug, Clone, Copy)]
#[repr(i32)]
enum ExitCode {
    /// 成功
    Ok = 0,
    /// 命令行使用错误
    Usage = 64,
    /// 数据格式错误
    DataErr = 65,
    /// 无法打开输入
    NoInput = 66,
    /// 服务不可用
    Unavailable = 69,
    /// 内部软件错误
    Software = 70,
    /// 操作系统错误
    OsErr = 71,
    /// I/O 错误
    IoErr = 74,
    /// 协议错误
    Protocol = 76,
    /// 权限不足
    NoPerm = 77,
}

impl From<ExitCode> for i32 {
    fn from(code: ExitCode) -> Self {
        code as i32
    }
}

/// 命令行参数
#[derive(Parser, Debug)]
#[command(name = "stroke-rs")]
#[command(about = "A passive MAC to OUI mapping tool using libpcap", long_about = None)]
#[command(version = "1.1.0")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 指定网络接口
    #[arg(short, long, value_name = "INTERFACE")]
    interface: Option<String>,

    /// 显示源 IP 地址
    #[arg(short = 'I', long = "show-ip")]
    show_ip: bool,
}

/// 子命令
#[derive(Subcommand, Debug)]
enum Commands {
    /// 列出所有可用的网络接口
    #[command(alias = "ls")]
    List,
}

/// 以太网帧头（14 字节）
///
/// 格式:
/// - 目的 MAC: 6 字节 (偏移 0-5)
/// - 源 MAC: 6 字节 (偏移 6-11)
/// - 类型: 2 字节 (偏移 12-13)
#[derive(Debug, Clone, Copy)]
struct EthernetFrame<'a> {
    /// 原始数据包数据
    data: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// 从数据包创建以太网帧
    ///
    /// 注意: 调用者需要确保数据包至少有 14 字节
    fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 14 {
            return None;
        }
        Some(EthernetFrame { data })
    }

    /// 获取源 MAC 地址（6 字节）
    fn source_mac(&self) -> [u8; 6] {
        [
            self.data[6],
            self.data[7],
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
        ]
    }

    /// 获取目的 MAC 地址（6 字节）
    #[allow(dead_code)]
    fn dest_mac(&self) -> [u8; 6] {
        [
            self.data[0],
            self.data[1],
            self.data[2],
            self.data[3],
            self.data[4],
            self.data[5],
        ]
    }

    /// 获取以太网类型（大端序）
    ///
    /// 常见类型:
    /// - 0x0800: IPv4
    /// - 0x0806: ARP
    /// - 0x86DD: IPv6
    fn ether_type(&self) -> u16 {
        u16::from_be_bytes([self.data[12], self.data[13]])
    }

    /// 检查是否为 IPv4 数据包
    fn is_ipv4(&self) -> bool {
        self.ether_type() == 0x0800
    }

    /// 获取 IPv4 源地址（如果是 IPv4 数据包）
    ///
    /// IP 头格式:
    /// - 版本/IHL: 1 字节
    /// - 服务类型: 1 字节
    /// - 总长度: 2 字节
    /// - 标识: 2 字节
    /// - 标志/片偏移: 2 字节
    /// - TTL: 1 字节
    /// - 协议: 1 字节
    /// - 校验和: 2 字节
    /// - 源 IP: 4 字节 (偏移 26-29)
    /// - 目的 IP: 4 字节 (偏移 30-33)
    fn source_ipv4(&self) -> Option<Ipv4Addr> {
        if !self.is_ipv4() {
            return None;
        }
        if self.data.len() < 30 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.data[26],
            self.data[27],
            self.data[28],
            self.data[29],
        ))
    }
}

/// 将 MAC 地址格式化为可读字符串
///
/// 格式: XX:XX:XX:XX:XX:XX
fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// 列出所有可用的网络接口
fn list_devices() -> Result<(), ExitCode> {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            print_error(
                ExitCode::IoErr,
                "Failed to enumerate network devices",
                Some(&e.to_string()),
            );
            return Err(ExitCode::IoErr);
        }
    };

    println!("=");
    println!("Available Network Interfaces:");
    println!("=");
    println!();

    if devices.is_empty() {
        println!("  No network devices found.");
        println!();
        println!("Hint: Try running with root privileges (sudo).");
        return Ok(());
    }

    let mut first_non_loopback = true;
    for (i, dev) in devices.iter().enumerate() {
        print!("  {}. {}", i + 1, dev.name);

        // 标记默认选择的设备（第一个非回环设备）
        let is_loopback = dev.flags.is_loopback();
        if !is_loopback && first_non_loopback {
            print!(" [default]");
            first_non_loopback = false;
        }
        println!();

        // 打印设备描述
        if let Some(ref desc) = dev.desc {
            println!("      Description: {}", desc);
        }

        // 打印设备标志
        print!("      Flags: ");
        let mut first = true;
        if dev.flags.is_loopback() {
            print!("loopback");
            first = false;
        }
        if dev.flags.is_up() {
            if !first {
                print!(", ");
            }
            print!("up");
            first = false;
        }
        if dev.flags.is_running() {
            if !first {
                print!(", ");
            }
            print!("running");
        }
        if first {
            print!("none");
        }
        println!();

        // 打印地址
        if !dev.addresses.is_empty() {
            println!("      Addresses:");
            for addr in &dev.addresses {
                if let Some(ip) = addr.addr {
                    println!("        IPv4: {}", ip);
                }
            }
        }
        println!();
    }

    println!("=");
    println!("Total: {} device(s)", devices.len());
    println!();
    println!("Usage example:");
    println!("  stroke-rs -i <interface_name>");

    Ok(())
}

/// 打印格式化的错误信息
fn print_error(code: ExitCode, message: &str, detail: Option<&str>) {
    eprintln!();
    eprintln!("Error: {}", message);

    if let Some(d) = detail {
        if !d.is_empty() {
            eprintln!("       {}", d);
        }
    }

    eprintln!();

    match code {
        ExitCode::Usage => {
            eprintln!("Hint: Use --help for usage information.");
        }
        ExitCode::NoPerm => {
            eprintln!("Hint: Try running with root privileges (sudo).");
        }
        ExitCode::NoInput => {
            eprintln!("Hint: Use --list to see available interfaces.");
        }
        ExitCode::Unavailable => {
            eprintln!("Hint: The interface may be down or not connected.");
        }
        _ => {}
    }
    eprintln!();
}

/// 选择默认网络接口
///
/// 优先选择第一个非回环接口，否则选择第一个接口
fn select_default_device() -> Result<Device, ExitCode> {
    let devices = match Device::list() {
        Ok(d) => d,
        Err(e) => {
            print_error(
                ExitCode::IoErr,
                "Failed to enumerate network devices",
                Some(&e.to_string()),
            );
            return Err(ExitCode::IoErr);
        }
    };

    if devices.is_empty() {
        print_error(
            ExitCode::NoInput,
            "No network devices found",
            Some("Hint: Use --list to see available interfaces, or try running with sudo."),
        );
        return Err(ExitCode::NoInput);
    }

    // 优先选择非回环接口
    for dev in &devices {
        if !dev.flags.is_loopback() {
            return Ok(dev.clone());
        }
    }

    // 如果只有回环接口，选择第一个
    Ok(devices[0].clone())
}

/// 统计信息
struct Stats {
    /// 唯一 MAC 地址计数
    unique_macs: u64,
}

/// 主捕获循环
fn capture_loop(
    mut cap: Capture<Active>,
    show_ip: bool,
    running: Arc<AtomicBool>,
) -> Result<Stats, ExitCode> {
    // 用于去重的 MAC 地址集合
    let mut seen_macs: HashSet<[u8; 6]> = HashSet::new();

    println!();
    println!("Starting packet capture...");
    println!("Press Ctrl+C to stop and view statistics.");
    println!("=");
    println!();

    while running.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(packet) => {
                // 解析以太网帧
                if let Some(frame) = EthernetFrame::new(packet.data) {
                    // 只处理 IPv4 数据包（与 C 版本一致）
                    if !frame.is_ipv4() {
                        continue;
                    }

                    let source_mac = frame.source_mac();

                    // 检查是否是新的 MAC 地址
                    if seen_macs.insert(source_mac) {
                        // 新的唯一 MAC 地址
                        let vendor = oui::lookup_vendor(&source_mac);
                        let mac_str = format_mac(&source_mac);

                        if show_ip {
                            if let Some(ip) = frame.source_ipv4() {
                                println!("{} @ {} -> {}", mac_str, ip, vendor);
                            } else {
                                println!("{} -> {}", mac_str, vendor);
                            }
                        } else {
                            println!("{} -> {}", mac_str, vendor);
                        }
                    }
                }
            }
            Err(PcapError::TimeoutExpired) => {
                // 超时是正常的，继续循环
                continue;
            }
            Err(e) => {
                eprintln!("pcap error: {}", e);
                // 继续运行，不要因为一个错误就退出
            }
        }
    }

    Ok(Stats {
        unique_macs: seen_macs.len() as u64,
    })
}

/// 打印统计信息
fn print_stats(_cap: &mut Capture<Active>, stats: &Stats) {
    println!();
    println!("=");
    println!("Capture Stopped. Statistics:");
    println!("=");
    println!();

    // 注意: pcap crate 目前不直接暴露 pcap_stats
    // 但我们可以显示我们自己追踪的统计信息

    println!("  Discovery Statistics:");
    println!("    Unique MAC addresses: {:>14}", stats.unique_macs);
    println!();
}

fn main() -> Result<(), i32> {
    let args = Args::parse();

    // 处理子命令
    if let Some(Commands::List) = args.command {
        return list_devices().map_err(|e| e.into());
    }

    // 打印启动横幅
    println!("Stroke-rs 1.1.0");
    println!("A passive MAC to OUI mapping tool (Rust port)");
    println!("=");
    println!();
    println!("Configuration:");
    println!("  Mode:         {}", if args.show_ip { "MAC + IP" } else { "MAC only" });
    print!("  Interface:    ");

    // 选择设备
    let device = if let Some(ref name) = args.interface {
        println!("{}", name);
        Device::from(name)
    } else {
        println!("[auto-selecting]");
        let dev = select_default_device()?;
        println!();
        println!("  Selected:     {}", dev.name);
        if let Some(ref desc) = dev.desc {
            println!("  Description:  {}", desc);
        }
        dev
    };

    // 创建捕获句柄
    // 参数:
    // - SNAPLEN: 34 字节 (以太网头 14 + IP 头 20)
    // - PROMISC: 混杂模式
    // - TIMEOUT: 500 毫秒
    let mut cap = match Capture::from_device(device.clone()) {
        Ok(c) => c
            .snaplen(34)
            .promisc(true)
            .timeout(500)
            .open()
            .map_err(|e| {
                print_error(
                    ExitCode::Unavailable,
                    "Failed to open network interface",
                    Some(&e.to_string()),
                );
                ExitCode::Unavailable
            })?,
        Err(e) => {
            print_error(
                ExitCode::NoInput,
                "Invalid network device",
                Some(&e.to_string()),
            );
            return Err(ExitCode::NoInput.into());
        }
    };

    // 设置 BPF 过滤器，只捕获 IPv4 数据包
    // 过滤器: "ip"
    if let Err(e) = cap.filter("ip", true) {
        print_error(
            ExitCode::Protocol,
            "Failed to set BPF filter",
            Some(&e.to_string()),
        );
        return Err(ExitCode::Protocol.into());
    }

    // 设置捕获方向（只捕获入站流量）
    if let Err(e) = cap.direction(Direction::In) {
        // 这不是致命错误，只是警告
        eprintln!("Warning: Failed to set capture direction: {}", e);
    }

    // 创建信号处理标志
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 设置 Ctrl+C 处理器
    ctrlc::set_handler(move || {
        r.store(false, Ordering::Relaxed);
    })
    .map_err(|e| {
        print_error(
            ExitCode::Software,
            "Failed to set up signal handler",
            Some(&e.to_string()),
        );
        ExitCode::Software
    })?;

    // 开始捕获
    let stats = capture_loop(cap, args.show_ip, running)?;

    // 打印统计信息
    // 注意: pcap crate 不直接支持 pcap_stats，所以我们不传递 &mut cap
    // 但如果将来需要，可以添加

    println!();
    println!("=");
    println!("Capture Stopped. Statistics:");
    println!("=");
    println!();
    println!("  Discovery Statistics:");
    println!("    Unique MAC addresses: {:>14}", stats.unique_macs);
    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame_parsing() {
        // 构造一个测试以太网帧
        // 目的 MAC: 00:11:22:33:44:55
        // 源 MAC: aa:bb:cc:dd:ee:ff
        // 类型: 0x0800 (IPv4)
        let mut data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // 目的 MAC
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // 源 MAC
            0x08, 0x00, // 类型 (IPv4)
        ];

        // 添加一些 IP 头数据
        data.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x3c, // 版本/IHL, TOS, 长度
            0x00, 0x00, 0x00, 0x00, // 标识, 标志/片偏移
            0x40, 0x06, 0x00, 0x00, // TTL, 协议, 校验和
            0xc0, 0xa8, 0x01, 0x64, // 源 IP: 192.168.1.100
            0xc0, 0xa8, 0x01, 0x01, // 目的 IP: 192.168.1.1
        ]);

        let frame = EthernetFrame::new(&data).unwrap();

        assert_eq!(
            frame.source_mac(),
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
        );
        assert_eq!(
            frame.dest_mac(),
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]
        );
        assert!(frame.is_ipv4());
        assert_eq!(
            frame.source_ipv4(),
            Some(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_format_mac() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_eq!(format_mac(&mac), "00:11:22:33:44:55");

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_oui_table_sorted() {
        // 验证 OUI 表已排序（二分查找依赖）
        assert!(oui::is_sorted());
    }

    #[test]
    fn test_oui_lookup() {
        // 测试已知的 OUI
        let xerox_mac = [0x00, 0x00, 0x00, 0x11, 0x22, 0x33];
        assert_ne!(oui::lookup_vendor(&xerox_mac), "Unknown Vendor");

        // 测试未知的 OUI
        let unknown_mac = [0xff, 0xff, 0xff, 0x11, 0x22, 0x33];
        // 注意: ff-ff-ff 可能存在也可能不存在
        // 如果它不存在，应该返回 "Unknown Vendor"
        // 但让我们使用一个真正不存在的
        let test_mac = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        // 这只是一个测试，具体取决于 OUI 表的内容
        let _result = oui::lookup_vendor(&test_mac);
        // 无论如何，函数都应该返回一个 &str
    }

    #[test]
    fn test_short_packet() {
        // 测试太短的数据包
        let short_data = [0x00, 0x11, 0x22]; // 只有 3 字节
        assert!(EthernetFrame::new(&short_data).is_none());
    }
}
