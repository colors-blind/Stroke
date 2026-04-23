# Stroke

原始代码 来源于书籍 《Building Open Source Network Security Tools: Components and Techniques》

`Stroke` 是一个基于 `libpcap` 的被动网络监听工具，用于抓取局域网中的以太网数据包，提取源 MAC 地址，并将其映射为厂商（OUI）信息。

项目同时提供了一个辅助工具 `stroker_ace`，可从 IEEE 的 OUI 文本文件生成 `oui.h` 头文件，供 `stroke` 做二分查找匹配。

## 功能特性

- 被动抓包并识别新的源 MAC 地址
- 通过 OUI 前缀映射设备厂商
- 使用哈希表去重，避免重复输出同一 MAC
- 可选显示源 IP（`-I` 参数）
- 退出时输出抓包统计信息（接收/丢弃包数、唯一 MAC 数）

## 目录与文件说明

- `stroke.c`：主程序，负责抓包、去重、OUI 映射与输出
- `stroke.h`：公共定义与函数声明
- `oui.h`：OUI 映射表（自动生成或已预置）
- `stroker_ace.c`：把 IEEE OUI 文本转换成 `oui.h` 的生成器
- `Makefile`：编译规则

## 依赖要求

### 运行 `stroke` 需要

- `gcc`
- `libpcap`（开发头文件与动态库）

### 构建 `stroker_ace` 需要

- `libnet` 头文件（`stroker_ace.c` 包含了 `<libnet.h>`）

在 Debian/Ubuntu 可参考：

```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libnet1-dev
```

## 编译

在项目根目录执行：

```bash
make
```

会生成两个可执行文件：

- `stroke`
- `stroker_ace`

清理构建产物：

```bash
make clean
```

## 使用方法

### 1) 运行抓包程序

```bash
sudo ./stroke [-I] [-i <网卡名>]
```

参数说明：

- `-i <网卡名>`：指定抓包网卡（例如 `eth0`、`enp3s0`）
- `-I`：输出中附带源 IP 地址

如果不指定 `-i`，程序会调用 `pcap_lookupdev()` 自动选择网卡。

示例：

```bash
sudo ./stroke -i eth0
sudo ./stroke -I -i eth0
```

示例输出（格式）：

```text
Stroke 1.0 [passive MAC -> OUI mapping tool]
<ctrl-c> to quit
00:11:22:33:44:55 -> CISCO SYSTEMS, INC.
aa:bb:cc:dd:ee:ff @ 192.168.1.10 -> XEROX CORPORATION
```

按 `Ctrl+C` 结束后会输出统计信息。

### 2) 重新生成 `oui.h`（可选）

如果你希望更新厂商表，可从 IEEE 下载 OUI 文本（项目源码注释中的地址），然后执行：

```bash
./stroker_ace oui.txt
```

该命令会在当前目录生成新的 `oui.h`。

## 实现说明

- `stroke` 使用 `pcap_open_live()` 以混杂模式抓包
- `SNAPLEN` 为 `34` 字节，覆盖以太网头并可选读取 IPv4 地址
- 哈希表大小为 `251`（质数），冲突采用链地址法
- OUI 查找使用二分搜索，复杂度约为 `O(log n)`

## 注意事项

- 抓包通常需要 root 权限或对应能力（如 `CAP_NET_RAW`/`CAP_NET_ADMIN`）
- 程序仅支持以太网链路类型（`DLT_EN10MB`）
- 当前仓库中的 `oui.h` 数据较旧（头部标注为 2002 年），建议按需更新

## 许可证

源码头部使用 BSD 风格许可（2-Clause 风格条款）。
