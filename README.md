# Stroke

原始代码来源于书籍 《Building Open Source Network Security Tools: Components and Techniques》

`Stroke` 是一个基于 `libpcap` 的被动网络监听工具，用于抓取局域网中的以太网数据包，提取源 MAC 地址，并将其映射为厂商（OUI）信息。

项目提供了两种方式更新 OUI 厂商表：
- `stroker_ace.c`：从本地 IEEE OUI 文本文件生成 `oui.h`（需要 `libnet`）
- `update_oui.py`：**推荐方式** - 自动从 IEEE 官网下载最新数据并生成 `oui.h`

## 功能特性

- 被动抓包并识别新的源 MAC 地址
- 通过 OUI 前缀映射设备厂商
- 使用哈希表去重，避免重复输出同一 MAC
- 可选显示源 IP（`-I` 参数）
- 退出时输出抓包统计信息（接收/丢弃包数、唯一 MAC 数）
- **新增**：一键更新最新 OUI 厂商表（`update_oui.py`）

## 目录与文件说明

| 文件 | 说明 |
|------|------|
| `stroke.c` | 主程序，负责抓包、去重、OUI 映射与输出 |
| `stroke.h` | 公共定义与函数声明 |
| `oui.h` | OUI 映射表（自动生成或已预置） |
| `stroker_ace.c` | 把 IEEE OUI 文本转换成 `oui.h` 的生成器（C语言） |
| `update_oui.py` | **推荐** - Python 脚本，自动从 IEEE 官网下载并更新 `oui.h` |
| `requirements.txt` | Python 依赖库列表 |
| `Makefile` | 编译规则 |

## 依赖要求

### 运行 `stroke` 需要

- `gcc`
- `libpcap`（开发头文件与动态库）

### 构建 `stroker_ace` 需要（可选）

- `libnet` 头文件（`stroker_ace.c` 包含了 `<libnet.h>`）

### 运行 `update_oui.py` 需要（推荐）

- `Python 3.6+`
- `requests` 库

在 Debian/Ubuntu 可参考：

```bash
# 安装编译依赖
sudo apt update
sudo apt install -y build-essential libpcap-dev libnet1-dev

# 安装 Python 依赖（用于 update_oui.py）
sudo apt install -y python3 python3-pip
pip3 install -r requirements.txt
```

## 编译

在项目根目录执行：

```bash
make
```

会生成两个可执行文件：

- `stroke`
- `stroker_ace`（如未安装 `libnet` 会编译失败，不影响 `stroke` 使用）

**注意**：如果只需要 `stroke`，可以单独编译：

```bash
make stroke
```

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

| 参数 | 说明 |
|------|------|
| `-i <网卡名>` | 指定抓包网卡（例如 `eth0`、`enp3s0`、`wlan0`） |
| `-I` | 输出中附带源 IP 地址 |

如果不指定 `-i`，程序会自动选择第一个可用的非回环网卡。

示例：

```bash
sudo ./stroke -i eth0
sudo ./stroke -I -i eth0
```

示例输出（格式）：

```text
Stroke 1.0 [passive MAC -> OUI mapping tool]
<ctrl-c> to quit
Using device: eth0
00:11:22:33:44:55 -> CISCO SYSTEMS, INC.
aa:bb:cc:dd:ee:ff @ 192.168.1.10 -> XEROX CORPORATION
```

按 `Ctrl+C` 结束后会输出统计信息。

---

### 2) **推荐方式**：使用 `update_oui.py` 更新 OUI 厂商表

项目预置的 `oui.h` 数据较旧（2002 年），建议使用 Python 脚本一键更新到最新版本。

#### 2.1 安装 Python 依赖

```bash
pip3 install -r requirements.txt
```

或者单独安装：

```bash
pip3 install requests
```

#### 2.2 运行更新脚本

```bash
python3 update_oui.py
```

脚本会自动完成以下步骤：
1. 从 `https://standards-oui.ieee.org/oui/oui.txt` 下载最新 OUI 数据
2. 解析所有 OUI 条目（前缀 + 厂商名称）
3. **按 OUI 值排序**（确保二分查找算法能正确工作）
4. 生成新的 `oui.h` 头文件

#### 2.3 运行输出示例

```text
============================================================
OUI更新脚本
============================================================
正在从 https://standards-oui.ieee.org/oui/oui.txt 下载OUI数据...
下载完成，共 12345678 字符
正在解析OUI数据...
共解析到 54321 个OUI条目
正在排序OUI条目...
排序完成：从 00-00-00 到 FF-FF-FF
排序验证通过
正在生成头文件: /path/to/oui.h
头文件生成完成，共 54321 个条目
============================================================
更新成功！
新的OUI文件已保存至: /path/to/oui.h
============================================================

统计信息:
  总条目数: 54321
  OUI范围: 00-00-00 ~ FF-FF-FF
```

#### 2.4 重新编译 `stroke`

更新 `oui.h` 后，需要重新编译 `stroke` 才能生效：

```bash
make clean && make stroke
```

---

### 3) 备选方式：使用 `stroker_ace` 更新 OUI 厂商表（需 `libnet`）

如果你已经手动从 IEEE 下载了 `oui.txt` 文件，可以使用 `stroker_ace` 工具：

```bash
./stroker_ace oui.txt
```

该命令会在当前目录生成新的 `oui.h`。

**注意**：此方式需要 `libnet` 库，且需要手动下载 `oui.txt` 文件，推荐使用 `update_oui.py`。

---

## 实现说明

### `stroke` 主程序

- 使用 `pcap_open_live()` 以混杂模式抓包
- `SNAPLEN` 为 `34` 字节，覆盖以太网头并可选读取 IPv4 地址
- 哈希表大小为 `251`（质数），冲突采用链地址法
- OUI 查找使用**二分搜索**，复杂度约为 `O(log n)`
- **重要**：`oui_table` 必须按 OUI 值排序，否则二分查找无法工作

### `update_oui.py` 脚本

- 从 IEEE 官网自动下载最新 OUI 数据（`https://standards-oui.ieee.org/oui/oui.txt`）
- 使用正则表达式解析 `XX-XX-XX   (hex)   Vendor Name` 格式
- 解析后按 OUI 字节值**升序排序**
- 生成与现有代码完全兼容的 `oui.h` 格式
- 包含排序验证，确保二分查找可用

## 注意事项

- 抓包通常需要 root 权限或对应能力（如 `CAP_NET_RAW`/`CAP_NET_ADMIN`）
- 程序仅支持以太网链路类型（`DLT_EN10MB`）
- **OUI 表必须排序**：二分查找依赖有序数组，`update_oui.py` 已自动处理排序
- 建议定期更新 OUI 表以识别新的网络设备厂商

## 常见问题

### Q: 为什么更新 OUI 表后还是无法识别某些设备？
A: 请确保：
1. 重新编译了 `stroke`（`make clean && make stroke`）
2. `update_oui.py` 运行成功且没有错误

### Q: 如何查看当前系统有哪些网卡？
A: 使用以下命令：
```bash
ip link show
# 或
ifconfig -a
```

### Q: `pcap_lookupnet() failed: No such device` 错误？
A: 这是因为使用了无效的网卡名。请：
1. 确认网卡名是否正确（使用 `ip link show` 查看）
2. 或者不指定 `-i` 参数，让程序自动选择网卡

### Q: 为什么需要 sudo 才能运行？
A: 网络抓包需要特殊权限。你也可以通过以下方式赋予程序权限：
```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./stroke
```

## 许可证

源码头部使用 BSD 风格许可（2-Clause 风格条款）。
