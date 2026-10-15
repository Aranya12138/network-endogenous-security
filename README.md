# 项目运行说明

三模态网络内生安全实验：源网关调度三份异构模态副本（IPv4 / IPv6 / Source Routing），目的网关在 P4 数据面完成 2/3 数据完整性裁决、重复抑制与透明还原，中间交换机支持按模态和序号注入可重复的篡改/丢包故障。

## 1. 团队信息

- 组号：[待填]
- 组长：[待填]
- 成员名单：陈加豪、王家荣、陈辉腾、李正正、钟华涛、林富强
- Git 仓库：https://github.com/Aranya12138/network-endogenous-security

| 成员 | 主要工作 | 个人总结位置 | 贡献比例 |
| --- | --- | --- | ---: |
| 陈加豪（102401529） | 环境准备与三模态基线，路径证据与回归检查 | 个人材料/个人总结-组号-102401529-陈加豪.docx | [待填] |
| 王家荣（102401522） | 测试验证、结果分析、证据与报告整合 | 个人材料/个人总结-组号-102401522-王家荣.docx | [待填] |
| 陈辉腾（102401521） | 源网关P4调度与异构封装 | 个人材料/个人总结-组号-102401521-陈辉腾.docx | [待填] |
| 李正正（102401520） | 控制平面组播、调度表项与网关角色配置 | 个人材料/个人总结-组号-102401520-李正正.docx | [待填] |
| 钟华涛（102401516） | 目的网关裁决、模态去重与透明还原 | 个人材料/个人总结-组号-102401516-钟华涛.docx | [待填] |
| 林富强（102401510） | 故障注入与模态统计反馈 | 个人材料/个人总结-组号-102401510-林富强.docx | [待填] |

## 2. 环境

- 镜像：`2026-Aug-01` P4 tutorials 镜像（Ubuntu 24.10）
- 架构：BMv2（`simple_switch_grpc`）+ v1model，P4Runtime 控制面
- 最终 Git commit：class4-final 标签指向的提交（git rev-parse class4-final）

## 3. 项目版本

- 起始版本：class1 三模态基线（IPv4/IPv6/SR 三条转发路径，`polymorphic.p4.bak` / `mycontroller.py.bak` 为基线存档）
- 最终版本：class4-final
- 主要阶段 tag：`class1-baseline`、`class2-multicast`、`class3-adjudication`、`class4-final`

## 4. 编译和启动

进入本项目目录后执行：

```bash
make
```

`make` 会编译 `polymorphic.p4`（生成 `build/polymorphic.json` 与 `build/polymorphic.p4.p4info.txtpb`）并启动 Mininet 拓扑（10 台交换机、2 台主机），出现 `mininet>` 提示符即成功。

若当前终端提示找不到 `p4c-bm2-ss`、`simple_switch_grpc` 或 `mn` 等命令，执行一次 `source ~/p4setup.bash` 后重试（无需在每个终端重复执行）。

另开一个终端（同样进入项目目录）启动控制器：

```bash
python3 mycontroller.py
```

控制器会向全部 10 台交换机下发 P4 程序、IPv4/IPv6 LPM 转发表、ARP 应答规则、组播组 10（端口 2/3/4 各一份副本）、源网关调度规则（方向 0 在 S1、方向 1 在 S2）和目的网关裁决角色（方向 0 在 S2、方向 1 在 S1）。

按模态和序号注入故障（示例）：

```bash
# 单模态篡改：mode 1 的第 1 个包 protected_data 最低位翻转
python3 mycontroller.py --fault corrupt:1:1:0x1
# 单模态丢包：丢弃 mode 2 的第 1 个包
python3 mycontroller.py --fault drop:2:1
```

## 5. 自动测试

先退出手工启动的 Mininet 并清理：

```bash
make stop
make clean
```

再执行五个验收场景（每个场景独立完成编译、启动、下发表项、收发和清理）：

```bash
python3 run-poly-tests.py
```

预期输出：

```text
SCENARIO_PASS no-fault
SCENARIO_PASS reverse
SCENARIO_PASS corrupt-mode1
SCENARIO_PASS drop-mode2
SCENARIO_PASS no-majority
ALL_SCENARIOS_PASS 5
```

单独调试某一场景：`python3 run-poly-tests.py no-fault`（或 `reverse` / `corrupt-mode1` / `drop-mode2` / `no-majority`）。

## 6. 手工测试和计数器

接收端（以 h2 为例，先启动）：

```text
mininet> h2 sh -c 'python3 receive-poly.py --timeout 10 --expect 1 > /tmp/h2-poly.log 2>&1 &'
```

发送端（每发一份原始报文，源网关生成三份模态副本）：

```text
# 正向无故障
mininet> h1 python3 send-poly.py 10.0.2.2 class3-ok
# 反向无故障（先启动 h1 接收，再由 h2 发送）
mininet> h1 python3 send-poly.py 10.0.1.1 reverse-one
```

预期接收端日志出现 `POLY_SUMMARY received=1 expected=1`。

故障场景需在 clean 状态下用带 `--fault` 的控制器启动（每换一次故障设置需退出 Mininet、`make stop`、`make clean` 后重来）：

| 场景 | 控制器命令 | 预期 |
| --- | --- | --- |
| 单模态篡改 | `python3 mycontroller.py --fault corrupt:1:1:0x1` | 主机仍收到原文一份，mode1 bad=1，mode2/3 good=1 |
| 单模态丢包 | `python3 mycontroller.py --fault drop:2:1` | 主机收到一份，mode1/3 good=1，mode2 无事件 |
| 无多数 | 三条 `--fault corrupt:1:1:0x1` / `corrupt:2:1:0x2` / `corrupt:3:1:0x4` | 接收端 `--expect 0` 时 received=0，no_majority=1 |

读取裁决统计并生成三模态健康报告：

```bash
python3 read-counters.py
python3 read-counters.py | python3 evaluate-counters.py
```

基线功能回归（控制器下发表项后）：

```text
mininet> pingall                                    # IPv4：0% dropped
mininet> py h1.cmd('ping6 -c 3 fe80::5678%eth0')    # IPv6：0% packet loss
mininet> py h2.cmd('ping6 -c 3 fe80::1234%eth0')
mininet> xterm h1 h2                                # 原始 SR 演示：receive.py / send-sr.py
```

## 7. 已知限制

- **固定 payload**：实验采用 UDP 方案，受保护数据固定为 16 字节（`protected_data` 为 bit<128>），收发脚本将 UTF-8 消息左补零到 16 字节；消息超过 16 字节无法发送。
- **CRC32 不是密码学 MAC**：观察 CRC 用 CRC32（bmv2 `HashAlgorithm.crc32`）覆盖内层 IPv4 源/目的地址、协议号、UDP 源/目的端口与 16 字节数据。两个模态对同一份数据产生**相同错误**时 2/3 多数无法察觉；恶意构造碰撞不在本实验威胁模型内。
- **状态窗口**：裁决状态用 1024 个 slot，`slot = sequence_number & 0x3FF`，序号间隔 1024 的包会复用同一 slot；`seq_tag` 仅在新序号到达时重置全部候选状态，故两个序号恰好相差 1024 且前一组尚未完成裁决时会互相污染。测试场景每场只发一个包，不受影响。
- **假设单序号至多一个模态出错**：无多数场景（三份各不相同）按设计不输出，属预期行为而非系统故障。
- **故障定位依赖序号**：故障表按（模态, 序号）精确匹配，序号从 1 开始由源网关的 `sequence_counter` 生成；多包并发时需按实际序号构造故障参数。
- **单包裁决输出**：多数形成时输出"当前"副本还原后的报文；首个到达副本（即使内容正确）因尚未形成多数会被丢弃，这是顺序无关 2/3 裁决的固有行为。

## 8. 清理

```text
mininet> exit
make stop
make clean
```

`make stop` 清理残留的 Mininet/BMv2 进程，`make clean` 删除可重新生成的 `build/`、`pcaps/`、`logs/`。

## 主要文件

| 文件 | 说明 |
| --- | --- |
| `polymorphic.p4` | P4 数据面：PolyShim 封装/解析、源网关调度与组播、目的网关裁决与透明还原、故障注入表 |
| `mycontroller.py` | P4Runtime 控制器：转发表、调度规则、网关角色、`--fault` 故障注入 |
| `topo/topology.json` | 10 交换机 2 主机拓扑，含主机 IPv6 链路本地地址与静态邻居配置 |
| `utils/` | 适配版工具包（`p4_mininet.py` 已启用 IPv6；`run_exercise.py`、`p4runtime_lib` 等） |
| `run-poly-tests.py` | 五个验收场景的自动测试 |
| `send-poly.py` / `receive-poly.py` | UDP/5000、固定 16 字节的实验收发脚本 |
| `read-counters.py` / `evaluate-counters.py` | 裁决计数器读取与三模态健康报告 |
| `adjudication_model.py` | 可执行的 Python 2/3 裁决状态机参考模型 |
| `check-submission.sh` | 提交完整性自检 |
| `send.py` / `receive.py` / `send-sr.py` | 基线演示（IPv4/IPv6/SR）收发工具 |
