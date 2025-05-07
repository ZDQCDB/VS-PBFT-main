# VS-PBFT-NS3 - Blockchain Consensus Protocols Simulation

*English (中文在下方)*

## Project Overview

This project implements and simulates various blockchain consensus protocols using the NS-3 (Network Simulator 3) framework. The simulation allows for the evaluation of different consensus mechanisms under various network conditions and attack scenarios.

## Implemented Consensus Protocols

### 1. PBFT (Practical Byzantine Fault Tolerance)
- Traditional implementation of the PBFT consensus algorithm
- Includes complete message flow: REQUEST → PRE-PREPARE → PREPARE → COMMIT → REPLY
- Implements view changes to handle leader failures
- Features a configurable reputation-based system to evaluate node reliability

### 2. NAC-PBFT (Network Adaptive Consensus PBFT)
- An enhanced version of PBFT that adapts to network conditions
- Monitors network quality and adjusts parameters dynamically
- Implements congestion detection and handling mechanisms
- Includes adaptive message delay calculations

### 3. GR-PBFT (Gossip-based Reputation PBFT)
- Integrates gossip protocol with PBFT for more efficient message propagation
- Uses configurable gossip parameters (fanout, rounds)
- Implements reputation-based message validation
- Offers better scalability for larger networks

### 4. POS (Proof of Stake)
- Implements a stake-based validator selection mechanism
- Includes stake distribution and management
- Validates blocks based on node stake and reputation
- Provides metrics for stake-based consensus efficiency

### 5. POW (Proof of Work)
- Simulates the mining process with configurable difficulty
- Implements block validation and chain management
- Includes a transaction pool for pending transactions
- Handles chain reorganization when longer valid chains are discovered

## Security Features

### DoS Attack Simulation
- Implements configurable DoS (Denial of Service) attack scenarios
- Features attack detection and mitigation mechanisms
- Includes reputation-based penalties for malicious nodes
- Provides detailed attack success metrics and evaluation

### Reputation System
- All protocols incorporate a reputation-based security mechanism
- Nodes gain reputation for successful consensus participation
- Malicious behavior results in reputation penalties
- Nodes with low reputation can be excluded from consensus

## Project Structure

### Source Files (`src` directory)
- `src/applications/model/node-app.h`: Base class header defining the node application with core functionality
- `src/applications/model/node-app.cc`: Base implementation of node application with common functions

### Simulation Files (`scratch` directory)
- `scratch/pbft-simulator.cc`: Main simulation file setting up the network and nodes for PBFT consensus

### Protocol Implementations
- `PBFT/PBFT.cc`: Standard PBFT implementation
- `NAC-PBFT/NNAC-PBFT.cc`: Network Adaptive PBFT implementation
- `GR-PBFT/GR-PBFT.cc`: Gossip-based Reputation PBFT implementation
- `POS/POS.cc`: Proof of Stake implementation
- `POW/POW.cc`: Proof of Work implementation

## Performance Metrics

The simulation collects and calculates various performance metrics:
- Transaction throughput (TPS - Transactions Per Second)
- Average transaction latency
- Message count and communication overhead
- Consensus completion time
- Block/transaction confirmation rates
- Attack success rates (for security evaluations)

## Usage Instructions

### Basic Simulation Setup

1. Configure the simulation parameters:
   - Select the consensus protocol (PBFT, NAC-PBFT, GR-PBFT, POS, POW)
   - Set the number of nodes (N)
   - Configure round count and attack parameters

2. Run the simulation:
   ```bash
   # Example for PBFT simulation
   ./waf --run "PBFT-simulation --nodes=10 --rounds=30"
   ```

3. Enable DoS attack simulation:
   ```bash
   # Example with DoS attack enabled
   ./waf --run "PBFT-simulation --nodes=10 --rounds=30 --enableDoS=true --attackRound=20"
   ```

### Output Analysis

The simulation produces detailed logs with NS_LOG_INFO statements that track:
- Consensus progress and message flows
- Node states and reputation values
- Attack attempts and detection events
- Performance statistics at simulation completion

## Implementation Details

- Built on NS-3 network simulation framework
- Uses UDP sockets for inter-node communication
- Implements a common NodeApp base application for all protocols
- Provides detailed logging of simulation events and statistics
- Supports both normal operation and attack scenarios

## Recent Updates

- This code repository is mainly used to simulate our proposed VS-PBFT consensus algorithm, and the Heart-Disease dataset is used as input data for the experiments. The intelligent medical diagnosis model mentioned in this paper is conceptual and not implemented in this code.

---

# VS-PBFT-NS3 - 区块链共识协议仿真

*中文版*

## 项目概述

本项目使用NS-3（网络模拟器3）框架实现并模拟了多种区块链共识协议。该仿真允许在各种网络条件和攻击场景下评估不同的共识机制。

## 实现的共识协议

### 1. PBFT（实用拜占庭容错）
- 传统PBFT共识算法的实现
- 包含完整的消息流程：REQUEST → PRE-PREPARE → PREPARE → COMMIT → REPLY
- 实现视图变更以处理领导者故障
- 具有可配置的基于信誉的系统来评估节点可靠性

### 2. NAC-PBFT（网络自适应共识PBFT）
- PBFT的增强版本，能够适应网络条件
- 监控网络质量并动态调整参数
- 实现拥塞检测和处理机制
- 包含自适应消息延迟计算

### 3. GR-PBFT（基于Gossip的信誉PBFT）
- 将Gossip协议与PBFT集成，实现更高效的消息传播
- 使用可配置的Gossip参数（扇出数、轮次）
- 实现基于信誉的消息验证
- 为大型网络提供更好的可扩展性

### 4. POS（权益证明）
- 实现基于权益的验证者选择机制
- 包含权益分配和管理
- 基于节点权益和信誉验证区块
- 提供基于权益共识效率的度量指标

### 5. POW（工作量证明）
- 模拟可配置难度的挖矿过程
- 实现区块验证和链管理
- 包含待处理交易的交易池
- 当发现更长的有效链时处理链重组

## 安全特性

### DoS攻击模拟
- 实现可配置的DoS（拒绝服务）攻击场景
- 具有攻击检测和缓解机制
- 包含对恶意节点的基于信誉的惩罚
- 提供详细的攻击成功指标和评估

### 信誉系统
- 所有协议都包含基于信誉的安全机制
- 节点成功参与共识获得信誉
- 恶意行为导致信誉惩罚
- 低信誉节点可能被排除在共识之外

## 项目结构

### 源文件（`src`目录）
- `src/applications/model/node-app.h`：定义节点应用程序核心功能的基类头文件
- `src/applications/model/node-app.cc`：包含通用函数的节点应用程序基本实现

### 仿真文件（`scratch`目录）
- `scratch/pbft-simulator.cc`：设置PBFT共识网络和节点的主要仿真文件

### 协议实现
- `PBFT/PBFT.cc`：标准PBFT实现
- `NAC-PBFT/NNAC-PBFT.cc`：网络自适应PBFT实现
- `GR-PBFT/GR-PBFT.cc`：基于Gossip的信誉PBFT实现
- `POS/POS.cc`：权益证明实现
- `POW/POW.cc`：工作量证明实现

## 性能指标

仿真收集并计算各种性能指标：
- 交易吞吐量（TPS - 每秒交易数）
- 平均交易延迟
- 消息数量和通信开销
- 共识完成时间
- 区块/交易确认率
- 攻击成功率（用于安全评估）

## 使用说明

### 基本仿真设置

1. 配置仿真参数：
   - 选择共识协议（PBFT、NAC-PBFT、GR-PBFT、POS、POW）
   - 设置节点数量（N）
   - 配置轮次计数和攻击参数

2. 运行仿真：
   ```bash
   # PBFT仿真示例
   ./waf --run "PBFT-simulation --nodes=10 --rounds=30"
   ```

3. 启用DoS攻击仿真：
   ```bash
   # 启用DoS攻击的示例
   ./waf --run "PBFT-simulation --nodes=10 --rounds=30 --enableDoS=true --attackRound=20"
   ```

### 输出分析

仿真产生详细的日志，包含NS_LOG_INFO语句，用于跟踪：
- 共识进度和消息流
- 节点状态和信誉值
- 攻击尝试和检测事件
- 仿真完成时的性能统计

## 实现细节

- 基于NS-3网络仿真框架构建
- 使用UDP套接字进行节点间通信
- 为所有协议实现通用的NodeApp基础应用
- 提供仿真事件和统计的详细日志记录
- 支持正常操作和攻击场景

## 最近更新
本代码仓库主要用于仿真我们提出的VS-PBFT共识算法，实验使用了Heart-Disease数据集作为输入数据。本文中提到的智能医疗诊断模型为概念性设计，未在本代码中实现。
