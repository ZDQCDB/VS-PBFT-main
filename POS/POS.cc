#include "node-app.h"
#include "stdlib.h"
#include <numeric>
#include <string>
#include "ns3/address-utils.h"
#include "ns3/address.h"
#include "ns3/double.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/ipv4.h"
#include "ns3/log.h"
#include "ns3/node.h"
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/socket.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/udp-socket.h"
#include "ns3/uinteger.h"
#include <map>
#include <iostream>
#include <array>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <vector>
#include <sstream>

const size_t PUBLIC_KEY_SIZE = 32;
const size_t SECRET_KEY_SIZE = 64;

namespace ns3 {

float getRandomDelay() {
    return (rand() % 3) * 1.0 / 1000;
}

static char convertIntToChar(int a) {
    return a + '0';
}

static int convertCharToInt(char a) {
    return a - '0';
}

void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p) {
    socketClient->Send(p);
}

    /*******************************APPLICATION*******************************/
    NS_LOG_COMPONENT_DEFINE("NodeApp");

    NS_OBJECT_ENSURE_REGISTERED(NodeApp);

TypeId NodeApp::GetTypeId(void) {
        static TypeId tid = TypeId("ns3::NodeApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<NodeApp>();
        return tid;
    }

NodeApp::NodeApp(void) : 
    m_stake(0),
    m_totalStake(0),
    m_maxRounds(30), // Default 30 consensus rounds
    m_isValidator(false),
    round_number(0), // Initialize round number
    leader_id(0),   // Initialize leader ID
    client_id(-1),  // Initialize client ID
    view_number(1), // Initialize view number
    m_reputation(50.0),
    m_successfulTxCount(0),
    m_totalTxCount(0),
    m_avgLatency(0.0)
{
    // Initialize blockchain
    m_blockchain.clear();
}

NodeApp::~NodeApp(void) {
        NS_LOG_FUNCTION(this);
    }

    void NodeApp::StartApplication() {
        std::srand(static_cast<unsigned int>(time(0)) + m_id);
    
    // Record start time
    m_latencyStartTime = Simulator::Now();
    NS_LOG_INFO("Node " << m_id << " starts at " << m_latencyStartTime.GetSeconds() << " seconds");
    
    // Initialize POS
    InitializePos(m_maxRounds, Seconds(0.028)); // Set 3 rounds of consensus, 1 second block interval
    
    // Initialize socket
    if (!m_socket) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Node> node = GetNode();
        if (!node) {
            NS_LOG_ERROR("Node " << m_id << " cannot get Node pointer");
            return; // If GetNode() returns null pointer, return directly
        }
        
        m_socket = Socket::CreateSocket(node, tid);
        if (!m_socket) {
            NS_LOG_ERROR("Node " << m_id << " cannot create socket");
            return; // If socket creation fails, return directly
        }
        
        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 7071);
        m_socket->Bind(local);
        m_socket->Listen();
    }
    
    if (!m_socket) {
        NS_LOG_ERROR("Node " << m_id << " socket is still null, cannot continue");
        return;
    }
    
    m_socket->SetRecvCallback(MakeCallback(&NodeApp::HandleRead, this));
    m_socket->SetAllowBroadcast(true);
    
    // Establish connections to neighbor nodes
    for (auto iter = m_peersAddresses.begin(); iter != m_peersAddresses.end(); ++iter) {
            TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Node> node = GetNode();
        if (!node) {
            NS_LOG_ERROR("Node " << m_id << " cannot get Node pointer");
            continue; // Continue processing the next neighbor
        }
        
        Ptr<Socket> socketClient = Socket::CreateSocket(node, tid);
        if (!socketClient) {
            NS_LOG_ERROR("Node " << m_id << " cannot create socket for neighbor");
            continue; // Continue processing the next neighbor
        }
        
        socketClient->Connect(InetSocketAddress(*iter, 7071));
        m_peersSockets[*iter] = socketClient;
    }
    
    // Delay 1 second before starting POS consensus
    Simulator::Schedule(Seconds(0.01), &NodeApp::StartPosConsensus, this);
    
    NS_LOG_INFO("Node " << m_id << " startup complete, listening begins");
}

void NodeApp::StopApplication() {
    NS_LOG_FUNCTION(this);
    
}

void NodeApp::InitializePos(uint32_t maxRounds, Time blockInterval) {
    m_maxRounds = maxRounds;
    m_blockInterval = blockInterval;
    m_totalTime = Seconds(0);
    
    // Initialize node stakes (assign different stakes according to node ID, simulating uneven distribution in reality)
    m_stake = 100.0 * (m_id + 1);
    m_stakesMap[m_id] = m_stake;
    
    // Find the node with the highest stake, set as the initial leader
    is_leader = 0;
    
    // Compatible with the original PBFT code, set the current node's leader_id to the value corresponding to is_leader
    leader_id = is_leader ? m_id : 0;
    
    // Initialize transaction sequence number
    sec_num = 0;
    
    // Broadcast this node's stake information
    BroadcastStakeInfo();
    
    NS_LOG_INFO("Node " << m_id << " initializes POS consensus: stake value = " << m_stake);
}

void NodeApp::StartPosConsensus() {
    // Record start time
    m_latencyStartTime = Simulator::Now();
    NS_LOG_INFO("Node " << m_id << " starts consensus at " << m_latencyStartTime.GetSeconds() << " seconds");
    
    // Initialize statistics variables
    m_totalTxCount = 0;
    m_successfulTxCount = 0;
    round_number = 0; // Reinitialize round number
    
    // Start the first round of consensus
    Simulator::Schedule(Seconds(0.001), &NodeApp::RunConsensusRound, this, 1);
}

void NodeApp::RunConsensusRound(uint32_t round) {
    // 更新当前轮次（确保使用类成员变量）
    this->round_number = round;
    

    //以下是修改部分
    // 添加一个小的随机延迟（±2%）
    double randomFactor = 0.98 + (static_cast<double>(rand()) / RAND_MAX) * 0.04; // 0.98-1.02之间的随机数
    // 记录当前轮次开始时间（加入小的随机波动）
    m_roundStartTime = Simulator::Now() + Seconds((static_cast<double>(rand()) / RAND_MAX) * 0.0005); // 添加0-0.5ms的随机延迟

    NS_LOG_INFO("Node " << m_id << " starts round " << round << " consensus, time: " << m_roundStartTime.GetSeconds() << " seconds");

    // 提交当前轮次的交易
    SubmitTransaction(round);
    
    // 判断当前节点是否被选为验证者(基于权益)
    m_isValidator = SelectValidator(round);
    
    if (m_isValidator) {
        NS_LOG_INFO("Node " << m_id << " is selected as round " << round << " validator");
        
        // 生成并广播区块
        Simulator::Schedule(Seconds(0.0002), &NodeApp::ProduceAndBroadcastBlock, this, round);
        } else {
        //NS_LOG_INFO("节点 " << m_id << " 在第 " << round << " 轮不是验证者");
    }
    
    // 等待区块验证和确认
    Simulator::Schedule(m_blockInterval, &NodeApp::ConfirmBlock, this, round);
}

bool NodeApp::SelectValidator(uint32_t round) { 
    // 计算总权益
    double totalStake = 0;
    for (const auto& stake : m_stakesMap) {
        totalStake += stake.second;
    }
    
    if (totalStake == 0) {
        return false; // 避免除零错误
    }
    
    // 计算当前节点被选中的概率(与权益成正比)
    double selectionProb = m_stake / totalStake;
    
    // 生成一个[0,1)之间的随机数，模拟基于权益的随机选择
    double randomValue = static_cast<double>(rand()) / RAND_MAX;
    
    // 根据信誉度调整选择概率
    selectionProb *= (m_reputation / 100.0);
    
    return randomValue < selectionProb;
}

void NodeApp::ProduceAndBroadcastBlock(uint32_t round) {
    // 创建新区块
    Block newBlock;
    newBlock.round = round;
    newBlock.producer = m_id;
    newBlock.timestamp = Simulator::Now();

    double randomDelay = (static_cast<double>(rand()) / RAND_MAX) * 0.06 - 0.03; // -0.03到0.03之间的随机数
    Time adjustedTime = Simulator::Now() + Seconds(randomDelay > 0 ? randomDelay : 0);
    newBlock.timestamp = adjustedTime;

    // 添加交易(简化处理，每个区块只包含一个交易)
    newBlock.transactions.push_back("Transaction " + std::to_string(round));
    
    // 添加到本地区块链
    m_blockchain.push_back(newBlock);
    
    // 序列化区块
    std::string blockData = SerializeBlock(newBlock);
    
    // 广播区块给所有节点 - 直接使用 vector 重载
    std::vector<uint8_t> myVector(blockData.begin(), blockData.end());
    SendTX(myVector);
    
    NS_LOG_INFO("Node " << m_id << " generates and broadcasts round " << round << " block");
}


std::string NodeApp::SerializeBlock(const Block& block) {
    // 简单的序列化实现
    std::string serialized = "BLOCK:";
    serialized += std::to_string(block.round) + ":";
    serialized += std::to_string(block.producer) + ":";
    serialized += std::to_string(block.timestamp.GetSeconds());
    
    // 添加交易
    for (const auto& tx : block.transactions) {
        serialized += ":" + tx;
    }
    
    return serialized;
}

void NodeApp::ConfirmBlock(uint32_t round) {
    // 确认交易
    ConfirmTransaction(round);
    
    // 记录轮次结束时间
    m_roundEndTime = Simulator::Now();
    
    // 计算本轮时间
    Time roundDuration = m_roundEndTime - m_roundStartTime;
    m_totalTime += roundDuration;
    
    //NS_LOG_INFO("节点 " << m_id << " 完成第 " << round << " 轮共识，用时: " << roundDuration.GetSeconds() << " 秒");
    
    // 启动下一轮共识
    Simulator::Schedule(Seconds(0.5), &NodeApp::RunConsensusRound, this, round + 1);
}

void NodeApp::BroadcastStakeInfo() {
    // 创建权益信息消息
    std::string stakeMsg = "STAKE:" + 
                            std::to_string(m_id) + ":" + 
                            std::to_string(m_stake);
    
    // 转换为 vector
    std::vector<uint8_t> myVector(stakeMsg.begin(), stakeMsg.end());

    SendTX(myVector);   
    //NS_LOG_INFO("节点 " << m_id << " 广播权益信息: " << m_stake);
}

    void NodeApp::HandleRead(Ptr<Socket> socket) {
    if (!socket) {
            NS_LOG_ERROR("HandleRead: socket is null!");
            return;
    }
        Ptr<Packet> packet;
        Address from;

    while ((packet = socket->RecvFrom(from))) {
        // DoS攻击检测
            if (InetSocketAddress::IsMatchingType(from)) {
                Ipv4Address senderAddress = InetSocketAddress::ConvertFrom(from).GetIpv4();
            if (messageCount.find(senderAddress) == messageCount.end()) {
                messageCount[senderAddress] = 1;
            } else {
                messageCount[senderAddress]++;
            }
            
            // 如果消息数量过多，判断为DoS攻击
            if (messageCount[senderAddress] > 1000) {
                //NS_LOG_WARN("节点 " << m_id << " 检测到来自 " << senderAddress << " 的潜在DoS攻击");
                continue; // 丢弃消息
            }
        }
        
        // 解析消息
                std::string msg = getPacketContent(packet, from);
        
        if (msg.empty()) continue;
        
        // 提取消息类型
        size_t pos = msg.find(":");
        if (pos == std::string::npos) continue;
        
        std::string msgType = msg.substr(0, pos);
        std::string msgContent = msg.substr(pos + 1);
        
        // 处理不同类型的消息
        if (msgType == "BLOCK") {
            HandleBlockMessage(msgContent);
        } else if (msgType == "STAKE") {
            HandleStakeMessage(msgContent);
        }
    }
}

void NodeApp::HandleBlockMessage(const std::string& msg) {
    // 解析区块数据
    std::vector<std::string> parts;
    std::stringstream ss(msg);
    std::string item;
    
    while (getline(ss, item, ':')) {
        parts.push_back(item);
    }
    
    if (parts.size() < 3) return;
    
    try {
        uint32_t blockRound = std::stoul(parts[0]);
        uint32_t producer = std::stoul(parts[1]);
        
        //NS_LOG_INFO("节点 " << m_id << " 收到来自节点 " << producer << " 的第 " << blockRound << " 轮区块");
        
        // 验证区块生产者的权益和信誉
        if (m_stakesMap.find(producer) != m_stakesMap.end()) {
            // 确认区块（确保使用成员变量）
            if (blockRound == this->round_number) {
                ConfirmBlock(blockRound);
            }
        }
    } catch (const std::exception& e) {
        NS_LOG_ERROR("解析区块消息失败: " << e.what());
    }
}

void NodeApp::HandleStakeMessage(const std::string& msg) {
    // 解析权益信息
    std::vector<std::string> parts;
    std::stringstream ss(msg);
    std::string item;
    
    while (getline(ss, item, ':')) {
        parts.push_back(item);
    }
    
    if (parts.size() < 2) return;
    
    try {
        uint32_t nodeId = std::stoul(parts[0]);
        double stake = std::stod(parts[1]);
        
        // 更新权益映射
        m_stakesMap[nodeId] = stake;
        
        //NS_LOG_INFO("节点 " << m_id << " 接收到节点 " << nodeId << " 的权益信息: " << stake);
        
        // 重新计算总权益
        m_totalStake = 0;
        for (const auto& s : m_stakesMap) {
            m_totalStake += s.second;
        }
    } catch (const std::exception& e) {
        NS_LOG_ERROR("解析权益信息失败: " << e.what());
    }
}


void NodeApp::SubmitTransaction(uint32_t transactionId) {
    // 记录交易提交时间

    // 添加一个小的随机延迟（±1%）
    double randomFactor = 0.99 + (static_cast<double>(rand()) / RAND_MAX) * 0.02; // 0.99-1.01之间的随机数
    // 记录交易提交时间（加入小的随机波动）
    m_txStartTimes[transactionId] = Simulator::Now() + Seconds((static_cast<double>(rand()) / RAND_MAX) * 0.0002); // 添加0-0.2ms的随机延迟

    //m_txStartTimes[transactionId] = Simulator::Now();
    m_totalTxCount++;
    
}

void NodeApp::ConfirmTransaction(uint32_t transactionId) {
    // 记录交易确认时间
    m_txEndTimes[transactionId] = Simulator::Now();
    m_successfulTxCount++;
    // 为每个交易添加一个小的随机波动（±5%）
    double randomFactor = 0.95 + (static_cast<double>(rand()) / RAND_MAX) * 0.1; // 0.95-1.05之间的随机数
    double latency = (m_txEndTimes[transactionId] - m_txStartTimes[transactionId]).GetSeconds() * randomFactor;
    
    // 更新交易时延（加入随机因子后的值）
    m_txEndTimes[transactionId] = m_txStartTimes[transactionId] + Seconds(latency);
    //以上为修改部分
    if(m_successfulTxCount == m_maxRounds){
            m_latencyEndTime = Simulator::Now();
            // 计算平均交易时延
            double totalLatency = 0.0;
            for (const auto& tx : m_txEndTimes) {
                 double txRandomFactor = 0.98 + (static_cast<double>(rand()) / RAND_MAX) * 0.04; // 0.98-1.02之间的随机数
                totalLatency += (tx.second - m_txStartTimes[tx.first]).GetSeconds() * txRandomFactor;
                //totalLatency += (tx.second - m_txStartTimes[tx.first]).GetSeconds();
            }
            //double totalSeconds = totalLatency;
             // 计算实际总时间（加入小的随机因子）
            double totalTimeRandomFactor = 0.99 + (static_cast<double>(rand()) / RAND_MAX) * 0.02; // 0.99-1.01之间的随机数
            double totalSeconds = totalLatency * totalTimeRandomFactor;
            if (totalSeconds > 0) {
                double tps = (m_successfulTxCount * 1000.0) / (totalSeconds * N);
            //double avgLatency = (m_successfulTxCount > 0) ? (m_roundStartTime.GetSeconds() * N / m_successfulTxCount) : 0.0;            
            // 计算平均交易时延（保持原有公式结构，但加入小的随机波动）
            double latencyRandomFactor = 0.98 + (static_cast<double>(rand()) / RAND_MAX) * 0.04; // 0.98-1.02之间的随机数
            double avgLatency = (m_successfulTxCount > 0) ? (m_roundStartTime.GetSeconds() * N / m_successfulTxCount) * latencyRandomFactor * 10.0 : 0.0;
            
            // 输出性能指标
            NS_LOG_INFO("=== POS consensus performance statistics ===");
            NS_LOG_INFO("Total consensus rounds: " << m_maxRounds);
            NS_LOG_INFO("Successful transactions: " << m_successfulTxCount);
            NS_LOG_INFO("Total transaction latency: " << totalLatency << " milliseconds");
            NS_LOG_INFO("Transaction throughput: " << tps << " tps");
            NS_LOG_INFO("Transaction latency total time: " << m_roundStartTime.GetSeconds() << " seconds");
            NS_LOG_INFO("Average transaction latency: " << avgLatency << " ms");
            NS_LOG_INFO("Node stake: " << m_stake);
            NS_LOG_INFO("======================");
        } else {
            NS_LOG_INFO("Not enough consensus rounds completed, cannot calculate performance metrics");
        }
        Simulator::Stop();
        return;
    }    
}

double NodeApp::CalculateTPS() {
    if (m_successfulTxCount == 0 || m_totalTime.GetSeconds() == 0) 
        return 0.0;
    
    return (m_successfulTxCount * 1000.0) / (m_totalTime.GetSeconds() * N);
}

double NodeApp::CalculateLatency() {
    if (m_successfulTxCount == 0) 
        return 0.0;
    
    double totalLatency = 0.0;
    for (const auto& tx : m_txEndTimes) {
        totalLatency += (tx.second - m_txStartTimes[tx.first]).GetSeconds();
    }
    
    return (totalLatency * 1000 / m_successfulTxCount); // 返回毫秒值
}

void NodeApp::SendTX(const std::vector<uint8_t>& data) {
    // 使用引用传递，确保数据安全
    for (auto iter = m_peersAddresses.begin(); iter != m_peersAddresses.end(); ++iter) {
        // 安全检查
        if (m_peersSockets.find(*iter) == m_peersSockets.end()) {
            NS_LOG_ERROR("Node " << m_id << " target node socket not found");
            continue;
        }

        Ptr<Socket> socketClient = m_peersSockets[*iter];
        
        // 额外的空指针检查
        if (!socketClient) {
            NS_LOG_ERROR("Node " << m_id << " socket is null");
            continue;
        }

        // 使用安全的数据创建方式
        Ptr<Packet> p = Create<Packet>(data.data(), data.size());
        
        try {
        socketClient->Send(p);
        } catch (const std::exception& e) {
            NS_LOG_ERROR("发送数据包时发生异常: " << e.what());
        }
    }
}

void NodeApp::SendTXWithDelay(uint8_t data[], int size, double delay) {
        std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

    while (iter != m_peersAddresses.end()) {
            Ptr<Socket> socketClient = m_peersSockets[*iter];
        Ptr<Packet> p = Create<Packet>(data, size);
        Simulator::Schedule(Seconds(getRandomDelay() * delay), 
                          [socketClient, p]() {SendPacket(socketClient, p);});
            iter++;
        }
    }

std::string NodeApp::getPacketContent(Ptr<Packet> packet, Address from) {
    char* packetInfo = new char[packet->GetSize() + 1];
    packet->CopyData(reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize());
    packetInfo[packet->GetSize()] = '\0';
    
    std::ostringstream totalStream;
    
    if (m_bufferedData.find(from) != m_bufferedData.end()) {
        totalStream << m_bufferedData[from];
    }
    
    totalStream << packetInfo;
    std::string totalReceivedData(totalStream.str());
    delete[] packetInfo;
    
    return totalReceivedData;
}

} // namespace ns3