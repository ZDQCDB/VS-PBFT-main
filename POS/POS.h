#ifndef NODE_APP_H
#define NODE_APP_H

#include <algorithm>
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/boolean.h"
#include "ns3/socket.h"
#include "ns3/nstime.h" // 添加Time类定义
#include <map>
#include <vector>
#include <array>

namespace ns3 {

class Address;
class Socket;
class Packet;

// 将PBFT共识阶段枚举修改为POS共识阶段枚举
enum POSPhase {
    STAKE_ANNOUNCE,    // 0 权益公布阶段
    BLOCK_PROPOSE,     // 1 区块提议阶段
    BLOCK_VALIDATE,    // 2 区块验证阶段
    BLOCK_COMMIT,      // 3 区块提交阶段
    ROUND_COMPLETE     // 4 轮次完成
};

// 定义区块结构体
struct Block {
    uint32_t round;              // 轮次
    uint32_t producer;           // 生产者ID
    Time timestamp;              // 时间戳
    std::vector<std::string> transactions; // 交易列表
};

// 定义交易结构体
struct Transaction {
    int value;                   // 交易值
    bool validated;              // 是否已验证
    Time submitTime;             // 提交时间
    Time confirmTime;            // 确认时间
};

class NodeApp : public Application
{
  public:
    static TypeId GetTypeId (void);

    NodeApp (void);

    virtual ~NodeApp (void);

    uint32_t        m_id;                               // 节点ID
    Ptr<Socket>     m_socket;                           // 监听套接字
    std::map<Ipv4Address, Ptr<Socket>>      m_peersSockets;            // 邻居节点套接字列表
    std::map<Address, std::string>          m_bufferedData;            // 存储之前handleRead事件的缓冲数据
    
    Address         m_local;                            // 本节点地址
    std::vector<Ipv4Address>  m_peersAddresses;         // 邻居列表

    // POS共识相关成员变量
    double m_stake;                                    // 节点持有的权益数量
    std::map<uint32_t, double> m_stakesMap;            // 记录所有节点的权益 
    uint32_t m_totalStake;                             // 系统总权益
    Time m_blockInterval;                              // 出块间隔
    uint32_t m_maxRounds;                              // 最大共识轮次
    std::vector<Block> m_blockchain;                   // 本地区块链
    std::map<Ipv4Address, uint32_t> messageCount;      // 消息计数(用于DoS检测)
    bool m_isValidator;                                // 当前轮次是否为验证者
    
    int             N;                                  // 节点总数
    int             is_leader;                          // 是否为领导者(权益最高的节点)
    int             sec_num;                            // 交易序列号
    uint32_t        round_number;                       // 当前轮次

    // 为兼容network-helper.cc添加的成员变量
    int             leader_id;                          // 领导者ID (兼容原PBFT代码)
    int             client_id;                          // 客户端ID (兼容原PBFT代码)
    int             view_number;                        // 视图编号 (兼容原PBFT代码)

    double          m_reputation = 100.0;               // 节点信誉度

    // 性能统计相关
    Time m_roundStartTime;                              // 当前轮次开始时间
    Time m_roundEndTime;                                // 当前轮次结束时间
    Time m_totalTime;                                   // 所有轮次总时间
    Time m_latencyStartTime;                            // 交易延迟开始时间
    Time m_latencyEndTime;                              // 交易延迟结束时间
    uint32_t m_successfulTxCount;                       // 成功交易数
    uint32_t m_totalTxCount;                            // 总交易数
    std::map<uint32_t, Time> m_txStartTimes;            // 交易开始时间记录
    std::map<uint32_t, Time> m_txEndTimes;              // 交易结束时间记录
    double m_avgLatency;                                // 平均交易时延

    // 添加密钥相关成员变量
    std::array<unsigned char, 32> m_secretKey;          // 节点私钥
    std::array<unsigned char, 32> m_publicKey;          // 节点公钥

    virtual void StartApplication (void);
    virtual void StopApplication (void); 

    void HandleRead (Ptr<Socket> socket);

    std::string getPacketContent(Ptr<Packet> packet, Address from); 

    void SendTX(const std::vector<uint8_t>& data);

    void SendTXWithDelay(uint8_t data[], int size, double delay);

    // POS共识相关方法
    void InitializePos(uint32_t maxRounds, Time blockInterval);
    void StartPosConsensus();
    void RunConsensusRound(uint32_t round);
    bool SelectValidator(uint32_t round);
    void ProduceAndBroadcastBlock(uint32_t round);
    void ConfirmBlock(uint32_t round);
    void BroadcastStakeInfo();
    std::string SerializeBlock(const Block& block);
    void HandleBlockMessage(const std::string& msg);
    void HandleStakeMessage(const std::string& msg);
    //void CalculateMetrics();

    // TPS和时延计算
    void SubmitTransaction(uint32_t transactionId);
    void ConfirmTransaction(uint32_t transactionId);
    double CalculateTPS();
    double CalculateLatency();
};
}
#endif