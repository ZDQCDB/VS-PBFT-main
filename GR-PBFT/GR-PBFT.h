#ifndef NODE_APP_H
#define NODE_APP_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/address.h"
#include "ns3/socket.h"
#include "ns3/boolean.h"
#include <map>
#include <set>
#include <vector>
#include <string>

namespace ns3 {

class Socket;
class Address;

// PBFTPhase：枚举类型
enum PBFTPhase {
    CLIENT_CHANGE,  // 0        客户端变更
    NEW_ROUND,      // 1        新回合
    REQUEST,        // 2        请求
    PRE_PREPARED,   // 3        预准备阶段
    PREPARED,       // 4        准备阶段
    COMMITTED,      // 5        提交阶段
    REPLY,          // 6        回复阶段
    VIEW_CHANGE     // 7        视图变更
};

struct Transaction {
    int view;               //视图编号
    int value;              //交易的值
    int prepare_vote;       //准备阶段的投票数
    int commit_vote;        //提交阶段的投票数
};

//static const uint32_t NETWORK_SIZE = 10;  // network size: num of nodes

class NodeApp : public Application {
public:
    NodeApp (void);
    virtual ~NodeApp (void);

    static TypeId GetTypeId (void);
    uint32_t N; // 可能用于存储节点编号

    // 设置和获取节点相关参数的方法
    void SetPeersAddresses (std::vector<Ipv4Address> peers);
    void SetNodeInternetAddress(Ipv4Address internet);
    void SetNodeId(uint8_t id);
    void SetIsLeader(uint8_t flag);
    void SetLeaderId(uint8_t id);
    void SetClientId(uint8_t id);
    
    Ipv4Address GetNodeInternetAddress() const;
    uint8_t GetNodeId() const;
    uint8_t GetIsLeader() const;
    uint8_t GetClientId() const;

    // Gossip协议相关参数
    void SetGossipFanout(int fanout);
    int GetGossipFanout() const;
    void SetGossipRounds(int rounds);
    int GetGossipRounds() const;

    // 交易相关函数
    void SubmitTransaction(uint32_t transactionId);
    void ConfirmTransaction(uint32_t transactionId);
    double CalculateTPS();
    double CalculateAverageLatency();

    // 其他公共方法
    std::string getPacketContent(Ptr<Packet> packet, Address from);
    void SendTX(uint8_t data[], int num);
    void SendTXWithDelay(unsigned char* data, int size, double delay);
    void SendGossip(unsigned char* data, int size, double delay);
    std::vector<Ipv4Address> SelectGossipPeers();
    bool ShouldRelay(const std::string& messageId);
    void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p);

protected:
    Ipv4Address m_local; // 存储 IP 地址
    virtual void StartApplication (void);
    virtual void StopApplication (void);
    void HandleRead (Ptr<Socket> socket);
    void initiateRound(void);
    void changeView(void);
    void sendStringMessage(std::string data);
    void printInformation();
    char convertIntToChar(int a);
    int convertCharToInt(char a);
    float getRandomDelay();
    void log_message_counts();

public:  // 将需要外部访问的成员变量移到public区域
    uint8_t m_id;
    uint8_t is_leader;
    uint8_t leader_id;
    uint8_t client_id;
    uint8_t view_number;
    uint8_t sec_num;
    std::vector<Ipv4Address> m_peersAddresses;

private:
    Ptr<Socket> m_socket;
    std::map<Ipv4Address, Ptr<Socket> > m_peersSockets;
    std::map<Address, std::string> m_bufferedData;
    Ipv4Address m_nodeInternetAddress;
    std::map<int, Transaction> transactions;
    std::vector<int> ledger;

    // Gossip协议参数
    int m_gossipFanout;
    int m_gossipRounds;
    std::set<std::string> m_processedMessages;

    // 性能统计相关变量
    Time m_roundStartTime;
    Time m_roundEndTime;
    Time m_totalTime;
    Time m_latencyStartTime;
    Time m_latencyEndTime;
    int m_roundMessageCount;
    int m_totalMessageCount;
    int m_messageRelayCount;

    std::vector<Time> m_transactionStartTimes;
    std::vector<Time> m_transactionEndTimes;

    // DOS攻击相关参数
    bool            m_enableDosAttack;                 // 是否启用DOS攻击
    int             m_dosAttackRound;                  // 在哪一轮发起攻击
    int             m_dosAttackCount;                  // 攻击次数
    std::vector<int> m_maliciousNodes;                 // 恶意节点列表
    std::map<int, int> m_receivedAttackCount;          // 记录每个节点收到的攻击消息数量
    bool            m_leaderParalyzed;                 // 主节点是否瘫痪
    bool            m_attackSuccess;                   // 攻击是否成功
    int             m_messageThreshold;                // 消息阈值，超过此值认为节点瘫痪
    Time            m_lastAttackDetectionTime;         // 上次检测到攻击的时间
    int             m_attackDetectionWindow;           // 攻击检测窗口(毫秒)
    int m_sequenceNumber;  // 添加成员变量
    std::map<int, std::string> m_lastReceivedMessage;  // 添加成员变量
    
    // DOS攻击相关函数
    void SetupDosAttack(bool enable, int attackRound, int attackCount, 
                        const std::vector<int>& maliciousNodes, int messageThreshold);
    void LaunchDosAttack(int m_id);
    bool IsMaliciousNode(int nodeId);
    void DetectDosAttack(int attackerId);
    void EvaluateAttackResult();
    void SendDosAttackMessage(int m_id);
    const int DOSID = 5;
};

} // namespace ns3

#endif /* NODE_APP_H */
