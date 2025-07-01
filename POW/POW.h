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
#include <map>
#include <vector>
#include <string>
#include <openssl/sha.h>

namespace ns3 {

class Address;
class Socket;
class Packet;

enum POWPhase {
    NEW_BLOCK,         // 0 新区块广播
    BLOCK_REQUEST,     // 1 请求区块
    BLOCK_RESPONSE,    // 2 区块响应
    NEW_TX,            // 3 新交易广播
    CHAIN_REQUEST,     // 4 请求整条链
    CHAIN_RESPONSE     // 5 响应整条链
};

// 区块结构
struct Block {
    int index;                 // 区块高度
    std::string prevHash;      // 前一个区块的哈希
    int timestamp;             // 时间戳
    int nonce;                 // 工作量证明中的随机数
    std::string data;          // 区块数据
    std::string hash;          // 区块哈希
};

// 交易结构
struct Transaction {
    int id;                    // 交易ID
    int timestamp;             // 时间戳
    std::string data;          // 交易数据
    std::string hash;          // 交易哈希
};

class NodeApp : public Application {
public:
    static TypeId GetTypeId(void);
    NodeApp(void);
    virtual ~NodeApp(void);
    
    bool is_leader;
    int leader_id;
    int view_number;
    int client_id;
    int sec_num;
    uint32_t m_id;                                 // 节点ID
    Ptr<Socket> m_socket;                          // 监听套接字
    std::map<Ipv4Address, Ptr<Socket>> m_peersSockets;  // 邻居节点套接字列表
    std::map<Address, std::string> m_bufferedData; // 缓冲数据
    std::vector<Ipv4Address> m_peersAddresses;     // 邻居列表
    
    int N;                                         // 总节点数
    int round_number;                              // 共识轮数计数器
    int difficulty;                                // 挖矿难度
    
    std::vector<Block> blockchain;                 // 区块链
    std::vector<Transaction> pendingTransactions;  // 待处理交易池
    
    Time round_start_time;
    Time round_end_time;
    Time total_time;
    Time latency_start_time;
    Time latency_end_time;
    int round_message_count;
    int total_message_count;
    int message_copies_count;
    
    bool mining;
    EventId miningEvent;
    int minedBlocks;
    int receivedBlocks;

    virtual void StartApplication(void);
    virtual void StopApplication(void);

    void HandleRead(Ptr<Socket> socket);
    std::string getPacketContent(Ptr<Packet> packet, Address from);
    void SendTX(uint8_t data[], int num);
    void SendTXWithDelay(uint8_t data[], int size, double delay);
    void sendStringMessage(std::string data);

    void StartMining();                            // 开始挖矿
    void StopMining();                             // 停止挖矿
    void MineBlock();                              // 挖矿主函数
    void GenerateTransaction();                    // 生成新交易
    bool VerifyBlock(const Block& block);          // 验证区块
    void AddBlock(const Block& block);             // 添加区块
    void ProcessNewTransaction(const Transaction& tx); // 处理新交易
    
    // 区块链管理
    void createGenesisBlock();                     // 创建创世区块
    std::string calculateBlockHash(int index, std::string prevHash, int timestamp, int nonce, std::string data); // 计算区块哈希
    std::string calculateTxHash(const Transaction& tx); // 计算交易哈希
    bool isValidProof(std::string hash);           // 验证工作量证明
    
    // 区块链通信
    void BroadcastNewBlock(const Block& block);            // 广播新区块
    void BroadcastNewTransaction(const Transaction& tx);   // 广播新交易
    void RequestFullChain();                               // 请求完整区块链
    void HandleBlockchain(std::vector<Block> receivedChain); // 处理接收的区块链
    
    void initiateRound();
    void printInformation();
    void PrintStatistics();

    // Network related
    void SetPeersAddresses(std::vector<Ipv4Address> peers);
    void SetNodeId(uint32_t id);
    void SetPeerId(uint32_t id);

    bool ResolveConflicts();
    std::string CalculateHash(const Block& block);
    std::string CalculateTransactionHash(const Transaction& tx);

    uint32_t m_peerId;
    
    bool m_mining;
    EventId m_miningEvent;
    
    std::vector<Block> m_blockchain;
    std::vector<Transaction> m_pendingTransactions;
    
    int m_difficulty;
    int a=300;
    int m_minedBlocks;
    int m_receivedBlocks;
    int m_processedTxs;
    Time m_startTime;
    Time m_lastBlockTime;
    
};

} // namespace ns3

#endif /* NODE_APP_H */
