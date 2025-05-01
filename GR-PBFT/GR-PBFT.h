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

// PBFTPhase: Enumeration type
enum PBFTPhase {
    CLIENT_CHANGE,  // 0        Client change
    NEW_ROUND,      // 1        New round
    REQUEST,        // 2        Request
    PRE_PREPARED,   // 3        Pre-prepared phase
    PREPARED,       // 4        Prepared phase
    COMMITTED,      // 5        Committed phase
    REPLY,          // 6        Reply phase
    VIEW_CHANGE     // 7        View change
};

struct Transaction {
    int view;               // View number
    int value;              // Transaction value
    int prepare_vote;       // Number of votes in the prepared phase
    int commit_vote;        // Number of votes in the committed phase
};

// static const uint32_t NETWORK_SIZE = 10;  // network size: num of nodes
// 心脏病数据结构
struct HeartData {
    int age;
    int sex;
    int cp;
    int trestbps;
    int chol;
    int target;  // 诊断结果
    std::string toString() {
        return std::to_string(age) + "," + 
               std::to_string(sex) + "," + 
               std::to_string(cp) + "," + 
               std::to_string(trestbps) + "," + 
               std::to_string(chol) + ":" + 
               std::to_string(target);
    }
};

class NodeApp : public Application {
public:
    NodeApp (void);
    virtual ~NodeApp (void);
    void LoadHeartDataset(const std::string& filePath);

    static TypeId GetTypeId (void);
    uint32_t N; // Possibly used to store node ID

    // Methods to set and get node-related parameters
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

    // Gossip protocol related parameters
    void SetGossipFanout(int fanout);
    int GetGossipFanout() const;
    void SetGossipRounds(int rounds);
    int GetGossipRounds() const;

    // Transaction-related functions
    void SubmitTransaction(uint32_t transactionId);
    void ConfirmTransaction(uint32_t transactionId);
    double CalculateTPS();
    double CalculateAverageLatency();

    // Other public methods
    std::string getPacketContent(Ptr<Packet> packet, Address from);
    void SendTX(uint8_t data[], int num);
    void SendTXWithDelay(unsigned char* data, int size, double delay);
    void SendGossip(unsigned char* data, int size, double delay);
    std::vector<Ipv4Address> SelectGossipPeers();
    bool ShouldRelay(const std::string& messageId);
    void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p);

protected:
    Ipv4Address m_local; // Store IP address
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

public:  // Move member variables that need external access to the public section
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

    // Gossip protocol parameters
    int m_gossipFanout;
    int m_gossipRounds;
    std::set<std::string> m_processedMessages;

    // Performance statistics related variables
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

    // DOS attack related parameters
    bool            m_enableDosAttack;                 // Whether DOS attack is enabled
    int             m_dosAttackRound;                  // The round in which the attack is launched
    int             m_dosAttackCount;                  // Number of attack attempts
    std::vector<int> m_maliciousNodes;                 // List of malicious nodes
    std::map<int, int> m_receivedAttackCount;          // Record the number of attack messages received by each node
    bool            m_leaderParalyzed;                 // Whether the leader node is paralyzed
    bool            m_attackSuccess;                   // Whether the attack was successful
    int             m_messageThreshold;                // Message threshold; exceeding this value indicates node paralysis
    Time            m_lastAttackDetectionTime;         // Last detected attack time
    int             m_attackDetectionWindow;           // Attack detection window (milliseconds)
    int m_sequenceNumber;  // Added member variable
    std::map<int, std::string> m_lastReceivedMessage;  // Added member variable
    
    // DOS attack related functions
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