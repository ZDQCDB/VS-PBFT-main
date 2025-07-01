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

namespace ns3 {

class Address;
class Socket;
class Packet;

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

enum NetworkState {
    GOOD,           // 0        Good network state
    NORMAL,         // 1        Normal network state
    CONGESTED       // 2        Congested network state
};

struct Transaction {
    int view;               // View number
    int value;              // Transaction value
    int prepare_vote;       // Number of votes in the prepared phase
    int commit_vote;        // Number of votes in the committed phase
};
struct HeartData {
    int age;
    int sex;
    int cp;
    int trestbps;
    int chol;
    int target;
    std::string toString() {
        return std::to_string(age) + "," + 
               std::to_string(sex) + "," + 
               std::to_string(cp) + "," + 
               std::to_string(trestbps) + "," + 
               std::to_string(chol) + ":" + 
               std::to_string(target);
    }
};

class NodeApp : public Application
{
  public:
    static TypeId GetTypeId (void);

    NodeApp (void);

    virtual ~NodeApp (void);
    void LoadHeartDataset(const std::string& filePath);

    uint32_t        m_id;                               // Node ID
    Ptr<Socket>     m_socket;                           // Listening socket
    std::map<Ipv4Address, Ptr<Socket>>      m_peersSockets;            // Socket list of neighbor nodes
    std::map<Address, std::string>          m_bufferedData;            // Map holding the buffered data from previous handleRead events
    
    Address         m_local;                            // Address of this node
    std::vector<Ipv4Address>  m_peersAddresses;         // Neighbor list

    std::vector<char> ledger;                           // Ledger
    
    int             N;                                  // Total number of nodes
    int             is_leader;                          // Is leader
    int             sec_num;                            // Transaction sequence number
    int             view_number;                        // View node ID

    int             leader_id;                          // Leader ID
    int             client_id;                          // Client ID

    static const int arraySize = 100;                    // Control total transactions
    Transaction transactions[arraySize];                // Declaration of the array

    NetworkState    m_networkState;                     // Current network state
    double          m_networkQuality;                   // Network quality indicator (0-100)
    double          m_messageDelay;                     // Message delay
    int             m_adaptiveThreshold;                // Adaptive threshold
    std::vector<double> m_recentDelays;                 // Recent message delay records
    Time            m_lastMessageTime;                  // Time of the last message
    int             m_maxDelayWindow;                   // Delay window size
    double          m_networkCongestionThreshold;       // Network congestion threshold
    double          m_reputation;                       // Node reputation
    double          m_minReputationThreshold;           // Minimum reputation threshold
    double          m_reputationDecayFactor;            // Reputation decay factor
    double          m_reputationIncrement;             // Reputation increment
    double          m_reputationDecrement;             // Reputation decrement

    std::vector<Time> m_transactionStartTimes;         // Record transaction start time
    std::vector<Time> m_transactionEndTimes;           // Record transaction confirmation time

    virtual void StartApplication (void);
    virtual void StopApplication (void); 

    void HandleRead (Ptr<Socket> socket);

    std::string getPacketContent(Ptr<Packet> packet, Address from); 

    void SendTX(uint8_t data[], int num);

    void SendTXWithDelay(uint8_t data[], int size, double delay);

    void initiateRound(void);

    void changeView(void);

    void sendStringMessage(std::string data);
    
    void printInformation();

    void UpdateNetworkState(double delay);
    int CalculateAdaptiveThreshold();
    double GetNetworkQuality() const;
    void SetNetworkQuality(double quality);
    NetworkState GetNetworkState() const;
    double CalculateMessageDelay();
    void RecordMessageDelay(double delay);
    void PrintNetworkStatus();
    int a=40;
    void PrintStatistics();
    double CalculateTPS1(double latency);
    void CheckConsensusProgress();

    void SubmitTransaction(uint32_t transactionId);
    void ConfirmTransaction(uint32_t transactionId);
    double CalculateTPS();
    
    double GetReputation() const;
    void SetReputation(double reputation);
    void UpdateReputation(bool success);
    bool CanParticipateInConsensus() const;

    EventId m_initiateRoundEvent;
    EventId m_checkProgressEvent;

    bool            m_enableDosAttack;
    int             m_dosAttackRound;
    int             m_dosAttackCount;
    std::vector<int> m_maliciousNodes;
    std::map<int, int> m_receivedAttackCount;
    bool            m_leaderParalyzed;
    bool            m_attackSuccess;
    int             m_messageThreshold;
    Time            m_lastAttackDetectionTime;
    int             m_attackDetectionWindow;
    int m_sequenceNumber;
    std::map<int, std::string> m_lastReceivedMessage;

    void SetupDosAttack(bool enable, int attackRound, int attackCount, 
                        const std::vector<int>& maliciousNodes, int messageThreshold);
    void LaunchDosAttack(int m_id);
    bool IsMaliciousNode(int nodeId);
    void DetectDosAttack(int attackerId);
    void EvaluateAttackResult();
    void SendDosAttackMessage(int m_id);
    const int DOSID = 5;
};
}
#endif
