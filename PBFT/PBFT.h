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

// PBFThase: Enumeration type
enum PBFTPhase {                // Enumeration value comments
    CLIENT_CHANGE,  // 0        Client change
    NEW_ROUND,      // 1        New round
    REQUEST,        // 2        Request
    PRE_PREPARED,   // 3        Pre-prepared stage
    PREPARED,       // 4        Prepared stage
    COMMITTED,      // 5        Committed stage
    REPLY,          // 6        Reply stage
    VIEW_CHANGE,    // 7        View change
    DOS_ATTACK      // 8        DOS attack message type
};

struct Transaction {
    int view;               // View number
    int value;              // Transaction value
    int prepare_vote;       // Number of votes in the prepared stage
    int commit_vote;        // Number of votes in the committed stage
};

class NodeApp : public Application
{
  public:
    static TypeId GetTypeId (void);

    NodeApp (void);

    virtual ~NodeApp (void);

    uint32_t        m_id;                               // Node ID
    Ptr<Socket>     m_socket;                           // Listening socket
    std::map<Ipv4Address, Ptr<Socket>>      m_peersSockets;            // Socket list of neighbor nodes
    std::map<Address, std::string>          m_bufferedData;            // Map holding the buffered data from previous handleRead events
    
    Address         m_local;                            // Address of this node
    std::vector<Ipv4Address>  m_peersAddresses;         // Neighbor list

    std::vector<char> ledger;                           // Ledger
    
    int             N;                                  // Total number of nodes
    int             is_leader;                          // Are you a leader?
    int             sec_num;                            // The transaction sequence number
    int             view_number;                        // View node ID

    int             leader_id;                          // Leader ID
    int             client_id;                          // Client ID

    static const int arraySize = 100;                    // Control total number of transactions
    Transaction transactions[arraySize];                // Declaration of the transaction array

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

    void PrintStatistics();
    double CalculateTPS1(double latency);

    void SubmitTransaction(uint32_t transactionId);
    void ConfirmTransaction(uint32_t transactionId);
    double CalculateTPS();
    // Reputation-related member variables and methods
    double m_reputation = 50.0;  // Reputation
    // Update reputation
    void UpdateReputation(bool success);
    // Check whether it meets the conditions for participating in consensus
    bool CanParticipateInConsensus() const;  

    // DOS attack related parameters
    bool            m_enableDosAttack;                 // Whether to enable DOS attack
    int             m_dosAttackRound;                  // Which round to launch the attack
    int             m_dosAttackCount;                  // Number of attacks
    std::vector<int> m_maliciousNodes;                 // List of malicious nodes
    std::map<int, int> m_receivedAttackCount;          // Record the number of attack messages received by each node
    bool            m_leaderParalyzed;                 // Whether the main node is paralyzed
    bool            m_attackSuccess;                   // Whether the attack was successful
    int             m_messageThreshold;                // Message threshold, exceeding this value is considered node paralysis
    Time            m_lastAttackDetectionTime;         // Last detected attack time
    int             m_attackDetectionWindow;           // Attack detection window (milliseconds)
    int m_sequenceNumber;  // Add member variable
    std::map<int, std::string> m_lastReceivedMessage;  // Add member variable

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
}
#endif