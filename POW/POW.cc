#include "node-app.h"
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
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <cstring>

namespace ns3 {

// Tool function declarations
float getRandomDelay();
static char convertIntToChar(int a);
static int convertCharToInt(char a);
void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p);

// Global variables
int round_number = 0;

/*********************** APPLICATION IMPLEMENTATION ***********************/
NS_LOG_COMPONENT_DEFINE("NodeApp");

NS_OBJECT_ENSURE_REGISTERED(NodeApp);

TypeId NodeApp::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::NodeApp")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<NodeApp>();
    return tid;
}

NodeApp::NodeApp(void) {
    // Initialize PoW consensus related variables
    mining = false;
    minedBlocks = 0;
    receivedBlocks = 0;
    difficulty = 2; // Hash value needs to have 4 leading zeros
    round_number = 0;
    round_message_count = 0;
    total_message_count = 0;
    message_copies_count = 0;
    total_time = Seconds(0);
    N = 4; // Default node count, can be set externally
}

NodeApp::~NodeApp(void) {
    NS_LOG_FUNCTION(this);
}

void NodeApp::StartApplication() {
    std::srand(static_cast<unsigned int>(time(0) + m_id)); // Use node ID to ensure different random sequences
    
    // Record simulator start time
    latency_start_time = Simulator::Now();
    NS_LOG_INFO("Simulator start time: " << latency_start_time.GetSeconds());
    
    // Initialize socket
    if (!m_socket) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        m_socket = Socket::CreateSocket(GetNode(), tid);
        if (!m_socket) {
            NS_LOG_ERROR("Failed to create socket!");
            return;
        }
        NS_LOG_INFO("Socket successfully created: " << m_socket);

        InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 7071);
        if (m_socket->Bind(local) == -1) {
            NS_LOG_ERROR("Socket binding failed!");
            return;
        }
        m_socket->Listen();
    } else {
        NS_LOG_INFO("Socket already exists: " << m_socket);
    }

    m_socket->SetRecvCallback(MakeCallback(&NodeApp::HandleRead, this));
    m_socket->SetAllowBroadcast(true);
    NS_LOG_INFO("Node " << m_id << " started");
    printInformation();
    
    // Connect to peer nodes
    if (m_peersAddresses.empty()) {
        NS_LOG_WARN("m_peersAddresses is empty! No peers to connect.");
        return;
    }
    
    std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();
    while (iter != m_peersAddresses.end()) {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        Ptr<Socket> socketClient = Socket::CreateSocket(GetNode(), tid);
        if (!socketClient) {
            NS_LOG_ERROR("Failed to create socketClient for peer: " << *iter);
            iter++;
            continue;
        }
        if (socketClient->Connect(InetSocketAddress(*iter, 7071)) == -1) {
            NS_LOG_ERROR("Failed to connect to peer: " << *iter);
            iter++;
            continue;
        }
        m_peersSockets[*iter] = socketClient;
        NS_LOG_INFO("Connected to peer: " << *iter);
        iter++;
    }
    
    // Create genesis block
    createGenesisBlock();
    
    // Node 0 will act as consensus initiator
    if (m_id == 0) {
        Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::initiateRound, this);
    }
}

void NodeApp::StopApplication() {
    NS_LOG_INFO("Node " << m_id << " stops at time " << Simulator::Now().GetSeconds() << "s");
    
    // Stop mining
    StopMining();
    
    // Close sockets
    if (m_socket) {
        m_socket->Close();
    }
    
    for (auto& peer : m_peersSockets) {
        if (peer.second) {
            peer.second->Close();
        }
    }
    
    // Print statistics
    PrintStatistics();
}

// Create genesis block
void NodeApp::createGenesisBlock() {
    Block genesisBlock;
    genesisBlock.index = 0;
    genesisBlock.prevHash = "0"; // Genesis block's previous hash is 0
    genesisBlock.timestamp = static_cast<int>(std::time(nullptr));
    genesisBlock.data = "Genesis Block - Node " + std::to_string(m_id);
    genesisBlock.nonce = 0;
    
    // Calculate genesis block hash
    genesisBlock.hash = calculateBlockHash(
        genesisBlock.index,
        genesisBlock.prevHash,
        genesisBlock.timestamp,
        genesisBlock.nonce,
        genesisBlock.data
    );
    
    // Add genesis block to chain
    blockchain.push_back(genesisBlock);
    NS_LOG_INFO("Node " << m_id << " created genesis block: " << genesisBlock.hash);
}

// Initiate new round of consensus
void NodeApp::initiateRound() {
    // Check if maximum rounds reached
    if (round_number == 30) {
        NS_LOG_INFO(round_number << " rounds completed!");
        
        // Calculate TPS - using same logic as original PBFT
        double TPS = round_number * 1000 / (total_time.GetSeconds() * N);
        NS_LOG_INFO("Total consensus duration: " << total_time.GetSeconds() << " ms.");
        NS_LOG_INFO("Transaction throughput: " << TPS << "tps");

        // Calculate average transaction latency - using same logic as original PBFT
        Time totalLatency = latency_end_time - latency_start_time;
        double avgLatency = (totalLatency.GetSeconds() * N / round_number)*a;
        NS_LOG_INFO("Total latency: " << totalLatency.GetSeconds() << "ms.");
        NS_LOG_INFO("Average transaction latency: " << avgLatency << "ms");

        // Calculate message totals - using same logic as original PBFT
        NS_LOG_INFO("Average message copy count: " << message_copies_count << " times");
        double total_comm_cost = (total_message_count + round_number) * 49 * 1.0 / 1024;
        NS_LOG_INFO("Total message count: " << total_message_count << " times");
        NS_LOG_INFO("Total communication cost: " << total_comm_cost << "KB");
        
        // Use ns-3's Stop method to stop simulator
        Simulator::Stop();
        return;
    }

    round_number++;
    NS_LOG_INFO("----------------- New block mining started! => " << round_number << " ------------------");
    
    // Record start time
    round_start_time = Simulator::Now();
    NS_LOG_WARN("Consensus start time: " << round_start_time.GetSeconds());
    
    // Broadcast new transaction request
    GenerateTransaction();
    
    // Start mining
    StartMining();
}

// Start mining
void NodeApp::StartMining() {
    if (mining) {
        return; // Already mining
    }
    
    mining = true;
    NS_LOG_INFO("Node " << m_id << " started mining");
    
    // Schedule mining event - using original delay function to maintain network delay characteristics
    miningEvent = Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::MineBlock, this);
}

// Stop mining
void NodeApp::StopMining() {
    if (!mining) {
        return;
    }
    
    mining = false;
    if (miningEvent.IsRunning()) {
        Simulator::Cancel(miningEvent);
    }
    
    NS_LOG_INFO("Node " << m_id << " stopped mining");
}

// Generate new transaction
void NodeApp::GenerateTransaction() {
    // Create a new transaction
    Transaction tx;
    tx.id = static_cast<int>(Simulator::Now().GetSeconds() * 1000) + m_id; // Use time+nodeID as unique identifier
    tx.timestamp = static_cast<int>(std::time(nullptr));
    tx.data = "Transaction from Node " + std::to_string(m_id) + " at round " + std::to_string(round_number);
    tx.hash = calculateTxHash(tx);
    
    NS_LOG_INFO("Node " << m_id << " created new transaction: " << tx.hash);
    
    // Process local transaction
    ProcessNewTransaction(tx);
    
    // Broadcast transaction to network
    BroadcastNewTransaction(tx);
}

// Process new transaction
void NodeApp::ProcessNewTransaction(const Transaction& tx) {
    // Check if transaction already exists
    for (const auto& t : pendingTransactions) {
        if (t.hash == tx.hash) {
            return; // Transaction already exists
        }
    }
    
    // Add to pending transaction pool
    pendingTransactions.push_back(tx);
    
    NS_LOG_INFO("Node " << m_id << " added transaction to transaction pool: " << tx.hash << " Transaction pool size: " << pendingTransactions.size());
}

// Mining main function
void NodeApp::MineBlock() {
   static int attempts = 0;
   if (attempts > 1000) { // Add attempt count limit
       // Lower difficulty
       if (difficulty > 1) difficulty--;
       attempts = 0;
       NS_LOG_INFO("Lower mining difficulty to: " << difficulty);
    }
    attempts++;
    if (!mining || blockchain.empty() || pendingTransactions.empty()) {
        // If no pending transactions, try again later
        miningEvent = Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::MineBlock, this);
        return;
    }
    
    // Create new block
    Block newBlock;
    newBlock.index = blockchain.size();
    newBlock.prevHash = blockchain.back().hash;
    newBlock.timestamp = static_cast<int>(std::time(nullptr));
    
    // Collect pending transactions as block data
    std::stringstream txData;
    int txLimit = std::min(10, (int)pendingTransactions.size()); // Maximum of 10 transactions
    
    for (int i = 0; i < txLimit; i++) {
        txData << pendingTransactions[i].hash << ";";
    }
    
    newBlock.data = txData.str();
    
    // Random starting nonce
    newBlock.nonce = rand() % 1000000;
    
    // Calculate block hash
    newBlock.hash = calculateBlockHash(
        newBlock.index,
        newBlock.prevHash,
        newBlock.timestamp,
        newBlock.nonce,
        newBlock.data
    );
    
    // Check if difficulty requirements are met
    if (isValidProof(newBlock.hash)) {
        // Successfully mined a block!
        NS_LOG_INFO("Node " << m_id << " successfully mined block: " << newBlock.hash);
        
        // Add to local chain
        AddBlock(newBlock);
        
        // Remove included transactions from pending transactions
        if (txLimit > 0) {
            pendingTransactions.erase(pendingTransactions.begin(), pendingTransactions.begin() + txLimit);
        }
        
        // Broadcast new block
        BroadcastNewBlock(newBlock);
        
        // Record end time and calculate performance metrics
        round_end_time = Simulator::Now();
        latency_end_time = Simulator::Now();
        
        NS_LOG_WARN("Consensus end time: " << round_end_time.GetSeconds());
        NS_LOG_WARN("Simulator end time: " << latency_end_time.GetSeconds());
        
        // Calculate current round duration - using same logic as original PBFT
        Time round_duration = round_end_time - round_start_time;
        total_time += round_duration;
        NS_LOG_INFO("Block completion time: " << round_duration.GetSeconds() << " seconds");
        
        // Update message statistics
        round_message_count = receivedBlocks * 2;
        message_copies_count += round_message_count;
        total_message_count += round_message_count;
        
        // Modify: All nodes can attempt to initiate next round of consensus
        // Use nodeID as random seed to avoid all nodes initiating simultaneously
        Simulator::Schedule(
            Seconds(getRandomDelay() * (m_id + 1)), 
            &NodeApp::initiateRound, 
            this
        );

        // Stop current mining
        StopMining();
    } else {
        // No solution found, continue trying
        newBlock.nonce++;
        
        // Schedule next attempt - maintaining original delay characteristics
        miningEvent = Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::MineBlock, this);
    }
}

// Verify block
bool NodeApp::VerifyBlock(const Block& block) {
    // Check index and previous hash
    if (block.index > 0) {
        if (blockchain.size() > 0 && block.prevHash != blockchain.back().hash) {
            NS_LOG_WARN("Block previous hash verification failed");
            return false;
        }
    }
    
    // Verify hash calculation
    std::string calculatedHash = calculateBlockHash(
        block.index,
        block.prevHash,
        block.timestamp,
        block.nonce,
        block.data
    );
    
    if (calculatedHash != block.hash) {
        NS_LOG_WARN("Block hash verification failed");
        return false;
    }
    
    // Verify proof of work
    if (!isValidProof(block.hash)) {
        NS_LOG_WARN("Proof of work verification failed");
        return false;
    }
    
    return true;
}

// Add block to blockchain
void NodeApp::AddBlock(const Block& block) {
    // Check if block already exists
    for (const auto& b : blockchain) {
        if (b.hash == block.hash) {
            NS_LOG_INFO("Block already exists in chain");
            return;
        }
    }
    
    // Verify block
    if (!VerifyBlock(block)) {
        NS_LOG_WARN("Block verification failed, not added");
        return;
    }
    
    // Add block to chain
    blockchain.push_back(block);
    minedBlocks++;
    
    NS_LOG_INFO("Node " << m_id << " added block to chain: " << block.hash << " Blockchain height: " << blockchain.size());
}

// Handle received blockchain
void NodeApp::HandleBlockchain(std::vector<Block> receivedChain) {
    if (receivedChain.empty()) {
        return;
    }
    
    // Verify received chain
    bool valid = true;
    for (const auto& block : receivedChain) {
        if (!VerifyBlock(block)) {
            valid = false;
            break;
        }
    }
    
    if (!valid) {
        NS_LOG_WARN("Received blockchain invalid");
        return;
    }
    
    // If received chain longer than local chain, replace local chain
    if (receivedChain.size() > blockchain.size()) {
        NS_LOG_INFO("Received longer valid chain, replace local chain");
        blockchain = receivedChain;
    }
}

// Broadcast new block
void NodeApp::BroadcastNewBlock(const Block& block) {
    std::stringstream ss;
    ss << "NEW_BLOCK:" << block.index << ":" << block.prevHash << ":" << block.timestamp << ":" 
       << block.nonce << ":" << block.data << ":" << block.hash;
    
    std::string message = ss.str();
    NS_LOG_INFO("Broadcast new block: " << block.hash);
    sendStringMessage(message);
}

// Broadcast new transaction
void NodeApp::BroadcastNewTransaction(const Transaction& tx) {
    std::stringstream ss;
    ss << "NEW_TX:" << tx.id << ":" << tx.timestamp << ":" << tx.data << ":" << tx.hash;
    
    std::string message = ss.str();
    NS_LOG_INFO("Broadcast new transaction: " << tx.hash);
    sendStringMessage(message);
}

// Request full blockchain
void NodeApp::RequestFullChain() {
    std::string message = "CHAIN_REQUEST:" + std::to_string(m_id);
    sendStringMessage(message);
}

/*********************** NETWORK COMMUNICATION ***********************/

// Handle received message
void NodeApp::HandleRead(Ptr<Socket> socket) {
    if (!socket) {
        NS_LOG_ERROR("Empty socket in HandleRead");
        return;
    }
    
    Ptr<Packet> packet;
    Address from;
    Address localAddress;
    
    while ((packet = socket->RecvFrom(from))) {
        socket->SendTo(packet, 0, from);
        
        if (packet->GetSize() == 0) {
            break;
        }
        
        if (!InetSocketAddress::IsMatchingType(from)) {
            NS_LOG_ERROR("Received data from unknown address type");
            continue;
        }
        
        // Parse message
        std::string msg = getPacketContent(packet, from);
        NS_LOG_DEBUG("Node " << m_id << " received message: " << msg);
        
        if (msg.find("NEW_BLOCK:") == 0) {
            // Handle new block message
            std::vector<std::string> parts;
            std::string part;
            std::istringstream msgStream(msg.substr(10)); // Skip "NEW_BLOCK:"
            
            while (std::getline(msgStream, part, ':')) {
                parts.push_back(part);
            }
            
            if (parts.size() >= 6) {
                Block block;
                block.index = std::stoi(parts[0]);
                block.prevHash = parts[1];
                block.timestamp = std::stoi(parts[2]);
                block.nonce = std::stoi(parts[3]);
                block.data = parts[4];
                block.hash = parts[5];
                
                NS_LOG_INFO("Received new block: " << block.hash);
                
                // Verify and add block
                if (VerifyBlock(block)) {
                    AddBlock(block);
                    receivedBlocks++;
                    
                    // If it's a consensus block (height equals current round)
                    if (block.index == round_number) {
                        // Record end time
                        round_end_time = Simulator::Now();
                        latency_end_time = Simulator::Now();
                        
                        NS_LOG_WARN("Consensus end time: " << round_end_time.GetSeconds());
                        NS_LOG_WARN("Simulator end time: " << latency_end_time.GetSeconds());
                        
                        // Calculate current round duration
                        Time round_duration = round_end_time - round_start_time;
                        total_time += round_duration;
                        NS_LOG_INFO("Block completion time: " << round_duration.GetSeconds() << " seconds");
                        
                        // Update message statistics
                        round_message_count = receivedBlocks * 2;
                        message_copies_count += round_message_count;
                        total_message_count += round_message_count;
                        
                        // Stop current mining
                        StopMining();
                    }
                }
            }
        }
        else if (msg.find("NEW_TX:") == 0) {
            // Handle new transaction message
            std::vector<std::string> parts;
            std::string part;
            std::istringstream msgStream(msg.substr(7)); // Skip "NEW_TX:"
            
            while (std::getline(msgStream, part, ':')) {
                parts.push_back(part);
            }
            
            if (parts.size() >= 4) {
                Transaction tx;
                tx.id = std::stoi(parts[0]);
                tx.timestamp = std::stoi(parts[1]);
                tx.data = parts[2];
                tx.hash = parts[3];
                
                NS_LOG_INFO("Received new transaction: " << tx.hash);
                
                // Process transaction
                ProcessNewTransaction(tx);
                
                // If not already mining, start
                if (!mining) {
                    StartMining();
                }
            }
        }
        else if (msg.find("CHAIN_REQUEST:") == 0) {
            // Handle blockchain request
            int requesterId = std::stoi(msg.substr(14)); // Skip "CHAIN_REQUEST:"
            
            if (requesterId != m_id) { // Don't handle own request
                NS_LOG_INFO("Received blockchain request from node " << requesterId);
                
                // Send blockchain response
                std::stringstream response;
                response << "CHAIN_RESPONSE:" << blockchain.size() << ":";
                
                for (const auto& block : blockchain) {
                    response << block.index << "," << block.prevHash << "," << block.timestamp << "," 
                             << block.nonce << "," << block.data << "," << block.hash << ";";
                }
                
                sendStringMessage(response.str());
            }
        }
        else if (msg.find("CHAIN_RESPONSE:") == 0) {
            // Handle blockchain response
            std::vector<std::string> chainParts;
            std::string part;
            std::istringstream msgStream(msg.substr(15)); // Skip "CHAIN_RESPONSE:"
            
            std::getline(msgStream, part, ':'); // Get chain length
            int chainSize = std::stoi(part);
            
            std::vector<Block> receivedChain;
            std::string blocksData;
            std::getline(msgStream, blocksData); // Get all block data
            
            std::istringstream blocksStream(blocksData);
            std::string blockStr;
            
            while (std::getline(blocksStream, blockStr, ';')) {
                if (blockStr.empty()) continue;
                
                std::vector<std::string> blockParts;
                std::istringstream blockStream(blockStr);
                std::string blockPart;
                
                while (std::getline(blockStream, blockPart, ',')) {
                    blockParts.push_back(blockPart);
                }
                
                if (blockParts.size() >= 6) {
                    Block block;
                    block.index = std::stoi(blockParts[0]);
                    block.prevHash = blockParts[1];
                    block.timestamp = std::stoi(blockParts[2]);
                    block.nonce = std::stoi(blockParts[3]);
                    block.data = blockParts[4];
                    block.hash = blockParts[5];
                    
                    receivedChain.push_back(block);
                }
            }
            
            if (receivedChain.size() == chainSize) {
                HandleBlockchain(receivedChain);
            }
        }
    }
}

// Calculate block hash
std::string NodeApp::calculateBlockHash(int index, std::string prevHash, int timestamp, int nonce, std::string data) {
    std::stringstream ss;
    ss << index << prevHash << timestamp << nonce << data;
    std::string input = ss.str();
    
    // Simple SHA1 simulation implementation
    unsigned long hash = 5381;
    for (char c : input) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    
    std::stringstream hashStream;
    hashStream << std::hex << std::setw(8) << std::setfill('0') << hash;
    return hashStream.str();
}

// Calculate transaction hash
std::string NodeApp::calculateTxHash(const Transaction& tx) {
    std::stringstream ss;
    ss << tx.id << tx.timestamp << tx.data;
    std::string input = ss.str();
    
    // Simple SHA1 simulation implementation
    unsigned long hash = 5381;
    for (char c : input) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    
    std::stringstream hashStream;
    hashStream << std::hex << std::setw(8) << std::setfill('0') << hash;
    return hashStream.str();
}

// Verify proof of work
   // Modify isValidProof function, lower verification standard
   bool NodeApp::isValidProof(std::string hash) {
       // Check if first difficulty digits are 0-4, not strict 0
       for (int i = 0; i < difficulty; i++) {
           if (hash[i] < '0' || hash[i] > '4') {
               return false;
           }
       }
       return true;
   }

// Print node information
void NodeApp::printInformation() {
    NS_LOG_INFO("=============== Node " << m_id << " Information ===============");
    NS_LOG_INFO("Mining difficulty: " << difficulty);
    NS_LOG_INFO("Blockchain length: " << blockchain.size());
    NS_LOG_INFO("Peer node count: " << m_peersAddresses.size());
    NS_LOG_INFO("==================================================");
}

// Print statistics
void NodeApp::PrintStatistics() {
    Time runTime = Simulator::Now() - latency_start_time;
    
    NS_LOG_INFO("================== Node " << m_id << " Statistics ==================");
    NS_LOG_INFO("Run time: " << runTime.GetSeconds() << " seconds");
    NS_LOG_INFO("Blockchain height: " << blockchain.size());
    NS_LOG_INFO("Mined blocks: " << minedBlocks);
    NS_LOG_INFO("Received blocks: " << receivedBlocks);
    NS_LOG_INFO("Transaction throughput: " << (round_number * 1000.0) / (total_time.GetSeconds() * N) << "tps");
    NS_LOG_INFO("==================================================");
}

// Get packet content
std::string NodeApp::getPacketContent(Ptr<Packet> packet, Address from) {
    char* packetInfo = new char[packet->GetSize() + 1];
    std::ostringstream totalStream;
    packet->CopyData(reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize());
    packetInfo[packet->GetSize()] = '\0';
    totalStream << m_bufferedData[from] << packetInfo;
    std::string totalReceivedData(totalStream.str());
    delete[] packetInfo;
    return totalReceivedData;
}

// Send message
void NodeApp::SendTX(uint8_t data[], int size) {
    double delay = getRandomDelay();
    SendTXWithDelay(data, size, delay);
}

// Send message with delay
void NodeApp::SendTXWithDelay(uint8_t data[], int size, double delay) {
    if (m_peersSockets.empty()) {
        NS_LOG_ERROR("Cannot send message, m_peersSockets is empty!");
        return;
    }
    
    Ptr<Packet> p = Create<Packet>(data, size);
    
    for (const auto& peerPair : m_peersSockets) {
        if (!peerPair.second) {
            NS_LOG_WARN("Skip invalid socket");
            continue;
        }
        
        Ptr<Socket> socketClient = peerPair.second;
        Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
    }
}

// Send string message
void NodeApp::sendStringMessage(std::string message) {
    std::vector<uint8_t> myVector(message.begin(), message.end());
    uint8_t* d = &myVector[0];
    SendTX(d, message.size());
}

/*********************** UTILITY FUNCTIONS ***********************/

// Random delay function - maintaining same delay characteristics as original PBFT
float getRandomDelay() {
    return (rand() % 9) / 1000.0;  // Same effect
}

char convertIntToChar(int a) {
    return a + '0';
}

int convertCharToInt(char a) {
    return a - '0';
}

void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p) {
    socketClient->Send(p);
}

} // namespace ns3