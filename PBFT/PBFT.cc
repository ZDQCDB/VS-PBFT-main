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

int request_count       =       0;
int preprepare_count    =       0;
int prepare_count       =       0;
int commit_count        =       0;
int reply_count         =       0;
int round_number        =       0;
int view_is_changed     =       0;

int DOS_successful_count = 0;

namespace ns3{

    float getRandomDelay();
    static char convertIntToChar(int a);
    static int convertCharToInt(char a);
    static void log_message_counts();
    void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p);

    /*******************************APPLICATION*******************************/
    NS_LOG_COMPONENT_DEFINE("NodeApp");

    NS_OBJECT_ENSURE_REGISTERED(NodeApp);

    TypeId NodeApp::GetTypeId(void){
        static TypeId tid = TypeId("ns3::NodeApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<NodeApp>();

        return tid;
    }

    NodeApp::NodeApp(void){
    }

    NodeApp::~NodeApp(void){
        NS_LOG_FUNCTION(this);
    }
    Time round_start_time;
    Time round_end_time;
    Time total_time = Seconds(0); // 用于累加所有轮次的总耗时
    Time latency_start_time;
    Time latency_end_time;
    int round_message_count = 0;  // Current round message count
    int total_message_count = 0;  // Total message count for all rounds
    int message_copies_count = 0; // Total message copies count

    void NodeApp::StartApplication() {
        std::srand(static_cast<unsigned int>(time(0)));
        latency_start_time = Simulator::Now();
        NS_LOG_INFO("Simulator start time: " << latency_start_time.GetSeconds());
        // Initialize socket
        if (!m_socket)
        {
            TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
            m_socket = Socket::CreateSocket(GetNode(), tid);
            // Note: This is equivalent to monitoring all network card IP addresses.
            InetSocketAddress local = InetSocketAddress(Ipv4Address::GetAny(), 7071);
            m_socket->Bind(local); // Bind the local IP and port
            m_socket->Listen();
        }
        m_socket->SetRecvCallback(MakeCallback(&NodeApp::HandleRead, this));
        m_socket->SetAllowBroadcast(true);

        std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();
        // Establish connections to all nodes (each node to its neighbors)
        NS_LOG_INFO("node" << m_id << " start");
        printInformation();
        while (iter != m_peersAddresses.end())
        {
            TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
            Ptr<Socket> socketClient = Socket::CreateSocket(GetNode(), tid);
            socketClient->Connect(InetSocketAddress(*iter, 7071));
            m_peersSockets[*iter] = socketClient;
            iter++;
        }

        // Initialize algorithm by broadcasting 'CLIENT_CHANGE' by leader
        if (is_leader == 1) {
            Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::initiateRound, this);
        }
        
        // Setting DOS attack parameters (disabled by default)
        std::vector<int> maliciousNodes = {5, 6}; // Nodes 5 and 6 are malicious nodes
        SetupDosAttack(false, 30, 1000, maliciousNodes, 20); // Round 30, send 100 attacks, threshold 20, set to True to enable
    }

    void NodeApp::StopApplication(){
        if (is_leader == 1)    {
            NS_LOG_INFO("At time " << Simulator::Now().GetSeconds() << " Stop");
        }
    }
    // Update reputation: +10 for successful consensus, -10 for failed consensus
    void NodeApp::UpdateReputation(bool success) {
        if (success) {
            m_reputation += 0.1;  // Successful consensus participation, reputation +1
        } else {
            m_reputation -= 0.5;  // Failed consensus participation, reputation -10
        }

        // Ensure reputation is not below 0
        if (m_reputation < 0) {
            m_reputation = 0;
        }
        // Ensure reputation does not exceed 100
        if(m_reputation>100){
            m_reputation=100;
        }
        // Print updated reputation
        NS_LOG_INFO("Node " << m_id << " reputation updated to: " << m_reputation);
    }

    // Determine if node can participate in consensus (reputation >= 30)
    bool NodeApp::CanParticipateInConsensus() const {
        return m_reputation > 30;
    }
    /*******************************INTERACTION*******************************/

    void NodeApp::initiateRound(void){             
        /* Initial new round of network
            Hit the possibility of view change and handle it
            Reset network and define a new client and broadcast <client-change> message to network
            Then construct a <new-round> message and broadcast to network */          


        // 1. Check round limit
        if(round_number==30){
            NS_LOG_INFO(round_number<<" Round Finished Successfully!");
            
            //Calculate TPS
            double TPS = round_number*1000 / (total_time.GetSeconds()*N);
            NS_LOG_INFO("Total consensus duration: " << total_time.GetSeconds() << " ms.");
            NS_LOG_INFO("Transaction throughput: " << TPS << "tps");

            //Calculate average transaction latency
            Time totalLantency=latency_end_time-latency_start_time;
            double avgLantency = totalLantency.GetSeconds()*N / round_number;
            NS_LOG_INFO("Total latency: " << totalLantency.GetSeconds() << "ms.");
            NS_LOG_INFO("Average transaction latency: " << avgLantency << "ms");

            //Calculate total messages
            NS_LOG_INFO("Average message copies count: " << message_copies_count << " times");

            //Calculate communication overhead
            double total_comm_cost = total_message_count*49*1.0/1024;
            NS_LOG_INFO("Total message count: " << total_message_count << " times");
            NS_LOG_INFO("Total communication cost: " << total_comm_cost << "KB");            
            //EvaluateAttackResult();

            exit(0);
        }

        // 2. Hit the possibility of view change
        if (rand()%3==0 && view_is_changed==0){
            changeView();
            return;
        } else{
            NS_LOG_INFO("Current Leader Id => " << leader_id << "\n\n");
            view_is_changed=0;
        }  

        round_number++;

        // 3. Reset values
        request_count = 0;
        preprepare_count = 0;
        prepare_count = 0;
        commit_count = 0;
        reply_count = 0;

        // 4. Construct a template block
        std::string data[7]; 

        // 5. Set client who send request
        int random_client = -1;
        do{
            random_client = (rand() % N);
        }
        while(random_client == leader_id || client_id==random_client);

        client_id = random_client;
        NS_LOG_INFO("Current Client Id => " << client_id<<"\n\n");

        NS_LOG_INFO("----------------- New round started! => "<<round_number<<" ------------------");

        // 6. Construct a ClientChangeMessage(Set client id)
        /*- client-change:
            0. 0                        // NOT SET
            1. type: request            = CLIENT-CHANGE
            2. 0                        // NOT SET
            3. client-id                = client-id     // Random
            4. 0                        // NOT SET
            5. 0                        // NOT SET
            6. 0                        // NOT SET
        */
        data[0] = '0';
        data[2] = '0';
        data[3] = convertIntToChar(client_id);
        data[4] = '0';
        data[5] = '0';
        data[6] = '0'; // hasn't sign yet

        // 7. Set message state to 'CLIENT-CHANGE'
        data[1] = convertIntToChar(CLIENT_CHANGE);

        // 8. Broadcast client change message
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        NS_LOG_INFO("Message(CLIENT_CHANGE) Broadcasts => " << dataString<<"\n\n");
        sendStringMessage(dataString);

        // 9. Set message state to 'NEW-ROUND'
        data[1] = convertIntToChar(NEW_ROUND);

        // 10. Broadcast new round message (with larger delay)
        dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        NS_LOG_INFO("Message(NEW_ROUND) Broadcasts => " << dataString<<"\n\n");
        
        std::vector<uint8_t> myVector(dataString.begin(), dataString.end());
        uint8_t* d = &myVector[0];
        NodeApp::SendTXWithDelay(d, sizeof(dataString),12);   
        // Check if DOS attack needs to be triggered
        if (m_enableDosAttack && round_number == m_dosAttackRound) {
            NS_LOG_INFO("Node " << m_id << " preparing to launch DOS attack in round " << round_number);
            LaunchDosAttack(5); // Use current node ID
        }
    }

    // Handle incomming messages and Parse them in different states
    void NodeApp::HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;
        Address localAddress;

        while ((packet = socket->RecvFrom(from)))
        {
            socket->SendTo(packet, 0, from);
            if (packet->GetSize() == 0)
            {
                break;
            }
            if (!InetSocketAddress::IsMatchingType(from))
            {
                NS_LOG_ERROR("Received packet from an unexpected address type.");
                continue;
            }else{
            
                std::string msg = getPacketContent(packet, from);
                uint8_t client_id_uint = static_cast<uint8_t>(client_id);
                int state = convertCharToInt(msg[1]);

                // NS_LOG_INFO(state<<"======>"<<msg<<"-=====>"<<m_id<<"====>"<<client_id);
        
                // Client should not process messages: PRE-PREPARED,PREPARED, COMMIT, VIEW-CHANGE 
                if(m_id == client_id_uint && state != REPLY && state != NEW_ROUND && state!=CLIENT_CHANGE){
                    // NS_LOG_ERROR("Catch0 state=>"<<state<<" ID=>"<<m_id);
                    return;
                }               

                std::string data[7]; 

                // Which message is this?
                switch (state){
                    case CLIENT_CHANGE:{
                        /* Handle client change:
                            update client-id variable
                        */
                        client_id = convertCharToInt(msg[3]);
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);
                        NS_LOG_INFO("Client Id of "<<m_id<<" changed to => "<< client_id<<"\n\n");                        
                    }
                    case NEW_ROUND:{
                        /* Handle Start a new round:
                            Creating a <request message> and broadcast it by client
                        */

                        // Only Client should handle NEW-ROUND by send a request to the blockchain
                        if(m_id != client_id_uint){
                            // NS_LOG_ERROR("Catch1 state=>"<<state<<" ID=>"<<m_id);
                            return;
                        }
                        round_start_time = Simulator::Now();
                        NS_LOG_WARN("Consensus start time: " << round_start_time.GetSeconds());
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 1. Construct a RequestMessage 
                        /*- request:
                            0. value                    = random
                            1. type: request            = REQUEST
                            2. sender-id                = m_id
                            3. client-id                = client-id
                            4. view number(leader-id)   = view-number
                            5. sequence-number          = 0             // NOT SET
                            6. primary signed           = 0             // NOT SET
                        */
                        // Random value for request (Primary should assign sequence number and sign it)
                        data[0] = convertIntToChar(rand() % 9);
                        data[2] = convertIntToChar(m_id);
                        data[3] = convertIntToChar(client_id);
                        data[4] = convertIntToChar(view_number);
                        data[5] = '0';
                        data[6] = '0';

                        // 2. Set message state to to REQUEST  
                        data[1] = convertIntToChar(REQUEST);
                        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                        NS_LOG_INFO("Message(REQUEST) Broadcasts => " << dataString<<"\n\n");
                        sendStringMessage(dataString);
                    
                        break;
                    }
                    case REQUEST:{

                        /* Handle getting request:
                            should sign the request and broadcast <pre-prepare message> by primary
                        */

                        // Only leader should proccess request by signing it and broadcast
                        if (is_leader==0){
                            // NS_LOG_ERROR("Catch2 state=>"<<state<<" ID=>"<<m_id);
                            return;
                        }

                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 1. Add request counter and log
                        request_count++;
                        log_message_counts();

                        // 2. Construct PrePrepareMessage
                        /*- pre-prepare:
                            0. value                    = msg[0]
                            1. type: pre-prepare        = PREPREPARE
                            2. sender-id                = m_id
                            3. client-id                = msg[3]
                            4. view number(leader-id)   = msg[4]
                            5. sequence-number          = sec number // SET
                            6. primary signed           = 1          // SET/Signed
                        */
                        data[0] = msg[0];           
                        data[2] = convertIntToChar(m_id);
                        data[3] = msg[3];
                        data[4] = msg[4];

                        // 3. Set sequence number by primary and update it
                        data[5] = convertIntToChar(sec_num);
                        sec_num++;

                        // 4. Sign the transaction 
                        data[6] = '1';
                        
                        // 5. Set message state to PRE-PREPARED
                        data[1] = convertIntToChar(PRE_PREPARED);     

                        // 6. Broadcast pre-prepared message
                        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                        NS_LOG_INFO("Message(PRE_PREPARED) Broadcasts => " << dataString<<"\n\n");
                        sendStringMessage(dataString);
                        break;
                    }
                    case PRE_PREPARED:{ 
                        /* Handle pre-prepare message
                            Should check primary sign and insert it into their transactions
                            then broadcast <prepared message> 
                        */
        
                        // 1. Check primary sign (sent by primary)
                        if(msg[6]=='0'){
                            return;
                        }

                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 2. Add preprepare message counter and log 
                        preprepare_count++;
                        log_message_counts();

                        // 3. Construct prepare message
                        /*- prepare:
                            0. value                    = msg[0]
                            1. type: prepare            = PREPARE
                            2. sender-id                = m_id
                            3. client-id                = msg[3]
                            4. view number(leader-id)   = msg[4]
                            5. sequence-number          = msg[5]  
                            6. primary signed           = msg[6]  
                        */                    
                        data[0] = msg[0];           
                        data[2] = convertIntToChar(m_id);
                        data[3] = msg[3];
                        data[4] = msg[4];
                        data[5] = msg[5];
                        data[6] = msg[6];

                        // 4. Add transaction
                        // Sequence number value
                        int index = convertCharToInt(msg[5]);

                        // Set view in transaction
                        transactions[index].view = view_number;

                        // Store the value in the transaction
                        transactions[index].value = convertCharToInt(msg[0]);

                        // 5. Set message state to PREPARED
                        data[1] = convertIntToChar(PREPARED);     

                        // 6. broadcast prepared message  
                        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                        NS_LOG_INFO("Message(PREPARED) Broadcasts => " << dataString<<"\n\n");
                        sendStringMessage(dataString);
                        break;
                    }
                    case PREPARED:{
                        /* Handle prepare message
                            Should validate message, vote to valid messages and check if votes reach to threshold
                            if it reached, broadcast <commit message> 
                        */
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // Get current count
                        int index = convertCharToInt(msg[3]);  
                        int count = transactions[index].prepare_vote;

                        // 1. validate: check client id and view number and primary sign
                        if(convertCharToInt(msg[3]) == client_id && convertCharToInt(msg[4]) == view_number && convertCharToInt(msg[6])==1){

                            // 2. Add prepare message counter and log
                            prepare_count++;
                            log_message_counts();

                            // 3. Vote
                            transactions[index].prepare_vote++;
                            count++;
                            NS_LOG_INFO(m_id<<" Voted(prepare) to "<<count<<" messages.");   
                        }
                        // 4. Check reaching to threshold (N/2 + 1)
                        if (count >= N/2 + 1){

                            // 5. If it reached  to threshold, Reset votes (Not to send commit again!)
                            transactions[index].prepare_vote=0;

                            // 6. Construct commit message
                            /*- commpit:
                                0. value                    = msg[0]
                                1. type: commit             = COMMIT
                                2. sender-id                = m_id
                                3. client-id                = msg[3]
                                4. view number(leader-id)   = msg[4]
                                5. sequence-number          = msg[5]  
                                6. primary signed           = msg[6]      
                            */   
                            data[0] = msg[0];           
                            data[2] = convertIntToChar(m_id);
                            data[3] = msg[3];
                            data[4] = msg[4];
                            data[5] = msg[5];
                            data[6] = msg[6];

                            // 7. Set message state to COMMITED
                            data[1] = convertIntToChar(COMMITTED);     

                            // 8. broadcast commited message       
                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            NS_LOG_INFO("Message(commit) Broadcasts => " << dataString<<"\n\n");
                            sendStringMessage(dataString);
                        }      
                        else{
                            // :|
                            NS_LOG_INFO("\n\n");  
                        }            
                        break;
                    }
                    case COMMITTED:{
                        /* Handle commit message (consensus)
                            Should validate commit message, vote to valid messages and check if votes reach to threshold
                            if it reached, proccess request and broadcast <reply message> 
                        */
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // Get current count
                        int index = convertCharToInt(msg[5]);
                        int count = transactions[index].commit_vote;

                        // 1. validate: check client id and view number and primary sign                    
                        if(convertCharToInt(msg[3]) == (client_id) && convertCharToInt(msg[4]) == (view_number) && convertCharToInt(msg[6]) ==1){
                            // 2. Add prepare message counter and log
                            commit_count++;
                            log_message_counts();

                            // 3. Vote
                            transactions[index].commit_vote++;
                            count++;
                            NS_LOG_INFO(m_id<<" Voted(commit) to "<<count<<" messages.");  
                        }

                        // 4. Check reaching to threshold (N/2 + 1)
                        if (count >= N/2 + 1)
                        {
                            // 5. If it reached  to threshold, Reset votes (Not to send commit again!)
                            transactions[index].commit_vote=0;

                            // 6. Proccess transaction => x^2 % 10
                            int result = (convertCharToInt(msg[0])*convertCharToInt(msg[0])) % 10;
                            NS_LOG_INFO("Request from "<<client_id<<" done and Result is=> "<<result);

                            // 6. Construct reply
                            /*- reply:
                                0. value                    = processed value
                                1. type: commit             = REPLY
                                2. sender-id                = m_id
                                3. client-id                = msg[3]
                                4. view number(leader-id)   = msg[4]
                                5. sequence-number          = msg[5]  
                                6. primary signed           = msg[6]
                            */   
                            data[0] = convertIntToChar(result);           
                            data[2] = convertIntToChar(m_id);
                            data[3] = msg[3];
                            data[4] = msg[4];
                            data[5] = msg[5];
                            data[6] = msg[6];

                            // 7. Add to ledger
                            ledger.push_back(result);

                            // Increase sequence number
                            sec_num++;
                            NS_LOG_INFO(result<<" Added to Ledger "<<m_id<<"!");

                            // 8. Set message state to REPLY
                            data[1] = convertIntToChar(REPLY);     

                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            NS_LOG_INFO("Message(REPLY) Broadcasts => " << dataString<<"\n\n");
                            sendStringMessage(dataString);
                        }else{
                            // :|
                            NS_LOG_INFO("\n\n");  
                        }
                        break;
                    }
                    case REPLY:{
                        // Only Client should handle REPLY because it's the result of its own transaction(request)
                        if(m_id != client_id_uint){
                            // NS_LOG_ERROR("Catch3 state=>"<<state<<" ID=>"<<m_id);
                            return;
                        } 
                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 1. Add reply counter and log
                        reply_count++;
                        log_message_counts();

                        NS_LOG_INFO("Client=> "<<client_id<<" Receive its request result=> "<<msg[0]<<" From "<<msg[2]);
                        NS_LOG_INFO("===========================================================\n\n");

                        // 2. Start a new round after all replys arrived (by a larger delay to make sure last round is finished)
                        if(reply_count==N-1){

                            // 记录结束时间
                            round_end_time = Simulator::Now();
                            latency_end_time = Simulator::Now();
                            NS_LOG_WARN("Consensus end time: " << round_end_time.GetSeconds());
                            NS_LOG_WARN("Simulator end time: " << latency_end_time.GetSeconds());
                            // 计算当前轮次的耗时
                            Time round_duration = round_end_time - round_start_time;
                            total_time += round_duration;  // 累加总耗时
                            NS_LOG_INFO("Round completed in " << round_duration.GetSeconds() << " seconds.");
                            
                            // 计算当前轮次的消息数量（根据各阶段的消息数量进行加和）
                            round_message_count = request_count + preprepare_count + prepare_count + commit_count + reply_count;
                            message_copies_count += preprepare_count + prepare_count + commit_count;
                            total_message_count += round_message_count;  // 累加总消息数量
                            
                            // Update Sequence number of client
                            sec_num++;

                            Simulator::Schedule(Seconds(getRandomDelay())*10, &NodeApp::initiateRound, this);
                        }
                        break;
                    }
                    case VIEW_CHANGE:{

                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 1. Get new leader id and set it 
                        /*- view-change:
                            0. leader-id                = new leader-id
                            1. type: request            = VIEW-CHANGE
                            2. 0                        // NOT-SET
                            3. 0                        // NOT SET
                            4. 0                        // NOT SET
                            5. 0                        // NOT SET
                            6. 0                        // NOT SET
                        */
                        int new_leader = convertCharToInt(msg[0]);
                        leader_id = new_leader;

                        // 2. Update is-leader state
                        if(static_cast<uint8_t> (new_leader)==m_id){
                            is_leader = 1;
                        }else{
                            is_leader = 0;
                        }

                        // 3. Update view-is-changed
                        view_is_changed++;

                        // 4. Update view-number
                        view_number++;

                        NS_LOG_INFO("Leader Id of "<<m_id<<" changed to => "<< leader_id<<"\n\n"); 

                        // 3. Start a new round when all nodes handled view change
                        if(view_is_changed==N){
                            Simulator::Schedule(Seconds(getRandomDelay())*10, &NodeApp::initiateRound, this);
                        }

                        break;
                    }
                    default:{
                        NS_LOG_INFO("INVLAID MESSAGE TYPE: " << state);
                        break;
                    }

                }

            }
            socket->GetSockName(localAddress);
        }
    }

    // Convert packet came from address to string
    std::string NodeApp::getPacketContent(Ptr<Packet> packet, Address from){
        char* packetInfo = new char[packet->GetSize() + 1];
        std::ostringstream totalStream;
        packet->CopyData(reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize());
        packetInfo[packet->GetSize()] = '\0';
        totalStream << m_bufferedData[from] << packetInfo;
        std::string totalReceivedData(totalStream.str());
        return totalReceivedData;
    }

    void NodeApp::changeView(void){
        /* Handle view change by choose a new node to be leader
            Generate a random Id to be new leader id and broadcast <view-change> message
            */

        // 1. Generate a new id for leader
        int new_id = -1;
        do{
            new_id = rand() % N;
        }while(static_cast<uint8_t> (new_id)==leader_id);

        // 2. Set new leader id and update is-leader for current node
        leader_id = new_id;
        if(m_id!= static_cast<uint8_t> (new_id)){
            is_leader = 0;
        }else{
            is_leader = 1;
        }

        // 3. Update view_is_changed variable
        view_is_changed++;

        // 4. Construct a ViewChangeMessage(Set Leader id)
        /*- view-change:
            0. leader-id                = new leader-id
            1. type: request            = VIEW-CHANGE
            2. 0                        // NOT-SET
            3. 0                        // NOT SET
            4. 0                        // NOT SET
            5. 0                        // NOT SET
            6. 0                        // NOT SET
        */
        std::string data[7]; 

        data[2] = '0';
        data[4] = '0';
        data[3] = '0';
        data[5] = '0';
        data[6] = '0'; 

        // 5. Increase view number
        view_number++;

        // 6. Set message state to VIEW-CHANGE
        data[1] = convertIntToChar(VIEW_CHANGE);

        // 7. Set new leader 
        data[0] = convertIntToChar(leader_id);

        // 8. Broadcast view-change message
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        NS_LOG_INFO("New Leader Id => " << leader_id);
        NS_LOG_INFO("Message(VIEW-CHANGE) Broadcasts => " << dataString<<"\n\n");
        sendStringMessage(dataString);
    }

    /*******************************SEND*******************************/
    // Send Packet to related socket
    void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p){
        socketClient->Send(p);
    }

    // Convert string message to unit_8 type and broadcast it
    void NodeApp::sendStringMessage(std::string message){
        std::vector<uint8_t> myVector(message.begin(), message.end());
        uint8_t* d = &myVector[0];
        NodeApp::SendTX(d, sizeof(message));    
    }

   // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTX(uint8_t data[], int size){
        double delay = getRandomDelay();
        SendTXWithDelay(data, size, delay);
    }
    
    // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTXWithDelay(uint8_t data[], int size, double delay){
        NS_LOG_INFO("broadcast message at time: " << Simulator::Now().GetSeconds() << " s\n\n");
        Ptr<Packet> p;

        p = Create<Packet>(data, size);

        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");

        std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

        while (iter != m_peersAddresses.end())
        {
            TypeId tId = TypeId::LookupByName("ns3::UdpSocketFactory");

            Ptr<Socket> socketClient = m_peersSockets[*iter];

            Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
            iter++;
        }
    }


    /*******************************UTILS*******************************/
    static char convertIntToChar(int a) {
        return a + '0';
    }

    static int convertCharToInt(char a) {
        return a - '0';
    }

    float getRandomDelay() {
        return (rand() % 3) * 1.0 / 1000;
    }

    // Log information about each node and blockchain info
    void NodeApp::printInformation(){
        NS_LOG_INFO("=============== Information Node(Replica) "<<m_id<<" ===============");
        NS_LOG_INFO("Leader id " << leader_id);
        NS_LOG_INFO("Is Leader " << is_leader);
        NS_LOG_INFO("This Id " << m_id);
        NS_LOG_INFO("Sequence number " << sec_num);
        NS_LOG_INFO("===========================================================\n\n");
    }

    void log_message_counts(){
        NS_LOG_INFO("Request count=> "<<request_count<<"    Pre-prepare count=> "<<preprepare_count<<"   Prepare count=> "<<prepare_count<<"   Commit count=> "<<commit_count<<"   Reply count=> "<<reply_count);
    }

    void NodeApp::LaunchDosAttack(int m_id) {
        if (!m_enableDosAttack) {
            return;
        }
        
        NS_LOG_INFO("Malicious node " << m_id << " starts launching DOS flood attack targeting leader node " << leader_id);
        NS_LOG_INFO("Leader node " << leader_id << " begins to detect messages from node " << m_id);
        // Send multiple attack messages
        for (int i = 0; i < m_dosAttackCount; i++) {
            // Use small delay to simulate large number of requests in short time
            SendDosAttackMessage(m_id);
            DetectDosAttack(m_id);
        }
        NS_LOG_INFO("Malicious node " << m_id << " completed DOS flood attack");
    }

    void NodeApp::DetectDosAttack(int attackerId) {        
        // Get most recently received message
        std::string lastMessage = m_lastReceivedMessage[attackerId];
        
        // Check if message is valid (check signature)
        bool isValidMessage = (lastMessage[6] == '1');
        
        // Get current time
        Time now = Simulator::Now();
        m_lastAttackDetectionTime = now;
                
        if (!isValidMessage) {
            DOS_successful_count++;
            NS_LOG_INFO("Leader node detected DOS attack");
        }
    }

    void NodeApp::SendDosAttackMessage(int m_id) {
        std::string data[7];
        
        double probability  = 0.988+N*0.0002;
        bool sendValidMessage = (rand() / (RAND_MAX + 1.0)) < probability;

        if (sendValidMessage) {
            // Construct valid message
            data[0] = convertIntToChar(1); // Valid value
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(view_number);
            data[5] = convertIntToChar(m_sequenceNumber++); // Correct sequence number
            data[6] = '1'; // Add signature
            NS_LOG_INFO("Attacker node " << m_id << " constructs correct message");
        } else {
            // Construct invalid message
            data[0] = convertIntToChar(rand() % 9); // Random value
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(rand() % 100); // Random view number
            data[5] = convertIntToChar(rand() % 100); // Random sequence number
            data[6] = '0'; // No signature
            NS_LOG_INFO("Attacker node " << m_id << " constructs incorrect message");
        }
        
        // Convert array to string
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        
        // Send message to leader node
        if (m_peersSockets.find(m_peersAddresses[leader_id]) != m_peersSockets.end()) {
            Ptr<Socket> leaderSocket = m_peersSockets[m_peersAddresses[leader_id]];
            std::vector<uint8_t> myVector(dataString.begin(), dataString.end());
            uint8_t* d = &myVector[0];
            
            Ptr<Packet> p = Create<Packet>(reinterpret_cast<const uint8_t*>(d), dataString.size());
            leaderSocket->Send(p);
            
            // Save most recent message for detection
            m_lastReceivedMessage[m_id] = dataString;
            
            NS_LOG_INFO("Attacker node " << m_id << " launched DOS attack against leader node " << leader_id);
        }
    }

    void NodeApp::EvaluateAttackResult() {
        NS_LOG_INFO("DOS attack result evaluation:");
        double DOS_successful_rate = static_cast<double>(DOS_successful_count) / m_dosAttackCount;
        NS_LOG_INFO("DOS attack success rate: " << DOS_successful_rate*100 << "%");
        NS_LOG_INFO("DOS attack successful count: " << DOS_successful_count);
        NS_LOG_INFO("DOS attack total count: " << m_dosAttackCount);
    }

    void NodeApp::SetupDosAttack(bool enable, int attackRound, int attackCount, 
                                const std::vector<int>& maliciousNodes, int messageThreshold) {
        m_enableDosAttack = enable;
        m_dosAttackRound = attackRound;
        m_dosAttackCount = attackCount;
        m_maliciousNodes = maliciousNodes;
        m_messageThreshold = messageThreshold;
        m_leaderParalyzed = false;
        m_attackSuccess = false;
        m_attackDetectionWindow = 1000; // 1 second detection window
        m_lastAttackDetectionTime = Simulator::Now();
        
        // Initialize attack counter
        for (int i = 0; i < N; i++) {
            m_receivedAttackCount[i] = 0;
        }
    }

} // namespace ns3
