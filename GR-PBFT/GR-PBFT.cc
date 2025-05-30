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
#include <sodium.h>
#include <array>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <openssl/sha.h>

//定义了公钥和私钥以及证明的大小，这个事libsodium库所规定的
const size_t PublicKeySize = 32;
const size_t SecretKeySize = 64;
const size_t ProofSize = 96;


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
    char convertIntToChar(int a);
    int convertCharToInt(char a);
    void log_message_counts();

    /*******************************APPLICATION*******************************/
    NS_LOG_COMPONENT_DEFINE("NodeApp");

    NS_OBJECT_ENSURE_REGISTERED(NodeApp);

    TypeId NodeApp::GetTypeId(void){
        static TypeId tid = TypeId("ns3::NodeApp")
                                .SetParent<Application>()
                                .SetGroupName("Applications")
                                .AddConstructor<NodeApp>()
                                .AddAttribute("GossipFanout", "Number of peers to send gossip messages to",
                                              UintegerValue(2),
                                              MakeUintegerAccessor(&NodeApp::m_gossipFanout),
                                              MakeUintegerChecker<uint32_t>())
                                .AddAttribute("GossipRounds", "Number of gossip message propagation rounds",
                                              UintegerValue(2),
                                              MakeUintegerAccessor(&NodeApp::m_gossipRounds),
                                              MakeUintegerChecker<uint32_t>());

        return tid;
    }

    NodeApp::NodeApp(void) : 
        m_id(0),
        is_leader(0),
        leader_id(0),
        client_id(0),
        view_number(0),
        sec_num(0),
        m_peersAddresses(),
        m_socket(nullptr),
        m_peersSockets(),
        m_bufferedData(),
        m_nodeInternetAddress(),
        transactions(),
        ledger(),
        m_gossipFanout(2),
        m_gossipRounds(2),
        m_processedMessages(),
        m_roundStartTime(Seconds(0)),
        m_roundEndTime(Seconds(0)),
        m_totalTime(Seconds(0)),
        m_latencyStartTime(Seconds(0)),
        m_latencyEndTime(Seconds(0)),
        m_roundMessageCount(0),
        m_totalMessageCount(0),
        m_messageRelayCount(0),
        m_transactionStartTimes(),
        m_transactionEndTimes()
    {
        // 初始化交易数组
    //for (uint32_t i = 0; i < NETWORK_SIZE; ++i) {
    for (uint32_t i = 0; i < N; ++i) {
            transactions[i].view = 0;
            transactions[i].value = 0;
            transactions[i].prepare_vote = 0;
            transactions[i].commit_vote = 0;
        }
    }

    NodeApp::~NodeApp(void){
        NS_LOG_FUNCTION(this);
    }
    Time round_start_time;
    Time round_end_time;
    Time total_time = Seconds(0); // 用于累加所有轮次的总耗时
    Time latency_start_time;
    Time latency_end_time;
    int round_message_count = 0;  // 当前轮次的消息数量
    int total_message_count = 0;  // 所有轮次的总消息数量
    int message_copies_count = 0; // 所有消息副本的数量
    void NodeApp::StartApplication() {
        std::srand(static_cast<unsigned int>(time(0)));
    
        // 记录模拟器开始时间
        latency_start_time = Simulator::Now();
        NS_LOG_INFO("模拟器开始时间：" << latency_start_time.GetSeconds());
    
        // 确保 socket 被正确创建
        if (!m_socket) {
            TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
            m_socket = Socket::CreateSocket(GetNode(), tid);
            if (!m_socket) {
                NS_LOG_ERROR("Failed to create m_socket!");
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
        NS_LOG_INFO("node" << m_id << " start");
        printInformation();
        // 确保 m_peersAddresses 不是空的
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
        // 只有 leader 才会触发 initiateRound()
        if (is_leader == 1) {
            Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::initiateRound, this);
        }
        
        // 设置DOS攻击参数（默认禁用）
        std::vector<int> maliciousNodes = {5, 6}; // 节点5和6是恶意节点
        SetupDosAttack(false, 30, 1000, maliciousNodes, 20); // 第30轮，发送100次攻击，阈值20

    }
    

    void NodeApp::StopApplication(){
        // if (is_leader == 1)    {
        //     NS_LOG_INFO("At time " << Simulator::Now().GetSeconds() << " Stop");
        // }
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
            
            double TPS = round_number*1000 / (total_time.GetSeconds()*N);

            NS_LOG_INFO("所有共识的总时长：" << total_time.GetSeconds() << " ms.");
            NS_LOG_INFO("交易吞吐量: " << TPS << "tps");

            //计算平均交易时延
            Time totalLantency=latency_end_time-latency_start_time;
            //double avgLantency = totalLantency.GetSeconds()*NETWORK_SIZE / round_number;
            double avgLantency = totalLantency.GetSeconds()*N / round_number;

            NS_LOG_INFO("总时延" << totalLantency.GetSeconds() << "ms.");
            NS_LOG_INFO("平均交易时延：" << avgLantency << "ms");

            //计算消息总数
            NS_LOG_INFO("平均消息副本数量：" << message_copies_count << "次");

            //计算通信开销
            double total_comm_cost = (total_message_count+round_number)*49*1.0/1024;
            NS_LOG_INFO("总消息数量：" << total_message_count << "次");
            NS_LOG_INFO("总通信开销：" << total_comm_cost << "KB");

            EvaluateAttackResult();

            //使用ns-3的Stop方法"优雅"地停止模拟器
            Simulator::Stop();
            return;
            
            //exit(0);
        }

        // 2. Hit the possibility of view change
        if (rand()%3==0 && view_is_changed==0){
            changeView();
            return;
        } else{
            // ("Current Leader Id => " << leader_id << "\n\n");
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
            //random_client = (rand() % NETWORK_SIZE);
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
        if (m_enableDosAttack && round_number == m_dosAttackRound) {
            NS_LOG_INFO("节点" << m_id << "准备在第" << round_number << "轮发起DOS攻击");
            LaunchDosAttack(5); // 使用当前节点ID
        }
    }

    // Handle incomming messages and Parse them in different states
    void NodeApp::HandleRead(Ptr<Socket> socket) {
        if (!socket) {
            NS_LOG_ERROR("Null socket in HandleRead");
            return;
        }
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

                NS_LOG_INFO(state<<"======>"<<msg<<"-=====>"<<m_id<<"====>"<<client_id);
        
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
                        // 记录开始时间
                        round_start_time = Simulator::Now();
                        NS_LOG_WARN("共识开始时间：" << round_start_time.GetSeconds());

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
                        //以下添加了一下if的判断
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
                            //if (count >= static_cast<int>(NETWORK_SIZE/2 + 1)){
                            if (count >= static_cast<int>(N/2 + 1)){
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
                        //以下加一个if判断             
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
                        //if (count >= static_cast<int>(NETWORK_SIZE/2 + 1))
                        if (count >= static_cast<int>(N/2 + 1))
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
                            //NS_LOG_INFO("\n\n");  
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
                        //
                        NS_LOG_INFO("===========================================================\n\n");

                        // 2. Start a new round after all replys arrived (by a larger delay to make sure last round is finished)
                        //if(reply_count==NETWORK_SIZE-1){
                        if(reply_count==N-1){
                            // 记录结束时间
                            round_end_time = Simulator::Now();
                            latency_end_time = Simulator::Now();
                            NS_LOG_WARN("共识结束时间：" << round_end_time.GetSeconds());
                            NS_LOG_WARN("模拟器结束时间：" << latency_end_time.GetSeconds());
                            // 计算当前轮次的耗时
                            Time round_duration = round_end_time - round_start_time;
                            total_time += round_duration;  // 累加总耗时
                            NS_LOG_INFO("Round completed in " << round_duration.GetSeconds() << " seconds.");
                            
                            // 计算当前轮次的消息数量（根据各阶段的消息数量进行加和）
                            round_message_count = request_count + preprepare_count + prepare_count + commit_count + reply_count;
                            message_copies_count += preprepare_count + prepare_count + commit_count;
                            total_message_count += round_message_count;  // 累加总消息数量
                            NS_LOG_WARN("request阶段：" << request_count);
                            NS_LOG_WARN("preprepare阶段：" << preprepare_count);
                            NS_LOG_WARN("prepare阶段：" << prepare_count);
                            NS_LOG_WARN("commit阶段：" << commit_count);
                            NS_LOG_WARN("reply_count阶段：" << reply_count);
                            NS_LOG_WARN("中间三阶段消息副本数：" << preprepare_count + prepare_count + commit_count);
                            NS_LOG_WARN("每一轮消息总数：" << round_message_count);
                            
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
                        //if(view_is_changed==NETWORK_SIZE){
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
    void NodeApp::SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p) {
        socketClient->Send(p);
    }

    // Convert string message to unit_8 type and broadcast it
    void NodeApp::sendStringMessage(std::string message) {
        std::vector<uint8_t> myVector(message.begin(), message.end());
        uint8_t* d = &myVector[0];
        NodeApp::SendTX(d, sizeof(message));    
    }

    void NodeApp::SendGossip(unsigned char* data, int size, double delay) {
        std::vector<Ipv4Address> selectedPeers = SelectGossipPeers();
        
        for (const auto& peer : selectedPeers) {
            Ptr<Packet> p = Create<Packet>(reinterpret_cast<const uint8_t*>(data), size);
            Ptr<Socket> socketClient = m_peersSockets[peer];
            
            if (socketClient) {
                Simulator::Schedule(Seconds(delay), &NodeApp::SendPacket, this, socketClient, p);
            }
        }
    }

    // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTX(uint8_t data[], int size){
        double delay = getRandomDelay();
        SendTXWithDelay(data, size, delay);
    }
    
    // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTXWithDelay(unsigned char* data, int size, double delay) {
        // [新增] 检查 m_peersSockets 是否为空
        if (m_peersSockets.empty()) {
            NS_LOG_ERROR("Cannot send message, m_peersSockets is empty!");
            return;
        }
        Ptr<Packet> p;
        p = Create<Packet>(
            // [修改] 类型转换 data 为 const uint8_t*
            reinterpret_cast<const uint8_t*>(data), size
        );
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        // [修改] 遍历方式从迭代器改为基于范围的 for 循环
        for (const auto& peerPair : m_peersSockets) {
            // [新增] 检查单个 socket 是否为空
            if (!peerPair.second) {
                NS_LOG_WARN("Skipping invalid socket for peer");
                continue;
            }
            // [保留] 获取 socket
            Ptr<Socket> socketClient = peerPair.second;
            Simulator::Schedule(Seconds(delay), &NodeApp::SendPacket, this, socketClient, p);
        }
    }
    


    /*******************************UTILS*******************************/
    char NodeApp::convertIntToChar(int a) {
        return a + '0';
    }

    int NodeApp::convertCharToInt(char a) {
        return a - '0';
    }

    float NodeApp::getRandomDelay() {
        return (rand() % 6) * 1.0 / 1000;
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

    void NodeApp::log_message_counts(){
        //NS_LOG_INFO("Request count=> "<<request_count<<"    Pre-prepare count=> "<<preprepare_count<<"   Prepare count=> "<<prepare_count<<"   Commit count=> "<<commit_count<<"   Reply count=> "<<reply_count);
    }

    // Gossip 协议方法实现
    std::vector<Ipv4Address> NodeApp::SelectGossipPeers() {
        std::vector<Ipv4Address> selectedPeers;
        std::vector<Ipv4Address> availablePeers = m_peersAddresses;
        
        // 随机打乱可用节点列表
        std::random_shuffle(availablePeers.begin(), availablePeers.end());
        
        // 选择 m_gossipFanout 个节点
        int peersToSelect = std::min(m_gossipFanout, static_cast<int>(availablePeers.size()));
        selectedPeers.assign(availablePeers.begin(), availablePeers.begin() + peersToSelect);
        
        return selectedPeers;
    }

    bool NodeApp::ShouldRelay(const std::string& messageId) {
        // 如果消息已处理，则不再转发
        if (m_processedMessages.find(messageId) != m_processedMessages.end()) {
            return false;
        }
        
        // 记录已处理消息
        m_processedMessages.insert(messageId);
        return true;
    }

    // Gossip 协议参数设置方法
    void NodeApp::SetGossipFanout(int fanout) {
        m_gossipFanout = fanout;
    }

    int NodeApp::GetGossipFanout() const {
        return m_gossipFanout;
    }

    void NodeApp::SetGossipRounds(int rounds) {
        m_gossipRounds = rounds;
    }

    int NodeApp::GetGossipRounds() const {
        return m_gossipRounds;
    }

    // 性能指标计算方法
    double NodeApp::CalculateAverageLatency() {
        if (m_transactionStartTimes.empty() || m_transactionEndTimes.empty()) {
            return 0.0;
        }
        
        double totalLatency = 0.0;
        for (size_t i = 0; i < m_transactionStartTimes.size(); ++i) {
            totalLatency += (m_transactionEndTimes[i] - m_transactionStartTimes[i]).GetSeconds();
        }
        
        return totalLatency / m_transactionStartTimes.size();
    }

    void NodeApp::SubmitTransaction(uint32_t transactionId) {
        m_transactionStartTimes.push_back(Simulator::Now());
    }

    void NodeApp::ConfirmTransaction(uint32_t transactionId) {
        m_transactionEndTimes.push_back(Simulator::Now());
    }

    double NodeApp::CalculateTPS() {
        if (m_transactionStartTimes.empty()) {
            return 0.0;
        }
        
        Time totalTime = m_transactionEndTimes.back() - m_transactionStartTimes.front();
        return m_transactionStartTimes.size() / totalTime.GetSeconds();
    }

    // 设置和获取节点相关参数的方法
    void NodeApp::SetPeersAddresses(std::vector<Ipv4Address> peers) {
        m_peersAddresses = peers;
    }

    void NodeApp::SetNodeInternetAddress(Ipv4Address internet) {
        m_local = internet;
    }

    void NodeApp::SetNodeId(uint8_t id) {
        m_id = id;
    }

    void NodeApp::SetIsLeader(uint8_t flag) {
        is_leader = flag;
    }

    void NodeApp::SetLeaderId(uint8_t id) {
        leader_id = id;
    }

    Ipv4Address NodeApp::GetNodeInternetAddress() const {
        return Ipv4Address::ConvertFrom(m_local);
    }

    uint8_t NodeApp::GetNodeId() const {
        return m_id;
    }

    uint8_t NodeApp::GetIsLeader() const {
        return is_leader;
    }

    void NodeApp::SetClientId(uint8_t id) {
        client_id = id;
    }

    uint8_t NodeApp::GetClientId() const {
        return client_id;
    }

    void NodeApp::LaunchDosAttack(int m_id) {
        if (!m_enableDosAttack) {
            return;
        }
        
        NS_LOG_INFO("恶意节点" << m_id << "开始发起DOS洪范攻击,目标是主节点" << leader_id);
        NS_LOG_INFO("主节点" << leader_id << "开始检测来自节点" << m_id << "的消息");
        // 发送多次攻击消息
        for (int i = 0; i < m_dosAttackCount; i++) {
            // 使用较小的延迟，模拟短时间内的大量请求
            SendDosAttackMessage(m_id);
            DetectDosAttack(m_id);
        }
        NS_LOG_INFO("恶意节点" << m_id << "完成DOS洪范攻击");
    }

    void NodeApp::DetectDosAttack(int attackerId) {        
        // 获取最近收到的消息
        std::string lastMessage = m_lastReceivedMessage[attackerId];
        
        // 检查消息是否正确(检查签名)
        bool isValidMessage = (lastMessage[6] == '1');
        
        // 获取当前时间
        Time now = Simulator::Now();
        m_lastAttackDetectionTime = now;
                
        if (!isValidMessage) {
            DOS_successful_count++;
            NS_LOG_INFO("主节点检测到DOS攻击");
        }

    }

    void NodeApp::SendDosAttackMessage(int m_id) {
        std::string data[7];
        
        double probability  = 0.988+N*0.0002;
        bool sendValidMessage = (rand() / (RAND_MAX + 1.0)) < probability;

        if (sendValidMessage) {
            // 构造正确的消息
            data[0] = convertIntToChar(1); // 有效值
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(view_number);
            data[5] = convertIntToChar(m_sequenceNumber++); // 正确的序列号
            data[6] = '1'; // 添加签名
        } else {
            // 构造错误的消息
            data[0] = convertIntToChar(rand() % 9); // 随机值
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(rand() % 100); // 随机视图编号
            data[5] = convertIntToChar(rand() % 100); // 随机序列号
            data[6] = '0'; // 不添加签名
        }
        
        // 将数组转换为字符串
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        
        // 发送消息给主节点
        if (m_peersSockets.find(m_peersAddresses[leader_id]) != m_peersSockets.end()) {
            Ptr<Socket> leaderSocket = m_peersSockets[m_peersAddresses[leader_id]];
            std::vector<uint8_t> myVector(dataString.begin(), dataString.end());
            uint8_t* d = &myVector[0];
            
            Ptr<Packet> p = Create<Packet>(reinterpret_cast<const uint8_t*>(d), dataString.size());
            leaderSocket->Send(p);
            
            // 保存最近发送的消息用于检测
            m_lastReceivedMessage[m_id] = dataString;
            
            NS_LOG_INFO("攻击者节点" << m_id << "向主节点" << leader_id << "发起了DOS攻击");
        }
    }

    void NodeApp::EvaluateAttackResult() {
        NS_LOG_INFO("DOS攻击结果评估:");
        double DOS_successful_rate = static_cast<double>(DOS_successful_count) / m_dosAttackCount;
        NS_LOG_INFO("DOS攻击成功率:" << DOS_successful_rate*100 << "%");
        NS_LOG_INFO("DOS攻击成功次数:" << DOS_successful_count);
        NS_LOG_INFO("DOS攻击总次数:" << m_dosAttackCount);
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
        m_attackDetectionWindow = 1000; // 1秒内检测
        m_lastAttackDetectionTime = Simulator::Now();
        
        // 初始化接收攻击计数器
        for (int i = 0; i < N; i++) {
            m_receivedAttackCount[i] = 0;
        }
    }

} // namespace ns3
