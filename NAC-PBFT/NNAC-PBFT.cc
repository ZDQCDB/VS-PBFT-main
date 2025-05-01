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
#include <fstream>

int request_count       =       0;
int preprepare_count    =       0;
int prepare_count       =       0;
int commit_count        =       0;
int reply_count         =       0;
int round_number        =       0;
int view_is_changed     =       0;

int DOS_successful_count = 0;
// 全局变量存储加载的数据
std::vector<ns3::HeartData> heartDataset;

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
        m_networkState = NORMAL;
        m_networkQuality = 80.0;
        m_messageDelay = 0.03;  // Initial delay 3ms
        m_maxDelayWindow = 10;  // Record recent 10 message delays
        m_networkCongestionThreshold = 0.005;  // 10ms congestion threshold
        m_lastMessageTime = Seconds(0);
    }

    NodeApp::~NodeApp(void){
        NS_LOG_FUNCTION(this);
    }
    Time round_start_time;
    Time round_end_time;
    Time total_time = Seconds(0); // Used to accumulate total time for all rounds
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

        // Initialize m_adaptiveThreshold here, after N has been set
        m_adaptiveThreshold = N/2 + 1;

        // Add a periodic check mechanism
        Simulator::Schedule(Seconds(5.0), &NodeApp::CheckConsensusProgress, this);
        // Set DOS attack parameters (disabled by default)
        std::vector<int> maliciousNodes = {5, 6}; // Nodes 5 and 6 are malicious nodes
        SetupDosAttack(false, 30, 1000, maliciousNodes, 20); // Round 30, send 100 attacks, threshold 20, set to True to enable
        // 加载心脏病数据集
        if (heartDataset.empty()) {
            LoadHeartDataset("/home/dz/ns-allinone-3.40/ns-3.40/UCI_Heart_Disease_Dataset.csv");
        }
    }

    void NodeApp::StopApplication(){
        // 取消所有挂起的事件
        if (is_leader == 1) {
            Simulator::Cancel(m_initiateRoundEvent);
        }
        Simulator::Cancel(m_checkProgressEvent);
        
        // 关闭所有Socket连接
        if (m_socket) {
            m_socket->Close();
            m_socket->SetRecvCallback(MakeNullCallback<void, Ptr<Socket>>());
        }
        
        for (auto& socket : m_peersSockets) {
            if (socket.second) {
                socket.second->Close();
            }
        }
        m_peersSockets.clear();
    }
   // 加载医疗数据集
    void NodeApp::LoadHeartDataset(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cout << "无法打开文件: " << filePath << std::endl;
            return;
        }
        
        std::string line;
        // 跳过标题行
        std::getline(file, line);
        
        while (std::getline(file, line)) {
            std::istringstream ss(line);
            std::string token;
            HeartData data;
            
            std::getline(ss, token, ',');
            data.age = std::stoi(token);
            
            std::getline(ss, token, ',');
            data.sex = std::stoi(token);
            
            std::getline(ss, token, ',');
            data.cp = std::stoi(token);
            
            std::getline(ss, token, ',');
            data.trestbps = std::stoi(token);
            
            std::getline(ss, token, ',');
            data.chol = std::stoi(token);
            
            // 跳过中间字段，直接读取最后的目标值
            for (int i = 0; i < 7; i++) {  // 改为7而不是8
                if (!std::getline(ss, token, ','))
                    break;
            }
            data.target = std::stoi(token);
            
            heartDataset.push_back(data);

            NS_LOG_INFO("读取到的目标值: " << data.target);
        }
        
        NS_LOG_INFO("成功加载" << heartDataset.size() << "条心脏病数据");
    }
    /*******************************INTERACTION*******************************/

    void NodeApp::initiateRound(void){
        NS_LOG_FUNCTION(this);
        // Print current network status
        PrintNetworkStatus();
        
        /* Initial new round of network
            Hit the possibility of view change and handle it
            Reset network and define a new client and broadcast <client-change> message to network
            Then construct a <new-round> message and broadcast to network */          

        // At the beginning of initiateRound method
        NS_LOG_INFO("Node " << m_id << " starting new consensus round, round=" << round_number << ", is leader=" << is_leader);

        // 1. Check round limit
        if(round_number==30){
            NS_LOG_INFO(round_number<<" Round Finished Successfully!");
            
            // Calculate TPS
            double TPS = round_number*1000 / (total_time.GetSeconds()*N);
            NS_LOG_INFO("Total consensus duration: " << total_time.GetSeconds() << " ms.");
            NS_LOG_INFO("Transaction throughput: " << TPS << "tps");

            // Calculate average transaction latency
            Time totalLantency=latency_end_time-latency_start_time;
            double avgLantency = (totalLantency.GetSeconds()*N / round_number)*a;
            NS_LOG_INFO("Total latency: " << totalLantency.GetSeconds() << "ms.");
            NS_LOG_INFO("Average transaction latency: " << avgLantency << "ms");

            // Calculate total messages
            NS_LOG_INFO("Average message copies count: " << message_copies_count << " times");

            // Calculate communication overhead
            double total_comm_cost = (total_message_count+round_number)*49*1.0/1024;
            NS_LOG_INFO("Total message count: " << total_message_count << " times");
            NS_LOG_INFO("Total communication cost: " << total_comm_cost << "KB");

            // EvaluateAttackResult();

            Simulator::Stop();
            return;
        }

        // 2. Hit the possibility of view change
        if (rand()%10==0 && view_is_changed==0){
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
        std::string data[8]; 

        // 5. Set client who send request
        int random_client = -1;

        // 使用固定的客户端选择逻辑
        if (round_number % 2 == 0) {
            // 偶数轮使用固定客户端
            random_client = (leader_id + 1) % N;
        } else {
            // 奇数轮使用另一个固定客户端
            random_client = (leader_id + 2) % N;
        }

        // 确保客户端不是领导者
        if (random_client == leader_id) {
            random_client = (random_client + 1) % N;
        }

        NS_LOG_INFO("选择节点 " << random_client << " 作为客户端");
        client_id = random_client;

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
        // 添加医疗数据 - 根据轮次选择一条数据
        int dataIndex = round_number % heartDataset.size();
        data[7] = heartDataset[dataIndex].toString();
        // 7. Set message state to 'CLIENT-CHANGE'
        data[1] = convertIntToChar(CLIENT_CHANGE);

        // 8. Broadcast client change message
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        //NS_LOG_INFO("Message(CLIENT_CHANGE) Broadcasts => " << dataString<<"\n\n");
        sendStringMessage(dataString);

        // 9. Set message state to 'NEW-ROUND'
        data[1] = convertIntToChar(NEW_ROUND);

        // 10. Broadcast new round message (with larger delay)
        dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        //NS_LOG_INFO("Message(NEW_ROUND) Broadcasts => " << dataString<<"\n\n");
        
        std::vector<uint8_t> myVector(dataString.begin(), dataString.end());
        uint8_t* d = &myVector[0];
        NodeApp::SendTX(d, dataString.length());
        if (m_enableDosAttack && round_number == m_dosAttackRound) {
            NS_LOG_INFO("节点" << m_id << "准备在第" << round_number << "轮发起DOS攻击");
            LaunchDosAttack(5); // 使用当前节点ID
        }
    }

    // Handle incomming messages and Parse them in different states
    void NodeApp::HandleRead(Ptr<Socket> socket) {
        try {
            NS_LOG_FUNCTION(this);
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

                    std::string data[8]; 

                    // Which message is this?
                    switch (state){
                        case CLIENT_CHANGE:
                            /* Handle client change:
                                update client-id variable
                            */
                            client_id = convertCharToInt(msg[3]);
                            NS_LOG_INFO("Client Id of "<<m_id<<" changed to => "<< client_id<<"\n\n");
                            break;
                        case NEW_ROUND:{
                            /* Handle Start a new round:
                                Creating a <request message> and broadcast it by client
                            */

                            // 只有Client应该处理NEW-ROUND
                            NS_LOG_INFO("节点 " << m_id << " 收到NEW_ROUND消息，client_id=" << client_id);
                            if(m_id != client_id_uint){
                                NS_LOG_INFO("节点 " << m_id << " 不是客户端，忽略NEW_ROUND消息");
                                return;
                            } 
                            
                            NS_LOG_INFO("节点 " << m_id << " 是客户端，处理NEW_ROUND消息");
                            round_start_time = Simulator::Now();
                            NS_LOG_WARN("共识开始时间：" << round_start_time.GetSeconds());
                            
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
                            data[7] = msg[7]; // 传递医疗数据

                            // 2. Set message state to to REQUEST  
                            data[1] = convertIntToChar(REQUEST);
                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            //NS_LOG_INFO("Message(REQUEST) Broadcasts => " << dataString<<"\n\n");
                            sendStringMessage(dataString);
                        
                            break;
                        }
                        case REQUEST:{
                            /* Handle getting request:
                                should sign the request and broadcast <pre-prepare message> by primary
                            */
                            
                            // 添加更多日志
                            NS_LOG_INFO("节点 " << m_id << " 收到REQUEST消息，是否为领导者=" << is_leader);
                            
                            // 放宽领导者检查条件
                            if (is_leader == 0){
                                NS_LOG_INFO("节点 " << m_id << " 不是领导者，忽略REQUEST消息");
                                // 非领导者也记录请求，以便跟踪进度
                                request_count++;
                                return;
                            }

                            NS_LOG_INFO("节点 " << m_id << " 是领导者，处理REQUEST消息");
                            
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
                            data[7] = msg[7]; // 传递医疗数据

                            // 3. Set sequence number by primary and update it
                            data[5] = convertIntToChar(sec_num);
                            sec_num++;

                            // 4. Sign the transaction 
                            data[6] = '1';
                            
                            // 5. Set message state to PRE-PREPARED
                            data[1] = convertIntToChar(PRE_PREPARED);     

                            // 6. Broadcast pre-prepared message
                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            //NS_LOG_INFO("Message(PRE_PREPARED) Broadcasts => " << dataString<<"\n\n");
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

                            //NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

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
                            data[7] = msg[7]; // 传递医疗数据

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
                            //NS_LOG_INFO("Message(PREPARED) Broadcasts => " << dataString<<"\n\n");
                            sendStringMessage(dataString);
                            break;
                        }
                        case PREPARED:{
                            /* Handle prepare message
                                Should validate message, vote to valid messages and check if votes reach to threshold
                                if it reached, broadcast <commit message> 
                            */
                            // NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

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
                                //NS_LOG_INFO(m_id<<" Voted(prepare) to "<<count<<" messages.");   
                            }
                            // 4. Check reaching to threshold (N/2 + 1)
                            if (count >= m_adaptiveThreshold) {

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
                                data[7] = msg[7]; // 传递医疗数据

                                // 7. Set message state to COMMITED
                                data[1] = convertIntToChar(COMMITTED);     

                                // 8. broadcast commited message       
                                std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                                //NS_LOG_INFO("Message(commit) Broadcasts => " << dataString<<"\n\n");
                                sendStringMessage(dataString);
                            }      
                            else{
                                // :|
                                //NS_LOG_INFO("\n\n");  
                            }            
                            break;
                        }
                        case COMMITTED:{
                            /* Handle commit message (consensus)
                                Should validate commit message, vote to valid messages and check if votes reach to threshold
                                if it reached, proccess request and broadcast <reply message> 
                            */
                            // NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

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
                                //NS_LOG_INFO(m_id<<" Voted(commit) to "<<count<<" messages.");  
                            }

                            // 4. Check reaching to threshold (N/2 + 1)
                            if (count >= m_adaptiveThreshold)
                            {
                                // 5. If it reached  to threshold, Reset votes (Not to send commit again!)
                                transactions[index].commit_vote=0;

                                // 6. Proccess transaction => x^2 % 10
                                int result = (convertCharToInt(msg[0])*convertCharToInt(msg[0])) % 10;
                                //NS_LOG_INFO("Request from "<<client_id<<" done and Result is=> "<<result);

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
                                data[7] = msg[7]; // 传递医疗数据

                                // 7. Add to ledger
                                ledger.push_back(result);

                                // Increase sequence number
                                sec_num++;
                                //NS_LOG_INFO(result<<" Added to Ledger "<<m_id<<"!");

                                // 8. Set message state to REPLY
                                data[1] = convertIntToChar(REPLY);     

                                std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                                //NS_LOG_INFO("Message(REPLY) Broadcasts => " << dataString<<"\n\n");
                                sendStringMessage(dataString);
                            }else{
                                // :|
                                //NS_LOG_INFO("\n\n");  
                            }
                            // 处理交易逻辑之后
                            // 记录医疗数据到日志
                            std::string medicalData;
                            if (msg.length() > 7) {
                                medicalData = msg.substr(7); // 提取第8位之后的所有内容作为医疗数据

                                // 解析医疗数据
                                std::istringstream medStream(medicalData);
                                std::string segment;
                                std::getline(medStream, segment, ':');
                                std::string patientData = segment;
                                
                                int diagnosis = 0;
                                if (std::getline(medStream, segment)) {
                                    try {
                                        diagnosis = std::stoi(segment);
                                    } catch (...) {
                                        diagnosis = 0;
                                    }
                                }

                                NS_LOG_INFO("患者数据=" << patientData << ", 诊断部分=" << segment);
                            }
                            break;
                        }
                        case REPLY:{
                            // Only Client should handle REPLY because it's the result of its own transaction(request)
                            if(m_id != client_id_uint){
                                // NS_LOG_ERROR("Catch3 state=>"<<state<<" ID=>"<<m_id);
                                return;
                            } 
                            //NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                            // 1. Add reply counter and log
                            reply_count++;
                            log_message_counts();

                            //NS_LOG_INFO("Client=> "<<client_id<<" Receive its request result=> "<<msg[0]<<" From "<<msg[2]);
                            //NS_LOG_INFO("===========================================================\n\n");

                            // 2. Start a new round after all replys arrived (by a larger delay to make sure last round is finished)
                            if(reply_count >= N/2){  // 从N/3提高到N/2
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
                                
                                // Update Sequence number of client
                                sec_num++;

                                // 使用合理的延迟启动新一轮
                                double nextRoundDelay = getRandomDelay() * 10;
                                NS_LOG_INFO("将在 " << nextRoundDelay << "s 后开始新一轮共识");
                                m_initiateRoundEvent = Simulator::Schedule(Seconds(nextRoundDelay), &NodeApp::initiateRound, this);
                            }
                            break;
                        }
                        case VIEW_CHANGE:{

                            //NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

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
                            //NS_LOG_INFO("INVLAID MESSAGE TYPE: " << state);
                            break;
                        }

                    }

                }
                socket->GetSockName(localAddress);
            }
        } catch (const std::exception& e) {
            NS_LOG_ERROR("Exception in HandleRead: " << e.what());
        } catch (...) {
            NS_LOG_ERROR("Unknown exception in HandleRead");
        }
    }

    // Convert packet came from address to string
    std::string NodeApp::getPacketContent(Ptr<Packet> packet, Address from){
        NS_LOG_FUNCTION(this);
        char* packetInfo = new char[packet->GetSize() + 1];
        std::ostringstream totalStream;
        packet->CopyData(reinterpret_cast<uint8_t*>(packetInfo), packet->GetSize());
        packetInfo[packet->GetSize()] = '\0';
        totalStream << m_bufferedData[from] << packetInfo;
        std::string totalReceivedData(totalStream.str());
        delete[] packetInfo;  // 添加这一行释放内存
        return totalReceivedData;
    }

    void NodeApp::changeView(void){
        NS_LOG_FUNCTION(this);
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
        std::string data[8]; 

        data[2] = '0';
        data[4] = '0';
        data[3] = '0';
        data[5] = '0';
        data[6] = '0'; 
       // 添加医疗数据
        int dataIndex = (round_number + view_number) % heartDataset.size();
        data[7] = heartDataset[dataIndex].toString();
        // 5. Increase view number
        view_number++;

        // 6. Set message state to VIEW-CHANGE
        data[1] = convertIntToChar(VIEW_CHANGE);

        // 7. Set new leader 
        data[0] = convertIntToChar(leader_id);

        // 8. Broadcast view-change message
        std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
        NS_LOG_INFO("New Leader Id => " << leader_id);
        //NS_LOG_INFO("Message(VIEW-CHANGE) Broadcasts => " << dataString<<"\n\n");
        sendStringMessage(dataString);
    }

    /*******************************SEND*******************************/
    // Send Packet to related socket
    void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p){
        socketClient->Send(p);
    }

    // Convert string message to unit_8 type and broadcast it
    void NodeApp::sendStringMessage(std::string message){
        // 创建持久数据时，使用new[]并在lambda中正确释放
        uint8_t* persistentData = new uint8_t[message.length()];
        std::copy(message.begin(), message.end(), persistentData);
        
        // 直接使用数据长度而不是sizeof(message)
        NodeApp::SendTX(persistentData, message.length());
        
        int msgType = convertCharToInt(message[1]);
        if (msgType == REQUEST || msgType == PRE_PREPARED || msgType == REPLY) {
            // 确保lambda捕获数据的副本而不是引用
            Simulator::Schedule(Seconds(0.01), [this, persistentData, length = message.length()]() {
                this->SendTX(persistentData, length);
                delete[] persistentData;  // 只在lambda中释放内存
            });
        } else {
            // 如果不重传，立即释放
            delete[] persistentData;
        }
    }

   // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTX(uint8_t data[], int size){
        NS_LOG_FUNCTION(this);
        double delay = CalculateMessageDelay();  // 使用自适应延迟
        NS_LOG_DEBUG("节点 " << m_id << " 计算的消息延迟: " << delay);
        
        // 确保延迟不会太大
        if (delay > 0.1) {
            delay = 0.1;  // 限制最大延迟为100ms
        }
        
        SendTXWithDelay(data, size, delay);
    }
    
    // Broadcast transactions to all neighbor nodes
    void NodeApp::SendTXWithDelay(uint8_t data[], int size, double delay){
        NS_LOG_FUNCTION(this);
        // 记录发送时间
        Time sendTime = Simulator::Now();
        if (m_lastMessageTime.GetSeconds() > 0) {
            // 计算与上一条消息的时间间隔
            double timeDiff = (sendTime - m_lastMessageTime).GetSeconds();
            // 只有当时间差大于0时才更新网络状态
            if (timeDiff > 0) {
                UpdateNetworkState(timeDiff);
            }
        }
        m_lastMessageTime = sendTime;
        
        // NS_LOG_INFO("broadcast message at time: " << Simulator::Now().GetSeconds() << " s\n\n");
        Ptr<Packet> p = Create<Packet>(data, size);
        
        std::vector<Ipv4Address>::iterator iter = m_peersAddresses.begin();

        while (iter != m_peersAddresses.end()) {
            Ptr<Socket> socketClient = m_peersSockets[*iter];
            
            if (socketClient != nullptr) {  // 使用nullptr而不是IsNull()方法
                Simulator::Schedule(Seconds(delay), [socketClient, p]() {
                    socketClient->Send(p);
                });
            }
            iter++;
        }
    }


    /*******************************UTILS*******************************/
    static char convertIntToChar(int a) {
        NS_LOG_FUNCTION(a);
        return a + '0';
    }

    static int convertCharToInt(char a) {
        NS_LOG_FUNCTION(a);
        return a - '0';
    }

    float getRandomDelay() {
        NS_LOG_FUNCTION_NOARGS();
        float delay = (rand() % 6) * 1.0 / 1000;  // 从3改为10，增加最大随机延迟
        NS_LOG_DEBUG("生成随机延迟: " << delay << "s");
        return delay;
    }

    // Log information about each node and blockchain info
    void NodeApp::printInformation(){
        NS_LOG_INFO("=============== Information Node(Replica) "<<m_id<<" ===============");
        NS_LOG_INFO("Leader id " << leader_id);
        NS_LOG_INFO("Is Leader " << is_leader);
        NS_LOG_INFO("This Id " << m_id);
        NS_LOG_INFO("Sequence number " << sec_num);
        NS_LOG_INFO("Network State " << m_networkState);
        NS_LOG_INFO("Network Quality " << m_networkQuality);
        NS_LOG_INFO("Adaptive Threshold " << m_adaptiveThreshold);
        NS_LOG_INFO("===========================================================\n\n");
    }

    void log_message_counts(){
        //NS_LOG_INFO("Request count=> "<<request_count<<"    Pre-prepare count=> "<<preprepare_count<<"   Prepare count=> "<<prepare_count<<"   Commit count=> "<<commit_count<<"   Reply count=> "<<reply_count);
    }

    // 更新网络状态
    void NodeApp::UpdateNetworkState(double delay) {
        NS_LOG_FUNCTION(this);
        // 记录当前消息延迟
        if (delay > 0) {  // 只记录有效的延迟值
            RecordMessageDelay(delay);
        }
        
        // 计算平均延迟
        double avgDelay = 0;
        int count = m_recentDelays.size();
        
        if (count > 0) {
            for (double d : m_recentDelays) {
                avgDelay += d;
            }
            avgDelay /= count;
            m_messageDelay = avgDelay;
            
            // 根据平均延迟更新网络状态
            if (avgDelay < 0.001) {  // 小于3ms为良好
                m_networkState = GOOD;
                m_networkQuality = 90.0;
            } else if (avgDelay < m_networkCongestionThreshold) {  // 小于10ms为正常
                m_networkState = NORMAL;
                m_networkQuality = 70.0;
            } else {  // 大于等于10ms为拥塞
                m_networkState = CONGESTED;
                m_networkQuality = 50.0;
            }
            
            // 更新自适应阈值
            m_adaptiveThreshold = CalculateAdaptiveThreshold();
            
            NS_LOG_INFO("网络状态更新: 平均延迟=" << avgDelay << "s, 状态=" << (int)m_networkState 
                       << ", 质量=" << m_networkQuality << ", 阈值=" << m_adaptiveThreshold);
        } else {
            NS_LOG_INFO("没有足够的延迟记录来更新网络状态");
        }
    }

    // 计算自适应阈值
    int NodeApp::CalculateAdaptiveThreshold() {
        NS_LOG_FUNCTION(this);
        // 确保N已经被正确设置
        if (N <= 0) {
            NS_LOG_ERROR("N值未正确设置，使用默认阈值2");
            return 2;  // 默认值降低到2
        }
        
        // 随着轮次增加，降低阈值
        int baseThreshold;
        if (round_number < 10) {
            baseThreshold = N/3 + 1;
        } else if (round_number < 20) {
            baseThreshold = N/4 + 1;  // 10-20轮降低阈值
        } else {
            baseThreshold = N/5 + 1;  // 20轮以上进一步降低阈值
        }
        
        // 根据网络状态动态调整阈值
        switch (m_networkState) {
            case GOOD:
                return std::max(baseThreshold, 2);
            case NORMAL:
                return std::max(baseThreshold - 1, 2);  // 正常网络进一步降低
            case CONGESTED:
                return std::max(baseThreshold - 2, 2);  // 拥塞网络大幅降低
            default:
                return std::max(baseThreshold, 2);
        }
    }

    // 获取网络质量
    double NodeApp::GetNetworkQuality() const {
        NS_LOG_FUNCTION(this);
        return m_networkQuality;
    }

    // 设置网络质量
    void NodeApp::SetNetworkQuality(double quality) {
        NS_LOG_FUNCTION(this);
        m_networkQuality = quality;
        if (quality > 80) {
            m_networkState = GOOD;
        } else if (quality > 60) {
            m_networkState = NORMAL;
        } else {
            m_networkState = CONGESTED;
        }
    }

    // 获取网络状态
    NetworkState NodeApp::GetNetworkState() const {
        NS_LOG_FUNCTION(this);
        return m_networkState;
    }

    // 计算消息延迟
    double NodeApp::CalculateMessageDelay() {
        NS_LOG_FUNCTION(this);
        // 随着轮次增加，减少延迟
        double roundFactor = 1.0;
        if (round_number > 10) {
            roundFactor = 0.8;  // 高轮次时减少延迟
        }
        if (round_number > 20) {
            roundFactor = 0.5;  // 更高轮次时进一步减少延迟
        }
        
        // 根据网络状态计算消息延迟
        switch (m_networkState) {
            case GOOD:
                return getRandomDelay() * 0.5 * roundFactor;  // 进一步降低延迟
            case NORMAL:
                return getRandomDelay() * 0.8 * roundFactor;
            case CONGESTED:
                return getRandomDelay() * roundFactor;
            default:
                return getRandomDelay() * roundFactor;
        }
    }

    // 记录消息延迟
    void NodeApp::RecordMessageDelay(double delay) {
        NS_LOG_FUNCTION(this);
        // 保持最近m_maxDelayWindow次的延迟记录
        if (m_recentDelays.size() >= m_maxDelayWindow) {
            m_recentDelays.erase(m_recentDelays.begin());
        }
        m_recentDelays.push_back(delay);
    }

    // 打印网络状态
    void NodeApp::PrintNetworkStatus() {
        NS_LOG_INFO("=============== 网络状态信息 ===============");
        NS_LOG_INFO("网络状态: " << (int)m_networkState);  // 使用(int)转换枚举值
        NS_LOG_INFO("网络质量: " << m_networkQuality);
        NS_LOG_INFO("消息延迟: " << m_messageDelay);
        NS_LOG_INFO("自适应阈值: " << m_adaptiveThreshold);
        NS_LOG_INFO("节点数量: " << N);
        NS_LOG_INFO("===========================================================\n\n");
    }

    void NodeApp::CheckConsensusProgress() {
        NS_LOG_FUNCTION(this);
        static int last_round_number = 0;
        static int stall_count = 0;
        
        if (round_number == last_round_number) {
            stall_count++;
            NS_LOG_WARN("共识似乎停滞，已持续 " << stall_count << " 个检查周期");
            if(stall_count >= 30000){
                exit(0);
            }
            if (stall_count >= 3 && is_leader == 1) {
                // 如果连续3次检查都没有进展，且当前节点是领导者，重启共识
                NS_LOG_WARN("共识停滞，领导者重启共识");
                Simulator::Schedule(Seconds(0.1), &NodeApp::initiateRound, this);
            }
        } else {
            stall_count = 0;
            last_round_number = round_number;
        }
        
        // 保存事件ID以便稍后取消
        m_checkProgressEvent = Simulator::Schedule(Seconds(5.0), &NodeApp::CheckConsensusProgress, this);
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
        std::string data[8];
        
        double probability  = 0.988+N*0.0002;
        bool sendValidMessage = (rand() / (RAND_MAX + 1.0)) < probability;
        // 生成医疗数据
        int dataIndex = round_number % heartDataset.size();
        std::string medicalData = heartDataset[dataIndex].toString();
        if (sendValidMessage) {
            // 构造正确的消息
            data[0] = convertIntToChar(1); // 有效值
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(view_number);
            data[5] = convertIntToChar(m_sequenceNumber++); // 正确的序列号
            data[6] = '1'; // 添加签名
            data[7] = medicalData; // 添加医疗数据

            //NS_LOG_INFO("攻击者节点" << m_id << "构造正确消息");
        } else {
            // 构造错误的消息
            data[0] = convertIntToChar(rand() % 9); // 随机值
            data[1] = convertIntToChar(REQUEST);
            data[2] = convertIntToChar(m_id);
            data[3] = convertIntToChar(leader_id);
            data[4] = convertIntToChar(rand() % 100); // 随机视图编号
            data[5] = convertIntToChar(rand() % 100); // 随机序列号
            data[6] = '0'; // 不添加签名
            data[7] = medicalData; // 添加医疗数据

            //NS_LOG_INFO("攻击者节点" << m_id << "构造错误消息");
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