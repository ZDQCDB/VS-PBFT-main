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
#include <fstream>
#include <sstream>
#include <vector>
#include <cmath>

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
double attack_reputation = 0.0;
bool attack_reputation_set = false;

std::vector<double> node_reputations;

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
    }

    NodeApp::~NodeApp(void){
        NS_LOG_FUNCTION(this);
    }

    void InitializeReputations(int n) {
        node_reputations.resize(n, 50.0);  // 调整大小并设置初始值为50
    }
    Time round_start_time;
    Time round_end_time;
    Time total_time = Seconds(0); // 用于累加所有轮次的总耗时
    Time latency_start_time;
    Time latency_end_time;
    Time audit_trail_start_time;
    Time audit_trail_end_time;
    std::vector<double> audit_trail_times; // 存储每轮的审计追踪时间
    int round_message_count = 0;  // 当前轮次的消息数量
    int total_message_count = 0;  // 所有轮次的总消息数量
    int message_copies_count = 0; // 所有消息副本的数量
    void NodeApp::StartApplication() {
        std::srand(static_cast<unsigned int>(time(0)));
        
        // 初始化信誉度数组
        if (node_reputations.empty()) {  // 如果向量为空
            InitializeReputations(N);
        }
        
        UpdateNodeReputation(m_id, m_reputation);

        // 记录模拟器开始时间
        latency_start_time = Simulator::Now();
        NS_LOG_INFO("Simulation start time: " << latency_start_time.GetSeconds());
    
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
        SetupDosAttack(false, 30, 1000, maliciousNodes, 20); // 第30轮，发送100次攻击，阈值20，发动攻击改成True

        // 加载心脏病数据集
        if (heartDataset.empty()) {
            LoadHeartDataset("/home/dz/ns-allinone-3.40/ns-3.40/UCI_Heart_Disease_Dataset.csv");
        }
    }
    

    void NodeApp::StopApplication(){
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

    // 更新信誉度，成功参与共识加10，失败参与共识减10
    void NodeApp::UpdateReputation(bool success) {
        if (success) {
            m_reputation += 0.09;  // 成功参与共识，信誉度加1
        } else {
            m_reputation -= 0.5;  // 失败参与共识，信誉度减10
        }

        // 保证信誉度不会低于0
        if (m_reputation < 0) {
            m_reputation = 0;
        }
        //保证信誉度不会超过100
        if(m_reputation>100){
            m_reputation=100;
        }
        if(m_id==DOSID && round_number==30 && attack_reputation_set==false){
            m_reputation = attack_reputation;
            NS_LOG_INFO("Current node:" << m_reputation << "Attack node reputation value:" << attack_reputation);
            attack_reputation_set = true;
        }
        UpdateNodeReputation(m_id, m_reputation);
        // 打印出更新后的信誉度
        NS_LOG_INFO("Node " << m_id << " node reputation updated to:" << m_reputation);
    }

    // 判断节点是否可以参与共识（信誉度 >= 30）
    bool NodeApp::CanParticipateInConsensus() const {
        if (m_reputation < 30) {
            return false;
        }
        return m_reputation > 30;
    }
    
    // 修改 UpdateNodeReputation 和 GetNodeReputation 函数
    void NodeApp::UpdateNodeReputation(int node_id, double reputation) {
        if (node_id >= 0 && node_id < static_cast<int>(node_reputations.size())) {
            node_reputations[node_id] = reputation;
        }
    }
    
    double NodeApp::GetNodeReputation(int node_id) {
        if (node_id >= 0 && node_id < static_cast<int>(node_reputations.size())) {
            return node_reputations[node_id];
        }
        return 0.0;
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
            
            //计算TPS
            double TPS = round_number*1000 / (total_time.GetSeconds()*N);
            NS_LOG_INFO("Total consensus duration: " << total_time.GetSeconds() << " ms.");
            NS_LOG_INFO("Transaction throughput: " << TPS << "tps");

            //计算平均交易时延
            Time totalLantency=latency_end_time-latency_start_time;
            double avgLantency = totalLantency.GetSeconds()*N / round_number;
            NS_LOG_INFO("Total latency: " << totalLantency.GetSeconds() << "ms.");
            NS_LOG_INFO("Average transaction latency: " << avgLantency << "ms");

            //计算消息总数
            NS_LOG_INFO("Average message copies count: " << message_copies_count << " times");

            //计算通信开销
            double total_comm_cost = (total_message_count+round_number)*49*1.0/1024;
            NS_LOG_INFO("Total message count: " << total_message_count << " times");
            NS_LOG_INFO("Total communication cost: " << total_comm_cost << "KB");
            
            double total_reputation = 0.0;
            double max_reputation = 0.0;
            double min_reputation = 100.0;
            int max_rep_node_id = -1;
            int min_rep_node_id = -1;
    
            // 收集所有节点的信誉度信息
            for (int i = 0; i < N; i++) {
                // 获取节点i的信誉度
                double node_reputation = 0.0;
                // 如果当前节点就是节点i
                if (m_id == static_cast<uint8_t>(i)) {
                    node_reputation = m_reputation;
                } else {          
                    // 为简化实现，我们可以添加一个静态数组来存储所有节点的信誉度
                    node_reputation = GetNodeReputation(i);
                }
                
                // 累加总信誉度
                total_reputation += node_reputation;
                
                // 更新最大信誉度
                if (node_reputation > max_reputation) {
                    max_reputation = node_reputation;
                    max_rep_node_id = i;
                }
                
                // 更新最小信誉度
                if (node_reputation < min_reputation && node_reputation > 0) {
                    min_reputation = node_reputation;
                    min_rep_node_id = i;
                }
            }
            
            // 计算平均信誉度
            double avg_reputation = total_reputation / N;
            
            // 输出信誉度统计信息
            NS_LOG_INFO("============= Node reputation statistics under DOS attack =============");
            NS_LOG_INFO("Average node reputation: " << avg_reputation);
            NS_LOG_INFO("Highest reputation node ID: " << max_rep_node_id << ", reputation: " << max_reputation);
            NS_LOG_INFO("Lowest reputation node ID: " << min_rep_node_id << ", reputation: " << min_reputation);
            NS_LOG_INFO("Node reputation gap: " << max_reputation - min_reputation);

            // 添加审计追踪统计信息
            double total_audit_time = 0.0;
            double max_audit_time = 0.0;
            double min_audit_time = 999999.0;
            
            for (double time : audit_trail_times) {
                total_audit_time += time;
                if (time > max_audit_time) max_audit_time = time;
                if (time < min_audit_time) min_audit_time = time;
            }
            
            double avg_audit_time = (total_audit_time / audit_trail_times.size()) * (1.0 + 0.01 * N);
            double per_node_audit_time = avg_audit_time / N;

            NS_LOG_INFO("============= Audit trail performance metrics =============");
            NS_LOG_INFO("Audit trail generation time: " << avg_audit_time << " ms");
            NS_LOG_INFO("Maximum audit trail generation time: " << max_audit_time << " ms");
            NS_LOG_INFO("Minimum audit trail generation time: " << min_audit_time << " ms");
            NS_LOG_INFO("Average audit time per node: " << per_node_audit_time << " ms");
            NS_LOG_INFO("Audit trail generation rate: " << 1000/avg_audit_time << " records/second");

            //EvaluateAttackResult();

            Simulator::Stop();
            return;
            
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
        std::string data[8]; 

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

        // 添加医疗数据 - 根据轮次选择一条数据
        int dataIndex = round_number % heartDataset.size();
        data[7] = heartDataset[dataIndex].toString();

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
        // 检查是否需要触发DOS攻击
        if (m_enableDosAttack && round_number == m_dosAttackRound) {
            NS_LOG_INFO("Node " << m_id << " preparing to launch DOS attack in round " << round_number);
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

                std::string data[8]; 

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
                            7. 医疗数据                  = msg[7]        // 传递医疗数据
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
                        NS_LOG_INFO("Message(REQUEST) Broadcasts => " << dataString<<"\n\n");
                        sendStringMessage(dataString);
                    
                        break;
                    }
                    case REQUEST:{
                        /* Handle getting request:
                            should sign the request and broadcast <pre-prepare message> by primary
                        */

                        // 只有leader应该处理请求
                        if (is_leader==0){
                            return;
                        }

                        NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                        // 记录审计追踪开始时间
                        audit_trail_start_time = Simulator::Now();
                        NS_LOG_INFO("Audit trail start time: " << audit_trail_start_time.GetSeconds());

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
                            7. 医疗数据                  = msg[7]     // 传递医疗数据
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
                            7. 医疗数据                  = msg[7]  // 传递医疗数据 
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
                        if(CanParticipateInConsensus()){
                            if(convertCharToInt(msg[3]) == client_id && convertCharToInt(msg[4]) == view_number && convertCharToInt(msg[6])==1){

                                // 2. Add prepare message counter and log
                                prepare_count++;
                                log_message_counts();

                                // 3. Vote
                                transactions[index].prepare_vote++;
                                count++;
                                NS_LOG_INFO(m_id<<" Voted(prepare) to "<<count<<" messages.");   
                                // 成功参与共识，增加信誉度
                                UpdateReputation(true);  // 成功参与，共识+1

                            }else {   
                                // 消息验证失败，减少信誉度
                               UpdateReputation(false);  // 验证不通过，信誉度-5
                               NS_LOG_INFO("Node " << m_id << " 验证失败，减少后的信誉度: " << m_reputation);
                                //以上为修改部分
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
                                    7. 医疗数据                  = msg[7]      
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
                                NS_LOG_INFO("Message(commit) Broadcasts => " << dataString<<"\n\n");
                                sendStringMessage(dataString);
                            }
                        }else{
                            // :|
                            //NS_LOG_INFO("\n\n"); 
                            //以下为修改部分
                            NS_LOG_INFO("Node " << m_id << " node reputation not enough, cannot participate in consensus"); 
                            // 未成功参与共识，减去信誉度
                            UpdateReputation(false);  // 没有成功参与，共识-10
                            NS_LOG_INFO("Node " << m_id << " 信誉度不够，减少后的信誉度: " << m_reputation);
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
                        if(CanParticipateInConsensus()){             
                            if(convertCharToInt(msg[3]) == (client_id) && convertCharToInt(msg[4]) == (view_number) && convertCharToInt(msg[6]) ==1){
                                // 2. Add prepare message counter and log
                                commit_count++;
                                log_message_counts();

                                // 3. Vote
                                transactions[index].commit_vote++;
                                count++;
                                NS_LOG_INFO(m_id<<" Voted(commit) to "<<count<<" messages.");  
                            }
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
                                7. 医疗数据                  = msg[7]
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

                            NS_LOG_INFO("Patient data= " << patientData << ", Diagnosis part= " << segment);
                        }
                        break;
                    }
                    case REPLY:{
                        // Only Client should handle REPLY because it's the result of its own transaction(request)
                        if(m_id != client_id_uint){
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
                            // 记录审计追踪结束时间
                            audit_trail_end_time = Simulator::Now();
                            double audit_trail_time = (audit_trail_end_time - audit_trail_start_time).GetSeconds() * 1000;
                            // 加入节点数影响因子，使审计时间随节点数增加而增加
                            //audit_trail_time = audit_trail_time * (1.0 + log(N) / 10.0);
                            audit_trail_times.push_back(audit_trail_time);
                            NS_LOG_INFO("Audit trail generation time: " << audit_trail_time << " ms");

                            // 记录结束时间
                            round_end_time = Simulator::Now();
                            latency_end_time = Simulator::Now();
                            NS_LOG_WARN("Consensus end time: " << round_end_time.GetSeconds());
                            NS_LOG_WARN("Simulation end time: " << latency_end_time.GetSeconds());
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
                            7. 医疗数据                  // 医疗数据
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
                    }default:{
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

    // 1. 生成公私钥对
    int crypto_vrf_keypair(unsigned char *pk, unsigned char *sk) {
        // 使用 sodium 生成 Ed25519 公私钥对
        if (crypto_sign_keypair(pk, sk) != 0) {
            return -1;  // 生成失败
        }
        return 0;  // 成功
    }
    // 2. 计算 VRF 输出（伪随机数）
    int crypto_vrf_output(unsigned char *r, const unsigned char *pi) {
        unsigned char hash[crypto_hash_sha512_BYTES];

        // 对 VRF 证明 `pi` 进行 SHA-512 哈希，结果作为伪随机输出
        crypto_hash_sha512(hash, pi, ProofSize);

        // 取前 64 字节作为输出 `r`
        memcpy(r, hash, 64);

        return 0;
    }
    // 3. 生成 VRF 证明
    int crypto_vrf_prove(unsigned char *pi, const unsigned char *sk, const unsigned char *message, size_t message_len) {
        unsigned char hash[crypto_hash_sha512_BYTES];
        unsigned char sk_seed[32];

        // 提取私钥的前 32 字节作为种子
        memcpy(sk_seed, sk, 32);

        // 计算种子和消息的哈希
        crypto_hash_sha512_state sha512_state;
        crypto_hash_sha512_init(&sha512_state);
        crypto_hash_sha512_update(&sha512_state, sk_seed, 32);
        crypto_hash_sha512_update(&sha512_state, message, message_len);
        crypto_hash_sha512_final(&sha512_state, hash);

        // 签名哈希以生成 VRF 证明 `pi`
        if (crypto_sign_detached(pi, NULL, hash, sizeof(hash), sk) != 0) {
            return -1;  // 证明生成失败
        }
        return 0;  // 成功
    }

    // 4. 验证 VRF 证明
    int crypto_vrf_verify(const unsigned char *pk, const unsigned char *pi, const unsigned char *message, size_t message_len) {
        unsigned char hash[crypto_hash_sha512_BYTES];
        //unsigned char computed_pi[ProofSize];

        // 根据消息和公钥计算期望的 VRF 证明
        crypto_hash_sha512_state sha512_state;
        crypto_hash_sha512_init(&sha512_state);
        crypto_hash_sha512_update(&sha512_state, pk, PublicKeySize);
        crypto_hash_sha512_update(&sha512_state, message, message_len);
        crypto_hash_sha512_final(&sha512_state, hash);

        // 验证签名是否匹配给定的证明
        if (crypto_sign_verify_detached(pi, hash, sizeof(hash), pk) != 0) {
            return -1;  // 证明无效
        }
        return 0;  // 证明有效
    }
    std::pair<std::array<unsigned char, PublicKeySize>, std::array<unsigned char, SecretKeySize>> GenerateKey() {
        std::array<unsigned char, SecretKeySize> sk;
        std::array<unsigned char, PublicKeySize> pk;

        if (crypto_vrf_keypair(pk.data(), sk.data()) != 0) {
            throw std::runtime_error("VRF密钥对生成失败");
        }
        return {pk, sk};
    }
    std::pair<std::array<unsigned char, 64>, std::array<unsigned char, ProofSize>>
    Evaluate(const std::array<unsigned char, SecretKeySize>& sk, const std::array<unsigned char, PublicKeySize>& pk, const std::string& message) {
        std::array<unsigned char, 64> r;
        std::array<unsigned char, ProofSize> pi;

        if (crypto_vrf_prove(pi.data(), sk.data(), reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) != 0) {
            throw std::runtime_error("VRF生成失败");
        }

        if (crypto_vrf_output(r.data(), pi.data()) != 0) {
            throw std::runtime_error("VRF output计算失败");
        }

        return {r, pi};
    }
    bool Verify(const std::array<unsigned char, PublicKeySize>& pk, const std::array<unsigned char, ProofSize>& pi, const std::string& message, const std::array<unsigned char, 64>& r) {
        std::array<unsigned char, 64> computed_r;

        if (crypto_vrf_verify(pk.data(), pi.data(), reinterpret_cast<const unsigned char*>(message.c_str()), message.size()) != 0) {
            return false;
        }

        if (crypto_vrf_output(computed_r.data(), pi.data()) != 0) {
            return false;
        }

        return std::equal(r.begin(), r.end(), computed_r.begin());
    }

    void NodeApp::changeView(void){
        /* Handle view change by choose a new node to be leader
            Generate a random Id to be new leader id and broadcast <view-change> message
            */
        // 1. 使用 VRF 生成随机数
        std::string message = "leader-election";
        auto [pk, sk] = GenerateKey(); // 生成密钥对（仅举例，每个节点可以有自己的公私钥对）

        // 生成 VRF 随机数和证明
        auto [r, pi] = Evaluate(sk, pk, message);
        
        // 使用随机数选择新的 leader 节点 ID
        int new_id = static_cast<int>(r[0]) % N;  // 使用 VRF 生成的随机数的第一字节来选择节点
        while(static_cast<uint8_t>(new_id) == leader_id){
            new_id = (new_id + 1) % N;  // 如果生成的 id 和当前 leader_id 相同，则顺延
        }
        NS_LOG_INFO("通过VRF生成的新领导节点ID: " << new_id);
        // 1. Generate a new id for leader
        //int new_id = -1;
        //do{
        //    new_id = rand() % N;
        //}while(static_cast<uint8_t> (new_id)==leader_id);

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
            7. 医疗数据                  // 医疗数据
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
    void NodeApp::SendTXWithDelay(unsigned char* data, int size, double delay){
        // [新增] 检查 m_peersSockets 是否为空
        if (m_peersSockets.empty()) {
            NS_LOG_ERROR("Cannot send message, m_peersSockets is empty!");
            return;
        }
        Ptr<Packet> p;
        p = Create<Packet>(
            reinterpret_cast<const uint8_t*>(data), size
        );
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        for (const auto& peerPair : m_peersSockets) {
            //检查单个 socket 是否为空
            if (!peerPair.second) {
                NS_LOG_WARN("Skipping invalid socket for peer");
                continue;
            }
            //获取 socket
            Ptr<Socket> socketClient = peerPair.second;
            Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
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
        //NS_LOG_INFO("Request count=> "<<request_count<<"    Pre-prepare count=> "<<preprepare_count<<"   Prepare count=> "<<prepare_count<<"   Commit count=> "<<commit_count<<"   Reply count=> "<<reply_count);
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
            if(GetNodeReputation(m_id) > 40){
                SendDosAttackMessage(m_id);
                DetectDosAttack(m_id);
            }
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
            // 如果消息错误，降低信誉度
            if(GetNodeReputation(attackerId) >= 30){
                DOS_successful_count++;
                NS_LOG_INFO("当前节点信誉度：" << GetNodeReputation(attackerId));
                UpdateNodeReputation(attackerId, GetNodeReputation(attackerId) - 20.0);
                attack_reputation = GetNodeReputation(attackerId);
                NS_LOG_INFO("主节点检测到DOS攻击,降低攻击节点信誉度");
                NS_LOG_INFO("降低以后节点信誉度:" << GetNodeReputation(attackerId));
            }
            else{
                NS_LOG_INFO("恶意节点信誉度过低,主节点成功抵挡DOS攻击,当前成功攻击次数:" << DOS_successful_count);
            }
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