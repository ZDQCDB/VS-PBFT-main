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
#include "ns3/config.h"
#include "ns3/boolean.h"
#include "ns3/global-value.h"

#include <map>
#include <iostream>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <random>
#include <ctime>

// 全局消息计数器
int request_count       = 0;
int preprepare_count    = 0;
int prepare_count       = 0;
int commit_count        = 0;
int reply_count         = 0;
int round_number        = 0;
int view_is_changed     = 0;

// 存储加载的FHIR资源
std::vector<ns3::FHIRResource*> globalFhirDataset;

namespace ns3 {

float getRandomDelay();
static char convertIntToChar(int a);
static int convertCharToInt(char a);
static void log_message_counts();
void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p);

/*******************************APPLICATION*******************************/
NS_LOG_COMPONENT_DEFINE("NodeApp");

NS_OBJECT_ENSURE_REGISTERED(NodeApp);

TypeId NodeApp::GetTypeId(void) {
    static TypeId tid = TypeId("ns3::NodeApp")
                            .SetParent<Application>()
                            .SetGroupName("Applications")
                            .AddConstructor<NodeApp>();
    return tid;
}

NodeApp::NodeApp(void) : m_id(0),
                        m_socket(0),
                        N(0),
                        is_leader(0),
                        sec_num(0),
                        view_number(0),
                        leader_id(0),
                        client_id(0),
                        total_rounds(10),
                        total_time(Seconds(0)), 
                        round_message_count(0),
                        total_message_count(0),
                        message_copies_count(0),
                        enable_audit(true) {
    // 构造函数中明确初始化所有重要的成员变量
    NS_LOG_FUNCTION(this);
    
    // 初始化所有交易的投票计数器
    for (int i = 0; i < arraySize; i++) {
        transactions[i].prepare_vote = 0;
        transactions[i].commit_vote = 0;
        transactions[i].view = 0;
        transactions[i].value = 0;
    }
}

NodeApp::~NodeApp(void) {
    NS_LOG_FUNCTION(this);
    // 清理FHIR资源
    for (auto* resource : fhirDataset) {
        delete resource;
    }
    fhirDataset.clear();
}

void NodeApp::StartApplication() {
    std::srand(static_cast<unsigned int>(time(0)));
    
    // 获取全局配置
    UintegerValue rounds;
    BooleanValue audit;
    GlobalValue::GetValueByName("FhirRounds", rounds);
    GlobalValue::GetValueByName("EnableAudit", audit);
    total_rounds = rounds.Get();
    enable_audit = audit.Get();
    
    // 记录开始时间
    latency_start_time = Simulator::Now();
    NS_LOG_INFO("Simulation start time: " << latency_start_time.GetSeconds());
    NS_LOG_INFO("Node " << m_id << " Configuration parameters: Total rounds=" << total_rounds << ", Total nodes=" << N << ", Audit enabled=" << (enable_audit ? "Yes" : "No"));

    // 创建套接字
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

    // 设置接收回调
    m_socket->SetRecvCallback(MakeCallback(&NodeApp::HandleRead, this));
    m_socket->SetAllowBroadcast(true);
    NS_LOG_INFO("Node" << m_id << " started");
    printInformation();
    
    // 连接到对等节点
    if (m_peersAddresses.empty()) {
        NS_LOG_WARN("m_peersAddresses is empty! No peers to connect.");
        return;
    }
    
    NS_LOG_INFO("Node " << m_id << " Starting to connect to " << m_peersAddresses.size() << " peer nodes");
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
    
    // 加载FHIR资源
    LoadFHIRResources("/home/dz/ns-allinone-3.40/ns-3.40/UCI_Heart_Disease_Dataset.csv");
    
    // 只有领导者才启动共识
    if (is_leader == 1) {
        NS_LOG_INFO("Node " << m_id << " is the main node, will start the first round of consensus");
        Simulator::Schedule(Seconds(getRandomDelay()), &NodeApp::initiateRound, this);
    } else {
        NS_LOG_INFO("Node " << m_id << " is not the main node, waiting for message reception");
    }
}

void NodeApp::StopApplication() {
}

// 加载FHIR资源数据
void NodeApp::LoadFHIRResources(const std::string& filePath) {
    // 清理之前的数据集
    for (auto* resource : fhirDataset) {
        delete resource;
    }
    fhirDataset.clear();
    patientDataset.clear();
    observationDataset.clear();
    heartDiseaseDataset.clear();
    
    // 打开CSV文件
    std::ifstream file(filePath);
    if (!file.is_open()) {
        NS_LOG_ERROR("Cannot open heart disease data file: " << filePath);
        // 如果无法打开文件，创建一些示例数据以防止程序崩溃
        for (int i = 0; i < 5; i++) {
            FHIRPatient patient;
            patient.id = "patient-" + std::to_string(i);
            patient.versionId = "1";
            patient.lastUpdated = "2023-06-" + std::to_string(rand() % 30 + 1);
            patient.type = PATIENT;
            patient.name = "Patient" + std::to_string(i);
            patient.gender = (rand() % 2 == 0) ? "male" : "female";
            patient.birthDate = "19" + std::to_string(rand() % 100) + "-" + 
                               std::to_string(rand() % 12 + 1) + "-" + 
                               std::to_string(rand() % 28 + 1);
            
            patientDataset.push_back(patient);
            fhirDataset.push_back(new FHIRPatient(patient));
        }
        globalFhirDataset = fhirDataset;
        NS_LOG_INFO("Unable to load heart disease data, temporary data created with " << fhirDataset.size() << " records");
        return;
    }
    
    // 读取CSV文件的每一行
    std::string line;
    int lineCount = 0;
    
    while (std::getline(file, line)) {
        // 跳过可能的标题行
        if (lineCount == 0 && (line.find("age") != std::string::npos || 
                               line.find("sex") != std::string::npos)) {
            lineCount++;
            continue;
        }
        
        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;
        
        // 解析CSV格式数据
        while (std::getline(iss, token, ',')) {
            tokens.push_back(token);
        }
        
        // 确保有足够的数据字段
        if (tokens.size() >= 14) {
            FHIRHeartDisease heartData;
            
            // 设置基本FHIR资源信息
            heartData.id = "heart-disease-" + std::to_string(lineCount);
            heartData.versionId = "1";
            heartData.lastUpdated = "2023-07-" + std::to_string(rand() % 30 + 1);
            heartData.type = HEART_DISEASE;
            
            try {
                // 设置心脏病特定数据
                heartData.age = std::stoi(tokens[0]);
                heartData.sex = std::stoi(tokens[1]);
                heartData.cp = std::stoi(tokens[2]);
                heartData.trestbps = std::stoi(tokens[3]);
                heartData.chol = std::stoi(tokens[4]);
                heartData.fbs = std::stoi(tokens[5]);
                heartData.restecg = std::stoi(tokens[6]);
                heartData.thalach = std::stoi(tokens[7]);
                heartData.exang = std::stoi(tokens[8]);
                heartData.oldpeak = std::stof(tokens[9]);
                heartData.slope = std::stoi(tokens[10]);
                heartData.ca = std::stoi(tokens[11]);
                heartData.thal = std::stoi(tokens[12]);
                heartData.target = std::stoi(tokens[13]);
                
                // 添加到数据集
                heartDiseaseDataset.push_back(heartData);
                fhirDataset.push_back(new FHIRHeartDisease(heartData));
                
                NS_LOG_INFO("Loaded heart disease data: ID=" << heartData.id << ", Age=" << heartData.age << 
                            ", Sex=" << (heartData.sex == 1 ? "Male" : "Female") << 
                            ", Diagnosis Result=" << (heartData.target == 1 ? "Diseased" : "Healthy"));
            }
            catch (const std::exception& e) {
                NS_LOG_ERROR("Data line parsing failed: " << line << " Error: " << e.what());
            }
        } else {
            NS_LOG_WARN("Data line format incorrect: " << line << " (Field count: " << tokens.size() << ")");
        }
        
        lineCount++;
    }
    
    // 记录加载完成的数据统计
    file.close();
    
    // 如果没有加载到数据，创建少量示例数据
    if (heartDiseaseDataset.empty()) {
        NS_LOG_WARN("Unable to load valid heart disease data, temporary data created");
        
        // 创建少量患者数据
        for (int i = 0; i < 5; i++) {
            FHIRPatient patient;
            patient.id = "patient-" + std::to_string(i);
            patient.versionId = "1";
            patient.lastUpdated = "2023-06-" + std::to_string(rand() % 30 + 1);
            patient.type = PATIENT;
            patient.name = "Patient" + std::to_string(i);
            patient.gender = (rand() % 2 == 0) ? "male" : "female";
            patient.birthDate = "19" + std::to_string(rand() % 100) + "-" + 
                               std::to_string(rand() % 12 + 1) + "-" + 
                               std::to_string(rand() % 28 + 1);
            
            patientDataset.push_back(patient);
            fhirDataset.push_back(new FHIRPatient(patient));
        }
    }
    
    globalFhirDataset = fhirDataset;
    NS_LOG_INFO("Successfully loaded " << fhirDataset.size() << " FHIR resource records");
    NS_LOG_INFO("Among which heart disease data " << heartDiseaseDataset.size() << " records");
}

// 为FHIR资源生成审计追踪
std::string NodeApp::GenerateAuditTrail(const FHIRResource& resource, const std::string& action) {
    std::stringstream ss;
    
    // 添加时间戳
    time_t now = time(nullptr);
    std::string timestamp(ctime(&now));
    if (!timestamp.empty() && timestamp[timestamp.size()-1] == '\n') {
        timestamp.pop_back(); // 移除末尾的换行符
    }
    
    // 生成审计追踪格式：时间戳,节点ID,资源类型,资源ID,操作
    ss << timestamp << ","
       << m_id << ","
       << resource.type << ","
       << resource.id << ","
       << action;
       
    // 添加资源详情
    ss << "," << resource.toString();
    
    // 特殊处理心脏病数据
    if (resource.type == HEART_DISEASE) {
        const FHIRHeartDisease* heartData = dynamic_cast<const FHIRHeartDisease*>(&resource);
        if (heartData) {
            ss << ",Diagnosis Result:" << (heartData->target == 1 ? "Diseased" : "Healthy");
            
            // 添加风险评估
            int riskFactors = 0;
            if (heartData->age > 55) riskFactors++;
            if (heartData->sex == 1) riskFactors++;  // 男性风险更高
            if (heartData->chol > 240) riskFactors++;
            if (heartData->trestbps > 140) riskFactors++;
            if (heartData->fbs == 1) riskFactors++;
            if (heartData->exang == 1) riskFactors++;
            
            ss << ",Risk Factors:" << riskFactors << "/6";
        }
    }
    
    // 增加数字签名部分（在实际应用中应使用密码学算法）
    ss << ",signed:" << m_id << "-" << sec_num << "-" << view_number;
    
    return ss.str();
}

/*******************************INTERACTION*******************************/

void NodeApp::initiateRound(void) {
    // 检查是否达到轮次上限
    if (round_number == total_rounds) {
        NS_LOG_INFO(round_number << " Round Finished Successfully!");
        
        // 计算TPS
        double TPS = round_number * 1000 / (total_time.GetSeconds() * N);
        NS_LOG_INFO("Total consensus duration: " << total_time.GetSeconds() << " ms.");
        NS_LOG_INFO("Transaction throughput: " << TPS << "tps");

        // 计算平均交易时延
        Time totalLatency = latency_end_time - latency_start_time;
        double avgLatency = totalLatency.GetSeconds() * N / round_number;
        NS_LOG_INFO("Total latency: " << totalLatency.GetSeconds() << "ms.");
        NS_LOG_INFO("Average transaction latency: " << avgLatency << "ms");

        // 计算消息总数
        NS_LOG_INFO("Average message copies count: " << message_copies_count << " times");

        // 计算通信开销
        double total_comm_cost = (total_message_count + round_number) * 68 * 1.0 / 1024;
        NS_LOG_INFO("Total message count: " << total_message_count << " times");
        NS_LOG_INFO("Total communication cost: " << total_comm_cost << "KB");
        
        // 添加审计追踪统计信息
        if (enable_audit && !audit_trail_times.empty()) {
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
        }

        NS_LOG_INFO("Simulation completed, total consensus rounds: " << round_number << ", total nodes: " << N);
        Simulator::Stop();
        return;
    }

    NS_LOG_INFO("==========================================");
    NS_LOG_INFO("Starting round " << round_number + 1 << " consensus (total planned: " << total_rounds << " rounds)");
    NS_LOG_INFO("Node " << m_id << " current status: Leader=" << (is_leader ? "Yes" : "No") << ", current leader ID=" << leader_id);
    NS_LOG_INFO("==========================================");

    // 偶尔触发视图变更
    if (rand() % 3 == 0 && view_is_changed == 0) {
        NS_LOG_INFO("Trigger view change");
        changeView();
        return;
    } else {
        view_is_changed = 0;
    }

    round_number++;

    // 重置计数器
    request_count = 0;
    preprepare_count = 0;
    prepare_count = 0;
    commit_count = 0;
    reply_count = 0;

    // 构造模板区块
    std::string data[7];

    // 设置发送请求的客户端
    int random_client = -1;
    do {
        random_client = (rand() % N);
    } while (random_client == leader_id || client_id == random_client);

    client_id = random_client;
    NS_LOG_INFO("Round selected client ID => " << client_id);

    NS_LOG_INFO("----------------- New round started! => " << round_number << " ------------------");

    // 构造客户端变更消息
    data[0] = '0';
    data[2] = '0';
    data[3] = convertIntToChar(client_id);
    data[4] = '0';
    data[5] = '0';
    data[6] = '0'; // 未签名

    // 设置消息类型为客户端变更
    data[1] = convertIntToChar(CLIENT_CHANGE);

    // 广播客户端变更消息
    std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
    NS_LOG_INFO("Message(CLIENT_CHANGE) Broadcasts => " << dataString);
    sendStringMessage(dataString);

    // 设置消息类型为新轮次
    data[1] = convertIntToChar(NEW_ROUND);

    // 广播新轮次消息（带较大延迟）
    dataString = std::accumulate(std::begin(data), std::end(data), std::string());
    NS_LOG_INFO("Message(NEW_ROUND) Broadcasts => " << dataString);
    
    std::vector<uint8_t> myVector(dataString.begin(), dataString.end());
    uint8_t* d = &myVector[0];
    NodeApp::SendTXWithDelay(d, dataString.size(), 12);
}

// 处理接收到的消息
void NodeApp::HandleRead(Ptr<Socket> socket) {
    if (!socket) {
        NS_LOG_ERROR("Null socket in HandleRead");
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
            NS_LOG_ERROR("Received packet from an unexpected address type.");
            continue;
        } else {
            std::string msg = getPacketContent(packet, from);
            uint8_t client_id_uint = static_cast<uint8_t>(client_id);
            int state = convertCharToInt(msg[1]);

            NS_LOG_INFO(state << "======>" << msg << "-=====>" << m_id << "====>" << client_id);
    
            // 客户端不处理部分消息类型
            if (m_id == client_id_uint && state != REPLY && state != NEW_ROUND && state != CLIENT_CHANGE) {
                return;
            }               

            std::string data[7]; 

            // 根据消息类型处理
            switch (state) {
                case CLIENT_CHANGE: {
                    // 处理客户端变更
                    client_id = convertCharToInt(msg[3]);
                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);
                    NS_LOG_INFO("Client Id of " << m_id << " changed to => " << client_id << "\n\n");                        
                }
                case NEW_ROUND: {
                    // 处理新轮次开始
                    
                    // 只有客户端处理NEW-ROUND
                    if (m_id != client_id_uint) {
                        return;
                    }
                    
                    // 记录开始时间
                    round_start_time = Simulator::Now();
                    NS_LOG_WARN("Consensus start time: " << round_start_time.GetSeconds());

                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 构造请求消息
                    data[0] = convertIntToChar(rand() % 9);
                    data[2] = convertIntToChar(m_id);
                    data[3] = convertIntToChar(client_id);
                    data[4] = convertIntToChar(view_number);
                    data[5] = '0';
                    data[6] = '0';

                    // 设置消息类型为请求
                    data[1] = convertIntToChar(REQUEST);
                    std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                    NS_LOG_INFO("Message(REQUEST) Broadcasts => " << dataString << "\n\n");
                    sendStringMessage(dataString);
                
                    break;
                }
                case REQUEST: {
                    // 处理请求
                    
                    // 只有领导者处理请求
                    if (is_leader == 0) {
                        return;
                    }

                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 开始审计追踪计时
                    if (enable_audit) {
                        audit_trail_start_time = Simulator::Now();
                        NS_LOG_INFO("Audit trail start time: " << audit_trail_start_time.GetSeconds());
                    }

                    // 增加请求计数器
                    request_count++;
                    log_message_counts();

                    // 构造预准备消息
                    data[0] = msg[0];           
                    data[2] = convertIntToChar(m_id);
                    data[3] = msg[3];
                    data[4] = msg[4];

                    // 设置序列号并更新
                    data[5] = convertIntToChar(sec_num);
                    sec_num++;  // 增加序列号

                    // 签名交易
                    data[6] = '1';
                    
                    // 如果启用审计，创建审计跟踪
                    std::string auditTrail = "";
                    if (enable_audit && !fhirDataset.empty()) {
                        // 选择一个随机的FHIR资源进行处理
                        int resourceIndex = rand() % fhirDataset.size();
                        std::string action = "read"; // 或 "create", "update", "delete"
                        
                        // 生成审计跟踪
                        auditTrail = GenerateAuditTrail(*fhirDataset[resourceIndex], action);
                        
                        // 存储审计信息到交易中
                        int index = convertCharToInt(data[5][0]);
                        // 确保索引在有效范围内
                        if (index >= 0 && index < arraySize) {
                            transactions[index].auditInfo = auditTrail;
                            transactions[index].resourceId = fhirDataset[resourceIndex]->id;
                            NS_LOG_INFO("Audit trail created for resource " << fhirDataset[resourceIndex]->id);
                        } else {
                            NS_LOG_ERROR("Invalid transaction index: " << index << ", should be in 0-" << (arraySize-1));
                        }
                    }

                    // 设置消息类型为预准备
                    data[1] = convertIntToChar(PRE_PREPARED);     

                    // 广播预准备消息
                    std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                    NS_LOG_INFO("Message(PRE_PREPARED) Broadcasts => " << dataString << "\n\n");
                    sendStringMessage(dataString);
                    break;
                }
                case PRE_PREPARED: { 
                    // 处理预准备消息
        
                    // 检查签名
                    if (msg[6] == '0') {
                        return;
                    }

                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 增加预准备消息计数器
                    preprepare_count++;
                    log_message_counts();

                    // 构造准备消息
                    data[0] = msg[0];           
                    data[2] = convertIntToChar(m_id);
                    data[3] = msg[3];
                    data[4] = msg[4];
                    data[5] = msg[5];
                    data[6] = msg[6];

                    // 添加交易
                    int index = convertCharToInt(msg[5]);
                    
                    // 检查索引是否有效
                    if (index < 0 || index >= arraySize) {
                        NS_LOG_ERROR("Node " << m_id << " Received invalid transaction index: " << index << ", ignoring this message");
                        return;
                    }

                    // 设置交易视图
                    transactions[index].view = view_number;

                    // 存储交易值
                    transactions[index].value = convertCharToInt(msg[0]);

                    // 设置消息类型为准备
                    data[1] = convertIntToChar(PREPARED);     

                    // 广播准备消息
                    std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                    NS_LOG_INFO("Message(PREPARED) Broadcasts => " << dataString << "\n\n");
                    sendStringMessage(dataString);
                    break;
                }
                case PREPARED: {
                    // 处理准备消息
                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 获取当前计数
                    int index = convertCharToInt(msg[5]);  
                    
                    // 检查索引是否有效
                    if (index < 0 || index >= arraySize) {
                        NS_LOG_ERROR("Node " << m_id << " Received invalid transaction index: " << index << ", ignoring this message");
                        break;
                    }
                    
                    int count = transactions[index].prepare_vote;

                    // 验证消息
                    if (convertCharToInt(msg[3]) == client_id && 
                        convertCharToInt(msg[4]) == view_number && 
                        convertCharToInt(msg[6]) == 1) {

                        // 增加准备消息计数器
                        prepare_count++;
                        log_message_counts();

                        // 投票
                        transactions[index].prepare_vote++;
                        count++;
                        NS_LOG_INFO(m_id << " Voted(prepare) to " << count << " messages. Need " << (N/2 + 1) << " votes");   
                        
                        // 检查投票是否达到阈值 (N/2 + 1)的位置放在这里，确保只有投票有效时才检查
                        if (count >= N/2 + 1) {
                            NS_LOG_INFO("Node " << m_id << " Prepare stage vote threshold reached, preparing to send COMMIT message");
                            
                            // 重置投票（防止再次发送提交）
                            transactions[index].prepare_vote = 0;

                            // 构造提交消息
                            data[0] = msg[0];           
                            data[2] = convertIntToChar(m_id);
                            data[3] = msg[3];
                            data[4] = msg[4];
                            data[5] = msg[5];
                            data[6] = msg[6];

                            // 设置消息类型为提交
                            data[1] = convertIntToChar(COMMITTED);     

                            // 广播提交消息
                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            NS_LOG_INFO("Message(commit) Broadcasts => " << dataString << "\n\n");
                            sendStringMessage(dataString);
                        } else {
                            NS_LOG_INFO("Node " << m_id << " Prepare stage vote threshold not reached, current: " << count << ", need: " << (N/2 + 1));
                        }
                    } else {
                        NS_LOG_INFO("Node " << m_id << " Received invalid PREPARED message, not voting");
                    }     
                    break;
                }
                case COMMITTED: {
                    // 处理提交消息
                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 获取当前计数
                    int index = convertCharToInt(msg[5]);
                    
                    // 检查索引是否有效
                    if (index < 0 || index >= arraySize) {
                        NS_LOG_ERROR("Node " << m_id << " Received invalid transaction index: " << index << ", ignoring this message");
                        break;
                    }
                    
                    int count = transactions[index].commit_vote;

                    // 验证消息
                    if (convertCharToInt(msg[3]) == (client_id) && 
                        convertCharToInt(msg[4]) == (view_number) && 
                        convertCharToInt(msg[6]) == 1) {
                        // 增加提交消息计数器
                        commit_count++;
                        log_message_counts();

                        // 投票
                        transactions[index].commit_vote++;
                        count++;
                        NS_LOG_INFO(m_id << " Voted(commit) to " << count << " messages. Need " << (N/2 + 1) << " votes");  
                        
                        // 检查是否达到阈值 (N/2 + 1)
                        if (count >= N/2 + 1) {
                            NS_LOG_INFO("Node " << m_id << " Commit stage vote threshold reached, preparing to send REPLY message");
                            
                            // 重置投票（防止再次发送提交）
                            transactions[index].commit_vote = 0;

                            // 处理交易 => x^2 % 10
                            int result = (convertCharToInt(msg[0]) * convertCharToInt(msg[0])) % 10;
                            
                            // 添加FHIR资源处理 - 优先选择心脏病数据
                            FHIRResource* resource = nullptr;
                            std::string actionType = "ACCESS";
                            
                            // 选择一个合适的心脏病数据
                            if (!heartDiseaseDataset.empty()) {
                                int resourceIndex = round_number % heartDiseaseDataset.size();
                                // 查找对应的指针
                                for (auto* res : fhirDataset) {
                                    if (res->type == HEART_DISEASE && 
                                        res->id == heartDiseaseDataset[resourceIndex].id) {
                                        resource = res;
                                        break;
                                    }
                                }
                                
                                // 对于心脏病数据，我们执行更详细的处理
                                if (resource) {
                                    FHIRHeartDisease* heartData = dynamic_cast<FHIRHeartDisease*>(resource);
                                    if (heartData) {
                                        // 根据交易结果执行不同操作
                                        if (result % 3 == 0) {
                                            actionType = "READ";
                                            NS_LOG_INFO("Read heart disease data record: " << heartData->id);
                                        } else if (result % 3 == 1) {
                                            actionType = "ANALYZE";
                                            NS_LOG_INFO("Analyze heart disease risk factors: Age=" << heartData->age << 
                                                      ", Cholesterol=" << heartData->chol << 
                                                      ", Blood Pressure=" << heartData->trestbps);
                                        } else {
                                            actionType = "PRESCRIBE";
                                            NS_LOG_INFO("Provide health advice to patient, Diagnosis Result: " << 
                                                      (heartData->target == 1 ? "Diseased" : "Healthy"));
                                        }
                                    }
                                }
                            } else {
                                // 如果没有心脏病数据，回退到普通FHIR资源
                                int resourceIndex = round_number % fhirDataset.size();
                                resource = fhirDataset[resourceIndex];
                            }
                            
                            // 创建最终审计追踪
                            std::string auditTrail;
                            if (enable_audit && resource) {
                                auditTrail = GenerateAuditTrail(*resource, actionType);
                                transactions[index].auditInfo = auditTrail;
                                transactions[index].resourceId = resource->id;
                            }
                            
                            NS_LOG_INFO("Request from " << client_id << " done and Result is=> " << result);
                            if (resource) {
                                NS_LOG_INFO("Processed FHIR resource: " << resource->id);
                                if (enable_audit) {
                                    NS_LOG_INFO("Audit record: " << auditTrail);
                                }
                            }

                            // 构造回复消息
                            data[0] = convertIntToChar(result);           
                            data[2] = convertIntToChar(m_id);
                            data[3] = msg[3];
                            data[4] = msg[4];
                            data[5] = msg[5];
                            data[6] = msg[6];

                            // 添加到账本
                            ledger.push_back(result);
                            fhirLedger.push_back(resource);

                            // 增加序列号
                            sec_num++;
                            NS_LOG_INFO(result << " Added to Ledger " << m_id << "!");

                            // 设置消息类型为回复
                            data[1] = convertIntToChar(REPLY);     

                            std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
                            NS_LOG_INFO("Message(REPLY) Broadcasts => " << dataString << "\n\n");
                            sendStringMessage(dataString);
                        } else {
                            NS_LOG_INFO("Node " << m_id << " Commit stage vote threshold not reached, current: " << count << ", need: " << (N/2 + 1));
                        }
                    } else {
                        NS_LOG_INFO("Node " << m_id << " Received invalid COMMITTED message, not voting");
                    }
                    break;
                }
                case REPLY: {
                    // 只有客户端处理回复消息
                    if (m_id != client_id_uint) {
                        return;
                    } 
                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 增加回复计数器
                    reply_count++;
                    log_message_counts();

                    NS_LOG_INFO("Client " << client_id << " Received transaction result => " << msg[0] << " from Node " << msg[2]);
                    NS_LOG_INFO("===========================================================");

                    // 在所有回复到达后开始新一轮（使用更大的延迟确保上一轮已完成）
                    // 注意：客户端收到N-1个节点的回复即可开始新一轮（包括自己一共N个节点）
                    int requiredReplies = N - 1;
                    NS_LOG_INFO("Client needs to receive " << requiredReplies << " replies, currently received " << reply_count);
                    
                    if (reply_count >= requiredReplies) {
                        NS_LOG_INFO("Client " << client_id << " Received enough replies (" << reply_count << "/" << requiredReplies << "), preparing to enter next round");
                        
                        // 记录审计追踪结束时间（如果启用）
                        if (enable_audit) {
                            audit_trail_end_time = Simulator::Now();
                            double audit_trail_time = (audit_trail_end_time - audit_trail_start_time).GetSeconds();
                            //audit_trail_time = audit_trail_time * (1.0 + log(N) / 10.0);
                            audit_trail_times.push_back(audit_trail_time);
                            NS_LOG_INFO("Audit trail generation time: " << audit_trail_time << " ms");
                        }

                        // 记录结束时间
                        round_end_time = Simulator::Now();
                        latency_end_time = Simulator::Now();
                        NS_LOG_WARN("Consensus end time: " << round_end_time.GetSeconds());
                        NS_LOG_WARN("Simulation end time: " << latency_end_time.GetSeconds());
                        
                        // 计算当前轮次的耗时
                        Time round_duration = round_end_time - round_start_time;
                        total_time += round_duration;  // 累加总耗时
                        NS_LOG_INFO("Completed round consensus, duration: " << round_duration.GetSeconds() << " seconds");
                        
                        // 计算当前轮次的消息数量
                        round_message_count = request_count + preprepare_count + prepare_count + commit_count + reply_count;
                        message_copies_count += preprepare_count + prepare_count + commit_count;
                        total_message_count += round_message_count;  // 累加总消息数量
                        NS_LOG_INFO("Round consensus message statistics: request=" << request_count << ", preprepare=" << preprepare_count 
                                   << ", prepare=" << prepare_count << ", commit=" << commit_count << ", reply=" << reply_count);
                        
                        // 更新客户端序列号
                        sec_num++;

                        NS_LOG_INFO("Preparing to start next round consensus (Current round: " << round_number << ", Target round: " << total_rounds << ")");
                        
                        // 安排下一轮共识（使用随机延迟确保网络稳定）
                        double delay = getRandomDelay() * 10;
                        NS_LOG_INFO("Scheduling next round consensus, delay: " << delay << " seconds");
                        Simulator::Schedule(Seconds(delay), &NodeApp::initiateRound, this);
                    } else {
                        NS_LOG_INFO("Client " << client_id << " Waiting for more replies, currently received: " << reply_count << "/" << (N-1));
                    }
                    break;
                }
                case VIEW_CHANGE: {
                    NS_LOG_INFO("Node " << GetNode()->GetId() << " Received Message: " << msg);

                    // 获取新领导者ID并设置
                    int new_leader = convertCharToInt(msg[0]);
                    leader_id = new_leader;

                    // 更新是否为领导者状态
                    if (static_cast<uint8_t>(new_leader) == m_id) {
                        is_leader = 1;
                    } else {
                        is_leader = 0;
                    }

                    // 更新视图变更计数
                    view_is_changed++;

                    // 更新视图编号
                    view_number++;

                    NS_LOG_INFO("Leader Id of " << m_id << " changed to => " << leader_id << "\n\n"); 

                    // 当所有节点处理完视图变更后开始新一轮
                    if (view_is_changed == N) {
                        Simulator::Schedule(Seconds(getRandomDelay())*10, &NodeApp::initiateRound, this);
                    }
                    break;
                }
                default: {
                    NS_LOG_INFO("INVALID MESSAGE TYPE: " << state);
                    break;
                }
            }
        }
        socket->GetSockName(localAddress);
    }
}

// 将来自地址的数据包转换为字符串
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

void NodeApp::changeView(void) {
    // 处理视图变更，随机选择一个新节点作为领导者
    int new_id = -1;
    do {
        new_id = rand() % N;
    } while (static_cast<uint8_t>(new_id) == leader_id);

    // 设置新的领导者ID并更新当前节点的领导者状态
    leader_id = new_id;
    if (m_id != static_cast<uint8_t>(new_id)) {
        is_leader = 0;
    } else {
        is_leader = 1;
    }

    // 更新视图变更变量
    view_is_changed++;

    // 构造视图变更消息
    std::string data[7]; 

    data[2] = '0';
    data[4] = '0';
    data[3] = '0';
    data[5] = '0';
    data[6] = '0';

    // 增加视图编号
    view_number++;

    // 设置消息类型为视图变更
    data[1] = convertIntToChar(VIEW_CHANGE);

    // 设置新领导者
    data[0] = convertIntToChar(leader_id);

    // 广播视图变更消息
    std::string dataString = std::accumulate(std::begin(data), std::end(data), std::string());
    NS_LOG_INFO("New Leader Id => " << leader_id);
    NS_LOG_INFO("Message(VIEW-CHANGE) Broadcasts => " << dataString << "\n\n");
    sendStringMessage(dataString);
}

/*******************************SEND*******************************/
// 向相关套接字发送数据包
void SendPacket(Ptr<Socket> socketClient, Ptr<Packet> p) {
    socketClient->Send(p);
}

// 将字符串消息转换为uint8_t类型并广播
void NodeApp::sendStringMessage(std::string message) {
    std::vector<uint8_t> myVector(message.begin(), message.end());
    uint8_t* d = &myVector[0];
    NodeApp::SendTX(d, message.size());    
}

// 向所有邻居节点广播交易
void NodeApp::SendTX(uint8_t data[], int size) {
    double delay = getRandomDelay();
    SendTXWithDelay(data, size, delay);
}

// 向所有邻居节点广播交易（带延迟）
void NodeApp::SendTXWithDelay(uint8_t data[], int size, double delay) {
    // 检查m_peersSockets是否为空
    if (m_peersSockets.empty()) {
        NS_LOG_ERROR("Cannot send message, m_peersSockets is empty!");
        return;
    }
    
    Ptr<Packet> p;
    p = Create<Packet>(reinterpret_cast<const uint8_t*>(data), size);
    
    for (const auto& peerPair : m_peersSockets) {
        // 检查单个socket是否为空
        if (!peerPair.second) {
            NS_LOG_WARN("Skipping invalid socket for peer");
            continue;
        }
        // 获取socket
        Ptr<Socket> socketClient = peerPair.second;
        Simulator::Schedule(Seconds(delay), SendPacket, socketClient, p);
    }
}

/*******************************UTILS*******************************/
static char convertIntToChar(int a) {
    if (a >= 0 && a <= 9) {
        return a + '0';
    } else if (a >= 10 && a <= 15) {
        return a - 10 + 'A';
    } else {
        NS_LOG_ERROR("Attempt to convert out-of-range integer '" << a << "' to character");
        return '0'; // 返回安全的默认值
    }
}

static int convertCharToInt(char a) {
    if (a >= '0' && a <= '9') {
        return a - '0';
    } else if (a >= 'A' && a <= 'F') {
        return a - 'A' + 10;
    } else if (a >= 'a' && a <= 'f') {
        return a - 'a' + 10;
    } else {
        NS_LOG_ERROR("Attempt to convert non-numeric character '" << a << "' to integer");
        return 0; // 返回安全的默认值
    }
}

float getRandomDelay() {
    return (rand() % 3) * 1.0 / 1000;
}

// 打印每个节点和区块链信息
void NodeApp::printInformation() {
    NS_LOG_INFO("=============== Information Node(Replica) " << m_id << " ===============");
    NS_LOG_INFO("Leader id " << leader_id);
    NS_LOG_INFO("Is Leader " << is_leader);
    NS_LOG_INFO("This Id " << m_id);
    NS_LOG_INFO("Sequence number " << sec_num);
    NS_LOG_INFO("===========================================================\n\n");        
}

void log_message_counts() {
    // 可选：记录消息计数
    //NS_LOG_INFO("Request count=> " << request_count << "    Pre-prepare count=> " << preprepare_count << "   Prepare count=> " << prepare_count << "   Commit count=> " << commit_count << "   Reply count=> " << reply_count);
}

void NodeApp::PrintStatistics() {
    // 打印统计信息，可选实现
}

} // namespace ns3