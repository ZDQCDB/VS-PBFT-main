#ifndef NODE_APP_H
#define NODE_APP_H

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/traced-callback.h"
#include "ns3/socket.h"
#include <string>
#include <vector>
#include <map>

namespace ns3 {

// FHIR资源类型枚举
enum FHIRResourceType {
  PATIENT,
  OBSERVATION,
  MEDICATION,
  IMMUNIZATION,
  DIAGNOSTIC_REPORT,
  CONDITION,
  HEART_DISEASE    // 添加心脏病数据类型
};

// PBFT共识阶段枚举
enum PBFTPhase {
  CLIENT_CHANGE,  // 0 客户端变更
  NEW_ROUND,      // 1 新回合
  REQUEST,        // 2 请求
  PRE_PREPARED,   // 3 预准备阶段
  PREPARED,       // 4 准备阶段
  COMMITTED,      // 5 提交阶段
  REPLY,          // 6 回复阶段
  VIEW_CHANGE     // 7 视图变更
};

// FHIR资源基类
struct FHIRResource {
  std::string id;
  std::string versionId;
  std::string lastUpdated;
  FHIRResourceType type;
  
  virtual std::string toString() const {
    return id + "," + versionId + "," + lastUpdated;
  }
  
  virtual ~FHIRResource() {}
};

// FHIR患者资源
struct FHIRPatient : public FHIRResource {
  std::string name;
  std::string gender;
  std::string birthDate;
  
  std::string toString() const override {
    return FHIRResource::toString() + "," + name + "," + gender + "," + birthDate;
  }
};

// FHIR观察资源
struct FHIRObservation : public FHIRResource {
  std::string patientId;
  std::string code;
  std::string value;
  std::string unit;
  
  std::string toString() const override {
    return FHIRResource::toString() + "," + patientId + "," + code + "," + value + "," + unit;
  }
};

// 心脏病数据结构
struct FHIRHeartDisease : public FHIRResource {
  int age;
  int sex;         // 1=男性, 0=女性
  int cp;          // 胸痛类型
  int trestbps;    // 静息血压
  int chol;        // 胆固醇水平
  int fbs;         // 空腹血糖
  int restecg;     // 静息心电图结果
  int thalach;     // 最大心率
  int exang;       // 运动诱发心绞痛
  float oldpeak;   // ST段压低
  int slope;       // ST段斜率
  int ca;          // 冠状动脉数量
  int thal;        // 地中海贫血类型
  int target;      // 诊断结果
  
  std::string toString() const override {
    return FHIRResource::toString() + "," + 
           std::to_string(age) + "," + 
           std::to_string(sex) + "," + 
           std::to_string(cp) + "," + 
           std::to_string(trestbps) + "," + 
           std::to_string(chol) + "," + 
           std::to_string(fbs) + "," + 
           std::to_string(restecg) + "," + 
           std::to_string(thalach) + "," + 
           std::to_string(exang) + "," + 
           std::to_string(oldpeak) + "," + 
           std::to_string(slope) + "," + 
           std::to_string(ca) + "," + 
           std::to_string(thal) + "," + 
           std::to_string(target);
  }
};

// 交易数据结构
struct Transaction {
  int view;              // 视图编号
  int value;             // 交易的值
  int prepare_vote;      // 准备阶段的投票数
  int commit_vote;       // 提交阶段的投票数
  std::string resourceId; // FHIR资源ID
  std::string auditInfo;  // 审计信息
};

class NodeApp : public Application
{
public:
  static TypeId GetTypeId(void);

  NodeApp(void);
  virtual ~NodeApp(void);

  // 节点属性
  uint32_t        m_id;                               // 节点ID
  Ptr<Socket>     m_socket;                           // 监听套接字
  std::map<Ipv4Address, Ptr<Socket>> m_peersSockets;  // 邻居节点套接字列表
  std::map<Address, std::string>     m_bufferedData;  // 缓冲数据映射
  
  Address         m_local;                            // 本节点地址
  std::vector<Ipv4Address> m_peersAddresses;          // 邻居列表

  std::vector<char> ledger;                           // 账本
  std::vector<FHIRResource*> fhirLedger;              // FHIR资源账本
  
  // PBFT相关变量
  int             N;                                  // 节点总数
  int             is_leader;                          // 是否为领导者
  int             sec_num;                            // 交易序列号
  int             view_number;                        // 视图节点ID
  int             leader_id;                          // 领导者ID
  int             client_id;                          // 客户端ID
  int             total_rounds;                       // 总轮次

  // 交易数组
  static const int arraySize = 1000;                    
  Transaction transactions[arraySize];                

  // 时间测量
  Time round_start_time;
  Time round_end_time;
  Time total_time;
  Time latency_start_time;
  Time latency_end_time;
  Time audit_trail_start_time;
  Time audit_trail_end_time;
  std::vector<double> audit_trail_times;              // 审计追踪时间记录
  bool enable_audit;                                  // 是否启用审计
  
  // 消息统计
  int round_message_count;
  int total_message_count;
  int message_copies_count;

  // 应用生命周期方法
  virtual void StartApplication(void);
  virtual void StopApplication(void);

  // 消息处理方法
  void HandleRead(Ptr<Socket> socket);
  std::string getPacketContent(Ptr<Packet> packet, Address from);
  
  // 交易相关方法
  void SendTX(uint8_t data[], int num);
  void SendTXWithDelay(uint8_t data[], int size, double delay);
  void initiateRound(void);
  void changeView(void);
  void sendStringMessage(std::string data);
  
  // 信息打印与统计
  void printInformation();
  void PrintStatistics();
  
  // FHIR资源加载方法
  void LoadFHIRResources(const std::string& filePath);
  std::string GenerateAuditTrail(const FHIRResource& resource, const std::string& action);
  
private:
  // FHIR资源数据集
  std::vector<FHIRResource*> fhirDataset;
  std::vector<FHIRPatient> patientDataset;
  std::vector<FHIRObservation> observationDataset;
  std::vector<FHIRHeartDisease> heartDiseaseDataset; // 心脏病数据集
};

} // namespace ns3

#endif /* NODE_APP_H */