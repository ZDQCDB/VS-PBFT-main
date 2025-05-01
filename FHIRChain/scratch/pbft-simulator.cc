#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/global-value.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"

using namespace ns3;

// 在全局作用域定义GlobalValue对象
static GlobalValue g_fhirRounds ("FhirRounds",
                               "Number of consensus rounds",
                               UintegerValue (20),
                               MakeUintegerChecker<uint32_t> ());
                               
static GlobalValue g_enableAudit ("EnableAudit",
                                "Enable audit trail functionality",
                                BooleanValue (true),
                                MakeBooleanChecker ());

NS_LOG_COMPONENT_DEFINE("BlockchainSimulator");

void startSimulator(int N) {
  NodeContainer nodes;
  nodes.Create(N);

  NetworkHelper networkHelper(N);
  NetDeviceContainer devices;
  PointToPointHelper pointToPoint;

  pointToPoint.SetDeviceAttribute("DataRate", StringValue("5Mbps"));
  pointToPoint.SetChannelAttribute("Delay", StringValue("2ms"));

  InternetStackHelper stack;
  stack.Install(nodes);

  Ipv4AddressHelper address;
  address.SetBase("10.1.1.0", "255.255.255.0");

  // 确保每个节点的 m_nodesConnectionsIps 初始化为空 vector
  for (int i = 0; i < N; ++i) {
      networkHelper.m_nodesConnectionsIps[i] = std::vector<Ipv4Address>();
  }
  
  // 两个for循环分配节点IP地址，点对点通信
  for (int i = 0; i < N; i++) {
      for (int j = 0; j < N && j != i; j++) {
          Ipv4InterfaceContainer interface;
          Ptr<Node> p1 = nodes.Get(i);
          Ptr<Node> p2 = nodes.Get(j);
          NetDeviceContainer device = pointToPoint.Install(p1, p2);
          
          interface.Add(address.Assign(device.Get(0)));
          interface.Add(address.Assign(device.Get(1)));

          networkHelper.m_nodesConnectionsIps[i].push_back(interface.GetAddress(1));
          networkHelper.m_nodesConnectionsIps[j].push_back(interface.GetAddress(0));

          address.NewNetwork();
      }
  }
  
  ApplicationContainer nodeApp = networkHelper.Install(nodes);
  
  // 分配好IP地址，开始PBFT共识
  nodeApp.Start(Seconds(1.0));
  nodeApp.Stop(Seconds(100.0));

  Simulator::Run();
  Simulator::Destroy();
}

int main(int argc, char *argv[]) {
  CommandLine cmd;
  
  // 添加命令行参数
  int N = 10;  // 默认节点数
  int roundCount = 20;  // 默认轮次
  bool enableAudit = true;  // 默认启用审计
  
  cmd.AddValue("nodes", "Number of nodes", N);
  cmd.AddValue("rounds", "Number of consensus rounds", roundCount);
  cmd.AddValue("audit", "Enable audit trail", enableAudit);
  cmd.Parse(argc, argv);
  
  // 设置全局环境变量
  GlobalValue::Bind("FhirRounds", UintegerValue(roundCount));
  GlobalValue::Bind("EnableAudit", BooleanValue(enableAudit));
  
  Time::SetResolution(Time::NS);

  // 启用日志
  LogComponentEnable("NodeApp", LOG_LEVEL_INFO);
  LogComponentEnable("BlockchainSimulator", LOG_LEVEL_INFO);
  
  NS_LOG_INFO("启动FHIRChain模拟，节点数: " << N << "，轮次: " << roundCount);
  
  // 启动模拟器
  startSimulator(N);

  return 0;
}