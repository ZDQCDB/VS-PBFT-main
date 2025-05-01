#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("BlockchainSimulator");

void startSimulator (int N) {

  NodeContainer nodes;
  nodes.Create (N);

  NetworkHelper networkHelper (N);
  NetDeviceContainer devices;
  PointToPointHelper pointToPoint;

  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("3Mbps"));    // Transmission rate is 3Mbps
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("3ms"));        // Network delay is 3ms

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("1.0.0.0", "255.255.255.0");   // IP address range

  // Ensure that each node's m_nodesConnectionsIps is initialized as an empty vector
  for (int i = 0; i < N; ++i) {
      networkHelper.m_nodesConnectionsIps[i] = std::vector<Ipv4Address>();
  }
  // Two for loops to assign node IP addresses, point-to-point communication
  for (int i = 0; i < N; i++) {
      for (int j = 0; j < N && j != i; j++) {
          Ipv4InterfaceContainer interface;
          Ptr<Node> p1 = nodes.Get (i);   // Establish connections for two nodes, create network device NetDevice
          Ptr<Node> p2 = nodes.Get (j);
          NetDeviceContainer device = pointToPoint.Install(p1, p2);
          
          interface.Add(address.Assign (device.Get(0)));    // Assign IP addresses to both ends
          interface.Add(address.Assign (device.Get(1)));

          networkHelper.m_nodesConnectionsIps[i].push_back(interface.GetAddress(1));    // Record to m_nodesConnectionsIps
          networkHelper.m_nodesConnectionsIps[j].push_back(interface.GetAddress(0));

          address.NewNetwork();   // Prepare to assign the next one
      }
  }
  ApplicationContainer nodeApp = networkHelper.Install (nodes);
  
  // IP addresses assigned, start PBFT consensus
  nodeApp.Start (Seconds (0.0));
  nodeApp.Stop (Seconds (10.0));

  Simulator::Run ();
  Simulator::Destroy ();

}


int main (int argc, char *argv[]) {
  CommandLine cmd;
  cmd.Parse (argc, argv);
  
  int N = 9;
  
  Time::SetResolution (Time::NS);   // Time unit: nanosecond

  LogComponentEnable ("NodeApp", LOG_LEVEL_INFO);

  // start the simulator
  startSimulator(N);

  return 0;
}