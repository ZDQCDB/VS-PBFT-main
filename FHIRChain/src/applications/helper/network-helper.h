#ifndef NETWORK_HELPER_H
#define NETWORK_HELPER_H

#include "ns3/application-container.h"
#include "ns3/node-container.h"
#include "ns3/ipv4-address.h"
#include <vector>

namespace ns3 {

class NetworkHelper
{
public:
  NetworkHelper(int n);

  ApplicationContainer Install(NodeContainer c);

  std::map<int, std::vector<Ipv4Address>> m_nodesConnectionsIps;

private:
  int m_nodes;

};

} // namespace ns3

#endif /* NETWORK_HELPER_H */