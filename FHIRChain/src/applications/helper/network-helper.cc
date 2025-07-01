#include "network-helper.h"
#include "../model/node-app.h"
#include "ns3/integer.h"
#include "ns3/names.h"
#include "ns3/ipv4.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/inet-socket-address.h"

namespace ns3 {

NetworkHelper::NetworkHelper(int n)
  : m_nodes(n)
{
  // 初始化节点连接
  m_nodesConnectionsIps.clear();
}

ApplicationContainer
NetworkHelper::Install(NodeContainer c)
{
  ApplicationContainer apps;

  for (uint32_t i = 0; i < c.GetN(); ++i) {
    Ptr<NodeApp> app = CreateObject<NodeApp>();
    // 设置节点ID
    app->m_id = i;

    // 设置节点数
    app->N = m_nodes;

    // 设置初始领导者
    if (i == 0) {
      app->is_leader = 1;
      app->leader_id = 0;
    } else {
      app->is_leader = 0;
      app->leader_id = 0;
    }

    // 设置初始序列号和视图编号
    app->sec_num = 1;
    app->view_number = 0;
    app->client_id = 0;

    // 获取节点IP
    Ptr<Ipv4> ipv4 = c.Get(i)->GetObject<Ipv4>();
    
    // 设置邻居连接
    for (uint32_t j = 0; j < m_nodesConnectionsIps[i].size(); j++) {
      app->m_peersAddresses.push_back(m_nodesConnectionsIps[i][j]);
    }

    c.Get(i)->AddApplication(app);
    apps.Add(app);
  }

  return apps;
}

} // namespace ns3
