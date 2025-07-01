#include "ns3/core-module.h" 
#include "network-helper.h"
#include "ns3/string.h"
#include "ns3/inet-socket-address.h"
#include "ns3/names.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"


namespace ns3 {
    NetworkHelper::NetworkHelper(uint32_t totalNoNodes) {
        m_factory.SetTypeId ("ns3::NodeApp");
        m_nodeNo = totalNoNodes;
    }

    ApplicationContainer
    NetworkHelper::Install (NodeContainer c)
    { 
        std::srand(static_cast<unsigned int>(time(0)));
        ApplicationContainer apps;
        int j = 0;

        int leader_id = (rand() % m_nodeNo);
        
        for (NodeContainer::Iterator i = c.Begin (); i != c.End (); i++)
        {
            Ptr<NodeApp> app = m_factory.Create<NodeApp> ();        //创建应用实例
            uint32_t nodeId = (*i)->GetId();        //获取节点ID
            app->m_id = nodeId;                     //设置应用程序的节点ID
            app->N = m_nodeNo;                      //设置总结点数

            if (j == leader_id) {                   //选中标记为主节点
                app->is_leader = 1;
            } else {
                app->is_leader = 0;
            }

            app->leader_id= leader_id;
            app->view_number = 1;
            app->client_id = -1;
            app->sec_num = 0;
            app->m_peersAddresses = m_nodesConnectionsIps[nodeId];      //获取节点的连接IP地址
            (*i)->AddApplication (app);             //将用于程序添加到节点上
            apps.Add (app);                         //将应用程序加入到应用容器
            j++;
        }
        return apps;                                //返回容器
    }
}
