#include "../src/aodv/helper/aodv-helper.h"
#include "../src/applications/helper/udp-echo-helper.h"
#include "../src/core/model/command-line.h"
#include "../src/core/model/double.h"
#include "../src/core/model/log.h"
#include "../src/core/model/object.h"
#include "../src/core/model/simulator.h"
#include "../src/core/model/string.h"
#include "../src/core/model/uinteger.h"
#include "../src/core/model/vector.h"
#include "../src/flow-monitor/helper/flow-monitor-helper.h"
#include "../src/flow-monitor/model/ipv4-flow-classifier.h"
#include "../src/internet/helper/internet-stack-helper.h"
#include "../src/internet/helper/ipv4-address-helper.h"
#include "../src/internet/model/ipv4.h"
#include "../src/mesh/helper/mesh-helper.h"
#include "../src/mobility/helper/mobility-helper.h"
#include "../src/mobility/model/mobility-model.h"
#include "../src/mobility/model/position-allocator.h"
#include "../src/netanim/model/animation-interface.h"
#include "../src/network/helper/application-container.h"
#include "../src/network/helper/net-device-container.h"
#include "../src/network/helper/node-container.h"
#include "../src/network/model/application.h"
#include "../src/network/model/packet-metadata.h"
#include "../src/network/model/socket.h"
#include "../src/network/utils/inet-socket-address.h"
#include "../src/network/utils/ipv4-address.h"
#include "../src/olsr/helper/olsr-helper.h"
#include "../src/wifi/helper/yans-wifi-helper.h"
#include "../src/wifi/model/wifi-standards.h"

#include "ns3/aodv-module.h"
#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/dsdv-module.h"
#include "ns3/dsr-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mesh-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/olsr-module.h"
#include "ns3/wifi-module.h"

#include <algorithm>
#include <cmath>
#include <deque>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <vector>

namespace ns3
{
class Socket;
class FlowMonitor;
}

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("EmergencyMeshMultiProtocolSimulation");

// 1. DTN Spray & Wait Store-Carry-and-Forward Application

struct DtnBundle
{
    Ptr<Packet> packet;
    Ipv4Address destination;
    uint16_t port;
    uint32_t tickets;
    Time creationTime;
};

class SprayAndWaitApplication : public Application
{
public:
    SprayAndWaitApplication() : m_initialTickets(8), m_maxBufferSize(100), m_checkInterval
    (Seconds(1.0)), m_nodeId(0) {}

    void Setup(const Ptr<Socket>& socket, const uint32_t L, NodeContainer allNodes, uint32_t
        nodeIndex)
    {
        m_socket = socket;
        m_initialTickets = L;
        m_allNodes = allNodes;
        m_nodeId = nodeIndex;
    }

    void SendEmergencyAlert(const Ipv4Address destIp, const uint16_t destPort, uint32_t packetSize)
    {
        if (m_buffer.size() >= m_maxBufferSize)
        {
            m_buffer.pop_front();
        }
        const Ptr<Packet> pkt = Create<Packet>(packetSize);
        const DtnBundle bundle = {.packet = pkt, .destination = destIp, .port = destPort, .tickets = m_initialTickets, .creationTime = Simulator::Now()};
        m_buffer.push_back(bundle);
    }

    void CheckNeighborsAndSpray()
    {
        if (m_buffer.empty())
        {
            ScheduleNextCheck();
            return;
        }

        Ptr<Node> myNode = m_allNodes.Get(m_nodeId);
        Ptr<MobilityModel> myMob = myNode->GetObject<MobilityModel>();
        Vector myPos = myMob->GetPosition();

        for (uint32_t i = 0; i < m_allNodes.GetN(); ++i)
        {
            if (i == m_nodeId) continue;

            Ptr<Node> otherNode = m_allNodes.Get(i);
            Ptr<MobilityModel> otherMob = otherNode->GetObject<MobilityModel>();
            Vector otherPos = otherMob->GetPosition();

            double dist = (myPos - otherPos).GetLength();

            if (dist <= 120.0)
            {
                Ptr<Ipv4> ipv4 = otherNode->GetObject<Ipv4>();
                Ipv4Address otherIp = ipv4->GetAddress(1, 0).GetLocal();

                for (auto it = m_buffer.begin(); it != m_buffer.end();)
                {
                    if (it->destination == otherIp)
                    {
                        m_socket->SendTo(it->packet, 0, InetSocketAddress(otherIp, it->port));
                        it = m_buffer.erase(it);
                    }
                    else if (it->tickets > 1)
                    {
                        uint32_t sprayedTickets = it->tickets / 2;
                        it->tickets -= sprayedTickets;

                        Ptr<Packet> copyPacket = it->packet->Copy();
                        m_socket->SendTo(copyPacket, 0, InetSocketAddress(otherIp, it->port));
                        ++it;
                    }
                    else
                    {
                        ++it;
                    }
                }
            }
        }
        ScheduleNextCheck();
    }

protected:
    void StartApplication() override
    {
        m_socket->SetRecvCallback(MakeCallback(&SprayAndWaitApplication::HandleReceive, this));
        ScheduleNextCheck();
    }

    void StopApplication() override
    {
        Simulator::Cancel(m_timerEvent);
        if (m_socket)
        {
            m_socket->Close();
        }
    }

private:
    void ScheduleNextCheck()
    {
        m_timerEvent = Simulator::Schedule(m_checkInterval,
            &SprayAndWaitApplication::CheckNeighborsAndSpray, this);
    }

    void HandleReceive(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) {
            // Process incoming DTN bundle
        }
    }

    Ptr<Socket> m_socket;
    uint32_t m_initialTickets;
    uint32_t m_maxBufferSize;
    Time m_checkInterval;
    EventId m_timerEvent;
    NodeContainer m_allNodes;
    uint32_t m_nodeId;
    std::deque<DtnBundle> m_buffer;
};

// Main Simulation Script

int main(int argc, char *argv[])
{
    double simTime = 110.0; // Total simulation time in seconds
    uint32_t numNodes = 30; // 30 emergency mesh nodes
    std::string protocol = "AODV";
    bool enableDtn = true;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Total simulation time in seconds", simTime);
    cmd.AddValue("protocol", "Routing protocol: AODV, OLSR, or HWMP", protocol);
    cmd.AddValue("enableDtn", "Enable DTN Spray & Wait Fallback Application", enableDtn);
    cmd.Parse(argc, argv);

    Time::SetResolution(Time::NS);
    PacketMetadata::Enable();

    NodeContainer nodes;
    nodes.Create(numNodes);

    YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default();
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel", "MaxRange", DoubleValue(120.0));

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    NetDeviceContainer devices;
    InternetStackHelper stack;

    if (protocol == "HWMP" || protocol == "hwmp")
    {
        MeshHelper mesh = MeshHelper::Default();
        mesh.SetStackInstaller("ns3::Dot11sStack");
        mesh.SetNumberOfInterfaces(1);

        devices = mesh.Install(wifiPhy, nodes);
        stack.Install(nodes);
    }
    else
    {
        wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue
            ("DsssRate2Mbps"), "ControlMode", StringValue("DsssRate1Mbps"));

        WifiMacHelper wifiMac;
        wifiMac.SetType("ns3::AdhocWifiMac");
        devices = wifi.Install(wifiPhy, wifiMac, nodes);

        if (protocol == "OLSR" || protocol == "olsr")
        {
            OlsrHelper olsr;
            stack.SetRoutingHelper(olsr);
            stack.Install(nodes);
        }
        else
        {
            AodvHelper aodv;
            stack.SetRoutingHelper(aodv);
            stack.Install(nodes);
        }
    }

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    Ptr<RandomRectanglePositionAllocator> positionAlloc =
        CreateObject<RandomRectanglePositionAllocator>();
    positionAlloc->SetAttribute("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));
    positionAlloc->SetAttribute("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=300.0]"));

    MobilityHelper mobility;
    mobility.SetPositionAllocator(positionAlloc);

    mobility.SetMobilityModel("ns3::RandomWaypointMobilityModel", "Speed", StringValue
        ("ns3::UniformRandomVariable[Min=1.0|Max=3.0]"), "Pause", StringValue
        ("ns3::ConstantRandomVariable[Constant=2.0]"), "PositionAllocator", PointerValue
        (positionAlloc));

    mobility.Install(nodes);

    if (!enableDtn)
    {
        // Pair 1: Node 0 -> Node 29
        UdpEchoServerHelper server1(9);
        ApplicationContainer serverApps = server1.Install(nodes.Get(29));
        serverApps.Start(Seconds(1.0));
        serverApps.Stop(Seconds(simTime));

        UdpEchoClientHelper client1(interfaces.GetAddress(29), 9);
        client1.SetAttribute("MaxPackets", UintegerValue(45));
        client1.SetAttribute("Interval", TimeValue(Seconds(2.0)));
        client1.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps1 = client1.Install(nodes.Get(0));
        cApps1.Start(Seconds(3.0));
        cApps1.Stop(Seconds(simTime));

        // Pair 2: Node 5 -> Node 25
        UdpEchoServerHelper server2(10);
        ApplicationContainer sApps2 = server2.Install(nodes.Get(25));
        sApps2.Start(Seconds(1.0));
        sApps2.Stop(Seconds(simTime));

        UdpEchoClientHelper client2(interfaces.GetAddress(25), 10);
        client2.SetAttribute("MaxPackets", UintegerValue(45));
        client2.SetAttribute("Interval", TimeValue(Seconds(2.0)));
        client2.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps2 = client2.Install(nodes.Get(5));
        cApps2.Start(Seconds(4.0));
        cApps2.Stop(Seconds(simTime));

        // Pair 3: Node 10 -> Node 20
        UdpEchoServerHelper server3(11);
        ApplicationContainer sApps3 = server3.Install(nodes.Get(20));
        sApps3.Start(Seconds(1.0));
        sApps3.Stop(Seconds(simTime));

        UdpEchoClientHelper client3(interfaces.GetAddress(20), 11);
        client3.SetAttribute("MaxPackets", UintegerValue(35));
        client3.SetAttribute("Interval", TimeValue(Seconds(2.5)));
        client3.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps3 = client3.Install(nodes.Get(10));
        cApps3.Start(Seconds(5.0));
        cApps3.Stop(Seconds(simTime));

        // Pair 4: Node 15 -> Node 28
        UdpEchoServerHelper server4(12);
        ApplicationContainer sApps4 = server4.Install(nodes.Get(28));
        sApps4.Start(Seconds(1.0));
        sApps4.Stop(Seconds(simTime));

        UdpEchoClientHelper client4(interfaces.GetAddress(28), 12);
        client4.SetAttribute("MaxPackets", UintegerValue(30));
        client4.SetAttribute("Interval", TimeValue(Seconds(3.0)));
        client4.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps4 = client4.Install(nodes.Get(15));
        cApps4.Start(Seconds(6.0));
        cApps4.Stop(Seconds(simTime));
    }
    else
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        std::vector<Ptr<SprayAndWaitApplication>> dtnApps(numNodes);

        for (uint32_t i = 0; i < numNodes; ++i)
        {
            Ptr<Socket> dtnSocket = Socket::CreateSocket(nodes.Get(i), tid);
            dtnSocket->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9999));

            dtnApps[i] = CreateObject<SprayAndWaitApplication>();
            dtnApps[i]->Setup(dtnSocket, 8, nodes, i);
            nodes.Get(i)->AddApplication(dtnApps[i]);
            dtnApps[i]->SetStartTime(Seconds(1.0));
            dtnApps[i]->SetStopTime(Seconds(simTime));
        }

        // Pair 1: Node 0 -> Node 29
        for (int p = 0; p < 45; p++)
        {
            Simulator::Schedule(Seconds(3.0 + p * 2.0),
                &SprayAndWaitApplication::SendEmergencyAlert, dtnApps[0], interfaces.GetAddress
                (29), 9999, 250);
        }

        // Pair 2: Node 5 -> Node 25
        for (int p = 0; p < 45; p++)
        {
            Simulator::Schedule(Seconds(4.0 + p * 2.0),
                &SprayAndWaitApplication::SendEmergencyAlert, dtnApps[5], interfaces.GetAddress
                (25), 9999, 250);
        }

        // Pair 3: Node 10 -> Node 20
        for (int p = 0; p < 35; p++)
        {
            Simulator::Schedule(Seconds(5.0 + p * 2.5),
                &SprayAndWaitApplication::SendEmergencyAlert, dtnApps[10], interfaces.GetAddress
                (20), 9999, 250);
        }

        // Pair 4: Node 15 -> Node 28
        for (int p = 0; p < 30; p++)
        {
            Simulator::Schedule(Seconds(6.0 + p * 3.0),
                &SprayAndWaitApplication::SendEmergencyAlert, dtnApps[15], interfaces.GetAddress
                (28), 9999, 250);
        }

        std::cout << "DTN Mode Active: Traffic routed via Spray & Wait Store-Carry-and-Forward "
                     "Queue\n";
    }

    AnimationInterface anim("emergency_mesh_adhoc.xml");

    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        std::string label = "Node-" + std::to_string(i);
        anim.UpdateNodeSize(nodes.Get(i), 10.0, 10.0);

        if (i == 0)
        {
            label = "Src 1";
            anim.UpdateNodeColor(nodes.Get(i), 0, 200, 0);
        }
        else if (i == 5)
        {
            label = "Src 2";
            anim.UpdateNodeColor(nodes.Get(i), 0, 180, 252);
        }
        else if (i == 10)
        {
            label = "Src 3";
            anim.UpdateNodeColor(nodes.Get(i), 30, 144, 255);
        }
        else if (i == 15)
        {
            label = "Src 4";
            anim.UpdateNodeColor(nodes.Get(i), 238, 130, 238);
        }
        else if (i == 29)
        {
            label = "Dst 1";
            anim.UpdateNodeColor(nodes.Get(i), 255, 0, 0);
        }
        else if (i == 25)
        {
            label = "Dst 2";
            anim.UpdateNodeColor(nodes.Get(i), 178, 34, 34);
        }
        else if (i == 20)
        {
            label = "Dst 3";
            anim.UpdateNodeColor(nodes.Get(i), 128, 0, 128);
        }
        else if (i == 28)
        {
            label = "Dst 4";
            anim.UpdateNodeColor(nodes.Get(i), 139, 0, 0);
        }
        else
        {
            label = "Relay (" + std::to_string(i) + ")";
            anim.UpdateNodeColor(nodes.Get(i), 255, 140, 0);
        }

        anim.UpdateNodeDescription(nodes.Get(i), label);
    }

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper
        .GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    std::string csvFileName = "flowmon_results_" + protocol + (enableDtn ? "_DTN.csv" : ".csv");
    std::ofstream csvFile(csvFileName, std::ios::out);

    csvFile << "Protocol,FlowID,SrcAddr,SrcPort,DstAddr,DstPort,FlowType,TxPackets,RxPackets,"
               "LostPackets,PDR_Percent,AvgDelay_ms,Throughput_Kbps\n";

    std::cout << "FLOW MONITOR PERFORMANCE REPORT [Protocol: " << protocol << "]\n";

    for (auto iter = stats.begin(); iter != stats.end(); ++iter)
    {
        Ipv4FlowClassifier::FiveTuple tuple = classifier->FindFlow(iter->first);
        std::string flowType = "Control";
        if ((tuple.destinationPort >= 9 && tuple.destinationPort <= 12) || (tuple.sourcePort >= 9
            && tuple.sourcePort <= 12) || tuple.destinationPort == 9999 || tuple.sourcePort == 9999)
        {
            flowType = "Application";
        }
        else if (tuple.destinationPort == 654 || tuple.sourcePort == 654)
        {
            flowType = "AODV_Control";
        }
        else if (tuple.destinationPort == 698 || tuple.sourcePort == 698)
        {
            flowType = "OLSR_Control";
        }

        double pdr = 0.0;
        double meanDelay = 0.0;
        double throughputKbps = 0.0;

        if (iter->second.rxPackets > 0)
        {
            pdr = static_cast<double>(iter->second.rxPackets) / iter->second.txPackets * 100.0;
            meanDelay = (iter->second.delaySum.GetSeconds() / iter->second.rxPackets) * 1000.0;
            double rxDuration = iter->second.timeLastRxPacket.GetSeconds() - iter->second
            .timeFirstTxPacket.GetSeconds();

            if (rxDuration > 0)
            {
                throughputKbps = (iter->second.rxBytes * 8.0 / rxDuration) / 1000.0;
            }
        }

        csvFile << protocol << ","
        << iter->first << ","
        << tuple.sourceAddress << ","
        << tuple.sourcePort << ","
        << tuple.destinationAddress << ","
        << tuple.destinationPort << ","
        << flowType << ","
        << iter->second.txPackets << ","
        << iter->second.rxPackets << ","
        << iter->second.lostPackets << ","
        << pdr << ","
        << meanDelay << ","
        << throughputKbps << "\n";

        if (flowType == "Application")
        {
            std::cout << "APP FLOW ID " << iter->first << "(" << tuple.sourceAddress << ":" <<
                tuple.sourcePort << " -> " << tuple.destinationAddress << ":" << tuple.destinationPort << ")\n";

            std::cout << "  Tx Packets : " << iter->second.txPackets << " | Rx Packets : " <<
                iter->second.rxPackets << " | Lost : " << iter->second.lostPackets << "\n";

            std::cout << "  PDR: " << pdr << " % | Avg Delay: " << meanDelay
            << "ms | Throughput: " << throughputKbps << " Kbps\n";
        }
    }

    csvFile.close();
    std::cout << "Results successfully exported to " << csvFileName << "\n\n";

    Simulator::Destroy();
    return 0;
}