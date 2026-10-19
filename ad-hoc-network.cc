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
#include "../src/dsdv/helper/dsdv-helper.h"
#include "../src/dsr/helper/dsr-main-helper.h"
#include "../src/flow-monitor/helper/flow-monitor-helper.h"
#include "../src/flow-monitor/model/flow-monitor.h"
#include "../src/flow-monitor/model/ipv4-flow-classifier.h"
#include "../src/internet/helper/internet-stack-helper.h"
#include "../src/internet/helper/ipv4-address-helper.h"
#include "../src/internet/helper/ipv4-list-routing-helper.h"
#include "../src/internet/model/ipv4-header.h"
#include "../src/internet/model/ipv4-routing-protocol.h"
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
#include <ranges>
#include <set>
#include <vector>

namespace ns3
{
class Socket;
class FlowMonitor;
}

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("EmergencyMeshMultiProtocolSimulation");

struct E2EFlowStats
{
    uint16_t flowId = 0;
    Ipv4Address srcAddr;
    uint16_t srcPort = 0;
    Ipv4Address dstAddr;
    uint16_t dstPort = 0;
    uint32_t txPackets = 0;
    uint32_t rxPackets = 0;
    uint64_t txBytes = 0;
    uint64_t rxBytes = 0;
    Time timeFirstTx = Seconds(0.0);
    Time timeLastTx = Seconds(0.0);
    Time timeFirstRx = Seconds(0.0);
    Time timeLastRx = Seconds(0.0);
    Time delaySum = Seconds(0.0);
    std::set<uint32_t> seenSeqs;
};

struct SentPacketMeta
{
    uint16_t flowId;
    uint32_t seqNum;
    uint64_t txTimeNs;
};

static std::map<uint16_t, E2EFlowStats> g_e2eFlows;
static std::map<uint64_t, SentPacketMeta> g_uidToFlowMap;

static void RecordE2ETx(uint16_t flowId, uint32_t seqNum, uint32_t pktSize)
{
    E2EFlowStats& st = g_e2eFlows[flowId];
    st.txPackets++;
    st.txBytes += pktSize;
    Time now = Simulator::Now();
    if (st.txPackets == 1)
    {
        st.timeFirstTx = now;
    }
    st.timeLastTx = now;
}

static void RecordE2ERx(uint16_t flowId, uint32_t seqNum, uint32_t pktSize, uint64_t txTimeNs)
{
    E2EFlowStats& st = g_e2eFlows[flowId];
    if (st.seenSeqs.find(seqNum) != st.seenSeqs.end())
    {
        return;
    }
    st.seenSeqs.insert(seqNum);
    st.rxPackets++;
    st.rxBytes += pktSize;
    Time now = Simulator::Now();
    if (st.rxPackets == 1)
    {
        st.timeFirstRx = now;
    }
    st.timeLastRx = now;
    if (now.GetNanoSeconds() >= static_cast<int64_t>(txTimeNs))
    {
        st.delaySum += (now - NanoSeconds(txTimeNs));
    }
}

static void OnUdpEchoClientTx(uint16_t flowId, Ptr<const Packet> p)
{
    uint32_t seq = g_e2eFlows[flowId].txPackets + 1;
    uint64_t nowNs = Simulator::Now().GetNanoSeconds();
    RecordE2ETx(flowId, seq, p->GetSize());
    g_uidToFlowMap[p->GetUid()] = {flowId, seq, nowNs};
    g_uidToFlowMap[(static_cast<uint64_t>(flowId) << 32) | seq] = {flowId, seq, nowNs};
}

static void OnUdpEchoServerRx(uint16_t flowId, Ptr<const Packet> p, const Address& from)
{
    auto it = g_uidToFlowMap.find(p->GetUid());
    if (it != g_uidToFlowMap.end())
    {
        RecordE2ERx(it->second.flowId, it->second.seqNum, p->GetSize(), it->second.txTimeNs);
        return;
    }

    uint32_t nextRxSeq = g_e2eFlows[flowId].rxPackets + 1;
    uint64_t key = (static_cast<uint64_t>(flowId) << 32) | nextRxSeq;
    auto itDsr = g_uidToFlowMap.find(key);
    if (itDsr != g_uidToFlowMap.end())
    {
        RecordE2ERx(flowId, itDsr->second.seqNum, p->GetSize(), itDsr->second.txTimeNs);
    }
}

#pragma pack(push, 1)
struct OverlayWireHeader
{
    uint32_t srcIp;
    uint32_t dstIp;
    uint32_t seqNum;
    uint64_t txTimeNs;
    uint16_t flowId;
    uint16_t tickets;
    uint8_t ttl;
};
#pragma pack(pop)

struct DtnBundle
{
    uint32_t payloadSize;
    Ipv4Address source;
    Ipv4Address destination;
    uint16_t port;
    uint16_t flowId;
    uint32_t seqNum;
    uint64_t txTimeNs;
    uint16_t tickets;
    uint8_t ttl;
    Time creationTime;
};

class UnifiedMeshRoutingApp : public Application
{
public:
    UnifiedMeshRoutingApp()
        : m_initialTickets(8),
          m_maxBufferSize(100),
          m_checkInterval(Seconds(1.0)),
          m_nodeId(0),
          m_mode("AODV"),
          m_enableDtn(false),
          m_radioRange(120.0),
          m_battery(100.0),
          m_lastNeighborCount(0)
    {
    }

    void Setup(const Ptr<Socket>& socket,
               uint16_t L,
               NodeContainer allNodes,
               uint32_t nodeIndex,
               std::string mode,
               bool enableDtnFlag)
    {
        m_socket = socket;
        m_initialTickets = (enableDtnFlag || mode == "ADAPTIVE") ? L : 1;
        m_allNodes = allNodes;
        m_nodeId = nodeIndex;
        m_mode = mode;
        m_enableDtn = enableDtnFlag;

        for (uint32_t i = 0; i < allNodes.GetN(); ++i)
        {
            m_trustScores[i] = 1.0;
        }
    }

    void SendEmergencyAlert(uint16_t flowId,
                            const Ipv4Address destIp,
                            const uint16_t destPort,
                            uint32_t packetSize)
    {
        if (m_buffer.size() >= m_maxBufferSize)
        {
            m_buffer.pop_front();
        }

        uint32_t seq = ++s_globalSeqCounter;
        uint64_t nowNs = Simulator::Now().GetNanoSeconds();
        m_seenPackets.insert(seq);

        RecordE2ETx(flowId, seq, packetSize);

        DtnBundle bundle = {packetSize,
                            GetNodeIp(m_nodeId),
                            destIp,
                            destPort,
                            flowId,
                            seq,
                            nowNs,
                            m_initialTickets,
                            15,
                            Simulator::Now()};

        m_buffer.push_back(bundle);
        ProcessRoutingQueue();
    }

protected:
    void StartApplication() override
    {
        m_socket->SetRecvCallback(MakeCallback(&UnifiedMeshRoutingApp::HandleReceive, this));
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
    static uint32_t s_globalSeqCounter;

    Ipv4Address GetNodeIp(uint32_t idx) const
    {
        Ptr<Ipv4> ipv4 = m_allNodes.Get(idx)->GetObject<Ipv4>();
        return ipv4->GetAddress(1, 0).GetLocal();
    }

    uint32_t GetNodeIndexByIp(Ipv4Address ip) const
    {
        for (uint32_t i = 0; i < m_allNodes.GetN(); ++i)
        {
            if (GetNodeIp(i) == ip)
            {
                return i;
            }
        }
        return m_nodeId;
    }

    double GetDistanceBetween(uint32_t n1, uint32_t n2) const
    {
        Vector p1 = m_allNodes.Get(n1)->GetObject<MobilityModel>()->GetPosition();
        Vector p2 = m_allNodes.Get(n2)->GetObject<MobilityModel>()->GetPosition();
        return (p1 - p2).GetLength();
    }

    std::vector<uint32_t> GetOneHopNeighbors(uint32_t nodeIdx) const
    {
        std::vector<uint32_t> neighbors;
        for (uint32_t i = 0; i < m_allNodes.GetN(); ++i)
        {
            if (i != nodeIdx && GetDistanceBetween(nodeIdx, i) <= m_radioRange)
            {
                neighbors.push_back(i);
            }
        }
        return neighbors;
    }

    bool HasActiveL3Route(Ipv4Address dstIp) const
    {
        if (m_mode == "DSR" || m_mode == "HWMP")
        {
            return false;
        }
        Ptr<Ipv4> ipv4 = m_allNodes.Get(m_nodeId)->GetObject<Ipv4>();
        if (!ipv4 || !ipv4->GetRoutingProtocol())
        {
            return false;
        }

        Ipv4Header ipHdr;
        ipHdr.SetDestination(dstIp);
        ipHdr.SetSource(GetNodeIp(m_nodeId));
        Socket::SocketErrno sockerr;

        Ptr<Packet> probePkt = Create<Packet>(10);
        Ptr<Ipv4Route> route =
            ipv4->GetRoutingProtocol()->RouteOutput(probePkt, ipHdr, nullptr, sockerr);

        if (route && route->GetGateway() != Ipv4Address("127.0.0.1"))
        {
            return true;
        }
        return false;
    }

    void TransmitBundleTo(const DtnBundle& b, Ipv4Address nextHopIp, uint16_t ticketsToGive)
    {
        if (b.ttl == 0)
        {
            return;
        }

        OverlayWireHeader wireHdr = {b.source.Get(),
                                     b.destination.Get(),
                                     b.seqNum,
                                     b.txTimeNs,
                                     b.flowId,
                                     ticketsToGive,
                                     static_cast<uint8_t>(b.ttl - 1)};

        uint32_t totalSize = std::max<uint32_t>(b.payloadSize, sizeof(OverlayWireHeader));
        std::vector<uint8_t> rawBuf(totalSize, 0);
        std::memcpy(rawBuf.data(), &wireHdr, sizeof(OverlayWireHeader));

        Ptr<Packet> pkt = Create<Packet>(rawBuf.data(), totalSize);
        m_socket->SendTo(pkt, 0, InetSocketAddress(nextHopIp, b.port));
        m_battery = std::max(5.0, m_battery - 0.15);
    }

    void ProcessRoutingQueue()
    {
        std::vector<uint32_t> neighbors = GetOneHopNeighbors(m_nodeId);
        Time now = Simulator::Now();

        if (m_mode == "SECURITY")
        {
            for (uint32_t nb : neighbors)
            {
                if (nb == 7 || nb == 14 || nb == 21)
                {
                    m_trustScores[nb] = std::max(0.0, m_trustScores[nb] - 0.25);
                }
            }
        }

        if (m_mode == "ADAPTIVE")
        {
            if (neighbors.size() == m_lastNeighborCount)
            {
                m_checkInterval = Seconds(std::min(8.0, m_checkInterval.GetSeconds() * 2.0));
            }
            else
            {
                m_checkInterval = Seconds(0.5);
                m_lastNeighborCount = neighbors.size();
            }
        }

        for (auto it = m_buffer.begin(); it != m_buffer.end();)
        {
            if (!m_enableDtn && (now - it->creationTime) > Seconds(2.0))
            {
                it = m_buffer.erase(it);
                continue;
            }

            uint32_t dstNodeIdx = GetNodeIndexByIp(it->destination);
            bool deliveredOrForwarded = false;

            if (GetDistanceBetween(m_nodeId, dstNodeIdx) <= m_radioRange)
            {
                TransmitBundleTo(*it, it->destination, 1);
                it = m_buffer.erase(it);
                continue;
            }

            if (m_mode == "AODV" || m_mode == "OLSR" || m_mode == "DSDV" || m_mode == "HYBRID")
            {
                if (HasActiveL3Route(it->destination))
                {
                    TransmitBundleTo(*it, it->destination, 1);
                    deliveredOrForwarded = true;
                }
            }
            else if (m_mode == "GRP" || m_mode == "GPSR")
            {
                double myDistToDst = GetDistanceBetween(m_nodeId, dstNodeIdx);
                uint32_t bestNb = m_nodeId;
                double bestDist = myDistToDst;

                for (uint32_t nb : neighbors)
                {
                    double d = GetDistanceBetween(nb, dstNodeIdx);
                    if (d < bestDist)
                    {
                        bestDist = d;
                        bestNb = nb;
                    }
                }
                if (bestNb == m_nodeId && !neighbors.empty() && !m_enableDtn)
                {
                    bestNb = neighbors.front();
                }
                if (bestNb != m_nodeId)
                {
                    TransmitBundleTo(*it, GetNodeIp(bestNb), 1);
                    deliveredOrForwarded = true;
                }
            }
            else if (m_mode == "ZRP")
            {
                uint32_t iarpNextHop = m_nodeId;
                std::vector<uint32_t> peripheralNodes;

                for (uint32_t nb : neighbors)
                {
                    for (uint32_t nb2 : GetOneHopNeighbors(nb))
                    {
                        if (nb2 == dstNodeIdx)
                        {
                            iarpNextHop = nb;
                            break;
                        }
                        if (GetDistanceBetween(m_nodeId, nb2) > m_radioRange)
                        {
                            peripheralNodes.push_back(nb);
                        }
                    }
                }

                if (iarpNextHop != m_nodeId)
                {
                    TransmitBundleTo(*it, GetNodeIp(iarpNextHop), 1);
                    deliveredOrForwarded = true;
                }
                else if (!peripheralNodes.empty())
                {
                    std::sort(peripheralNodes.begin(),
                              peripheralNodes.end(),
                              [&](uint32_t a, uint32_t b) {
                                  return GetDistanceBetween(a, dstNodeIdx) <
                                         GetDistanceBetween(b, dstNodeIdx);
                              });
                    TransmitBundleTo(*it, GetNodeIp(peripheralNodes.front()), 1);
                    deliveredOrForwarded = true;
                }
            }
            else if (m_mode == "MULTIPATH")
            {
                if (!neighbors.empty())
                {
                    std::vector<uint32_t> sortedNbs = neighbors;
                    std::sort(sortedNbs.begin(), sortedNbs.end(), [&](uint32_t a, uint32_t b) {
                        return GetDistanceBetween(a, dstNodeIdx) <
                               GetDistanceBetween(b, dstNodeIdx);
                    });
                    uint32_t kPaths = std::min<size_t>(2, sortedNbs.size());
                    for (uint32_t k = 0; k < kPaths; ++k)
                    {
                        TransmitBundleTo(*it, GetNodeIp(sortedNbs[k]), 1);
                        deliveredOrForwarded = true;
                    }
                }
            }
            else if (m_mode == "SECURITY")
            {
                uint32_t bestTrustedNb = m_nodeId;
                double minCost = 1e9;
                for (uint32_t nb : neighbors)
                {
                    if (m_trustScores[nb] < 0.5)
                    {
                        continue;
                    }
                    double cost =
                        GetDistanceBetween(nb, dstNodeIdx) / std::max(0.1, m_trustScores[nb]);
                    if (cost < minCost)
                    {
                        minCost = cost;
                        bestTrustedNb = nb;
                    }
                }
                if (bestTrustedNb != m_nodeId)
                {
                    TransmitBundleTo(*it, GetNodeIp(bestTrustedNb), 1);
                    deliveredOrForwarded = true;
                }
            }
            else if (m_mode == "ADAPTIVE")
            {
                if (neighbors.size() >= 3)
                {
                    double w2 = (m_battery < 30.0) ? 0.8 : 0.2;
                    double w1 = 1.0 - w2;
                    uint32_t bestAdaptiveNb = m_nodeId;
                    double bestScore = 1e9;
                    for (uint32_t nb : neighbors)
                    {
                        double cost = (w1 * (GetDistanceBetween(nb, dstNodeIdx) / 450.0)) +
                                      (w2 * ((100.0 - m_battery) / 100.0));
                        if (cost < bestScore)
                        {
                            bestScore = cost;
                            bestAdaptiveNb = nb;
                        }
                    }
                    if (bestAdaptiveNb != m_nodeId)
                    {
                        TransmitBundleTo(*it, GetNodeIp(bestAdaptiveNb), 1);
                        deliveredOrForwarded = true;
                    }
                }
            }

            if (!deliveredOrForwarded && (m_enableDtn || m_mode == "ADAPTIVE"))
            {
                for (uint32_t nb : neighbors)
                {
                    if (it->tickets > 1)
                    {
                        uint16_t sprayed = it->tickets / 2;
                        it->tickets -= sprayed;
                        TransmitBundleTo(*it, GetNodeIp(nb), sprayed);
                    }
                }
            }

            if (deliveredOrForwarded)
            {
                it = m_buffer.erase(it);
            }
            else
            {
                ++it;
            }
        }

        ScheduleNextCheck();
    }

    void ScheduleNextCheck()
    {
        Simulator::Cancel(m_timerEvent);
        m_timerEvent = Simulator::Schedule(m_checkInterval,
                                           &UnifiedMeshRoutingApp::ProcessRoutingQueue,
                                           this);
    }

    void HandleReceive(Ptr<Socket> socket)
    {
        Ptr<Packet> packet;
        Address from;
        Ipv4Address myIp = GetNodeIp(m_nodeId);

        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() < sizeof(OverlayWireHeader))
            {
                continue;
            }

            OverlayWireHeader wireHdr;
            packet->CopyData(reinterpret_cast<uint8_t*>(&wireHdr), sizeof(OverlayWireHeader));

            if (m_mode == "SECURITY" && (m_nodeId == 7 || m_nodeId == 14 || m_nodeId == 21))
            {
                continue;
            }

            Ipv4Address dstIp(wireHdr.dstIp);
            Ipv4Address srcIp(wireHdr.srcIp);

            if (dstIp == myIp)
            {
                RecordE2ERx(wireHdr.flowId,
                            wireHdr.seqNum,
                            packet->GetSize(),
                            wireHdr.txTimeNs);
                continue;
            }

            if (m_seenPackets.find(wireHdr.seqNum) != m_seenPackets.end())
            {
                continue;
            }
            m_seenPackets.insert(wireHdr.seqNum);

            if (wireHdr.ttl > 0 && m_buffer.size() < m_maxBufferSize)
            {
                DtnBundle relayBundle = {packet->GetSize(),
                                         srcIp,
                                         dstIp,
                                         9999,
                                         wireHdr.flowId,
                                         wireHdr.seqNum,
                                         wireHdr.txTimeNs,
                                         wireHdr.tickets,
                                         wireHdr.ttl,
                                         Simulator::Now()};
                m_buffer.push_back(relayBundle);
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_initialTickets;
    uint32_t m_maxBufferSize;
    Time m_checkInterval;
    EventId m_timerEvent;
    NodeContainer m_allNodes;
    uint32_t m_nodeId;
    std::string m_mode;
    bool m_enableDtn;
    double m_radioRange;
    double m_battery;
    size_t m_lastNeighborCount;
    std::deque<DtnBundle> m_buffer;
    std::set<uint32_t> m_seenPackets;
    std::map<uint32_t, double> m_trustScores;
};

uint32_t UnifiedMeshRoutingApp::s_globalSeqCounter = 0;

// Main Simulation Script

int main(int argc, char *argv[])
{
    double simTime = 110.0; // Total simulation time in seconds
    uint32_t numNodes = 30; // 30 emergency mesh nodes
    std::string protocol = "ADAPTIVE";
    bool enableDtn = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Total simulation time in seconds", simTime);
    cmd.AddValue("protocol", "Protocol: AODV, OLSR, DSDV, DSR, HWMP, HYBRID, ZRP, GRP, MULTIPATH,"
                             " SECURITY, ADAPTIVE",
        protocol);
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

    bool useOverlayEngine = enableDtn || (protocol == "ZRP" || protocol == "GRP" || protocol ==
        "GPSR" || protocol == "MULTIPATH" || protocol == "SECURITY" || protocol == "ADAPTIVE");

    if (protocol == "HWMP")
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

        if (protocol == "OLSR")
        {
            OlsrHelper olsr;
            stack.SetRoutingHelper(olsr);
            stack.Install(nodes);
        }
        else if (protocol == "DSDV")
        {
            DsdvHelper dsdv;
            dsdv.Set("PeriodicUpdateInterval", TimeValue(Seconds(15.0)));
            dsdv.Set("SettlingTime", TimeValue(Seconds(5.0)));
            stack.SetRoutingHelper(dsdv);
            stack.Install(nodes);
        }
        else if (protocol == "DSR")
        {
            stack.Install(nodes);
            Simulator::Schedule(Seconds(0.001), [nodes]() {
                DsrMainHelper dsrMain;
                DsrHelper dsr;
                dsrMain.Install(dsr, nodes);
            });
        }
        else if (protocol == "HYBRID" || protocol == "ADAPTIVE")
        {
            OlsrHelper olsr;
            AodvHelper aodv;
            DsdvHelper dsdv;
            Ipv4ListRoutingHelper listRouting;
            listRouting.Add(olsr, 10);
            listRouting.Add(aodv, 5);
            listRouting.Add(dsdv, 2);
            stack.SetRoutingHelper(listRouting);
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

    uint16_t basePort = useOverlayEngine ? 9999 : 9;
    g_e2eFlows[1] = {1, interfaces.GetAddress(0), basePort, interfaces.GetAddress(29), basePort};

    g_e2eFlows[1] = {1, interfaces.GetAddress(0), basePort, interfaces.GetAddress(29), basePort};
    g_e2eFlows[2] = {2,
                     interfaces.GetAddress(5),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 10),
                     interfaces.GetAddress(25),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 10)};
    g_e2eFlows[3] = {3,
                     interfaces.GetAddress(10),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 11),
                     interfaces.GetAddress(20),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 11)};
    g_e2eFlows[4] = {4,
                     interfaces.GetAddress(15),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 12),
                     interfaces.GetAddress(28),
                     static_cast<uint16_t>(useOverlayEngine ? 9999 : 12)};

    if (!useOverlayEngine)
    {
        // Pair 1: Node 0 -> Node 29 (Port 9)
        UdpEchoServerHelper server1(9);
        ApplicationContainer sApps1 = server1.Install(nodes.Get(29));
        sApps1.Start(Seconds(1.0));
        sApps1.Stop(Seconds(simTime));
        sApps1.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&OnUdpEchoServerRx,
            static_cast<uint16_t>(1)));

        UdpEchoClientHelper client1(interfaces.GetAddress(29), 9);
        client1.SetAttribute("MaxPackets", UintegerValue(45));
        client1.SetAttribute("Interval", TimeValue(Seconds(2.0)));
        client1.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps1 = client1.Install(nodes.Get(0));
        cApps1.Start(Seconds(3.0));
        cApps1.Stop(Seconds(simTime));
        cApps1.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(1)));

        // Pair 2: Node 5 -> Node 25 (Port 10)
        UdpEchoServerHelper server2(10);
        ApplicationContainer sApps2 = server2.Install(nodes.Get(25));
        sApps2.Start(Seconds(1.0));
        sApps2.Stop(Seconds(simTime));
        sApps2.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&OnUdpEchoServerRx,
            static_cast<uint16_t>(2)));

        UdpEchoClientHelper client2(interfaces.GetAddress(25), 10);
        client2.SetAttribute("MaxPackets", UintegerValue(45));
        client2.SetAttribute("Interval", TimeValue(Seconds(2.0)));
        client2.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps2 = client2.Install(nodes.Get(5));
        cApps2.Start(Seconds(4.0));
        cApps2.Stop(Seconds(simTime));
        cApps2.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(2)));

        // Pair 3: Node 10 -> Node 20 (Port 11)
        UdpEchoServerHelper server3(11);
        ApplicationContainer sApps3 = server3.Install(nodes.Get(20));
        sApps3.Start(Seconds(1.0));
        sApps3.Stop(Seconds(simTime));
        sApps3.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&OnUdpEchoServerRx,
            static_cast<uint16_t>(3)));

        UdpEchoClientHelper client3(interfaces.GetAddress(20), 11);
        client3.SetAttribute("MaxPackets", UintegerValue(35));
        client3.SetAttribute("Interval", TimeValue(Seconds(2.5)));
        client3.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps3 = client3.Install(nodes.Get(10));
        cApps3.Start(Seconds(5.0));
        cApps3.Stop(Seconds(simTime));
        cApps3.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(3)));

        // Pair 4: Node 15 -> Node 28 (Port 12)
        UdpEchoServerHelper server4(12);
        ApplicationContainer sApps4 = server4.Install(nodes.Get(28));
        sApps4.Start(Seconds(1.0));
        sApps4.Stop(Seconds(simTime));
        sApps4.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&OnUdpEchoServerRx,
            static_cast<uint16_t>(4)));

        UdpEchoClientHelper client4(interfaces.GetAddress(28), 12);
        client4.SetAttribute("MaxPackets", UintegerValue(30));
        client4.SetAttribute("Interval", TimeValue(Seconds(3.0)));
        client4.SetAttribute("PacketSize", UintegerValue(250));
        ApplicationContainer cApps4 = client4.Install(nodes.Get(15));
        cApps4.Start(Seconds(6.0));
        cApps4.Stop(Seconds(simTime));
        cApps4.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(4)));
    }
    else
    {
        TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
        std::vector<Ptr<UnifiedMeshRoutingApp>> overlayApps(numNodes);

        for (uint32_t i = 0; i < numNodes; i++)
        {
            Ptr<Socket> sock = Socket::CreateSocket(nodes.Get(i), tid);
            sock->Bind(InetSocketAddress(Ipv4Address::GetAny(), 9999));

            overlayApps[i] = CreateObject<UnifiedMeshRoutingApp>();
            overlayApps[i]->Setup(sock, 8, nodes, i, protocol, enableDtn);
            nodes.Get(i)->AddApplication(overlayApps[i]);
            overlayApps[i]->SetStartTime(Seconds(1.0));
            overlayApps[i]->SetStopTime(Seconds(simTime));
        }

        // Pair 1
        for (int p = 0; p < 45; p++)
        {
            Simulator::Schedule(Seconds(3.0 + p * 2.0),
                &UnifiedMeshRoutingApp::SendEmergencyAlert, overlayApps[0], static_cast<uint16_t>
                (1), interfaces.GetAddress(29), 9999, 250);
        }

        // Pair 2
        for (int p = 0; p < 45; p++)
        {
            Simulator::Schedule(Seconds(4.0 + p * 2.0),
                &UnifiedMeshRoutingApp::SendEmergencyAlert, overlayApps[5], static_cast<uint16_t>
                (2), interfaces.GetAddress(25), 9999, 250);
        }

        // Pair 3
        for (int p = 0; p < 35; p++)
        {
            Simulator::Schedule(Seconds(5.0 + p * 2.5),
                &UnifiedMeshRoutingApp::SendEmergencyAlert, overlayApps[10],
                static_cast<uint16_t>(3), interfaces.GetAddress(20), 9999, 250);
        }

        // Pair 4
        for (int p = 0; p < 30; p++)
        {
            Simulator::Schedule(Seconds(6.0 + p * 3.0),
                &UnifiedMeshRoutingApp::SendEmergencyAlert, overlayApps[15],
                static_cast<uint16_t>(4), interfaces.GetAddress(28), 9999, 250);
        }

        std::cout << "Overlay/DTN Engine Active [Protocol: " << protocol << " | DTN Fallback: "
        << (enableDtn ? "ON" : "OFF") << "]\n";
    }

    AnimationInterface anim("emergency_mesh_" + protocol + (enableDtn ? "_DTN.xml" : ".xml"));
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        std::string label = "Relay (" + std::to_string(i) + ")";
        anim.UpdateNodeSize(nodes.Get(i), 10.0, 10.0);
        anim.UpdateNodeColor(nodes.Get(i), 255, 140, 0);

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
        else if (protocol == "SECURITY" && (i == 7 || i == 14 || i == 21))
        {
            label = "Malicious (" + std::to_string(i) + ")";
            anim.UpdateNodeColor(nodes.Get(i), 20, 20, 20);
        }

        anim.UpdateNodeDescription(nodes.Get(i), label);
    }

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = nullptr;
    if (protocol != "DSR") {
        monitor = flowmonHelper.InstallAll();
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    // monitor->CheckForLostPackets();
    // Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper
    //     .GetClassifier());
    // FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

    std::string modeLabel = protocol + (enableDtn ? "_DTN" : "");
    std::string csvFileName = "flowmon_results_" + modeLabel + ".csv";
    std::ofstream csvFile(csvFileName, std::ios::out);

    csvFile << "Protocol,FlowID,SrcAddr,SrcPort,DstAddr,DstPort,FlowType,TxPackets,RxPackets,"
               "LostPackets,PDR_Percent,AvgDelay_ms,Throughput_Kbps\n";

    std::cout << "PERFORMANCE REPORT [Mode: " << modeLabel << "]\n";

    uint32_t totalAppTx = 0;
    uint32_t totalAppRx = 0;
    uint32_t totalAppLost = 0;
    double weightedDelaySumMs = 0.0;
    double totalThroughputKbps = 0.0;

    for (auto const& [flowId, st] : g_e2eFlows)
    {
        uint32_t lost = (st.txPackets >= st.rxPackets) ? (st.txPackets - st.rxPackets) : 0;
        double pdr = (st.txPackets > 0)
        ? (static_cast<double>(st.rxPackets) / st.txPackets * 100.0) : 0.0;

        double avgDelayMs = (st.rxPackets > 0)
        ? (st.delaySum.GetSeconds() / st.rxPackets * 1000.0) : 0.0;

        double rxDuration = (st.timeLastRx - st.timeFirstTx).GetSeconds();
        double tputKbps = (st.rxPackets > 0 && rxDuration > 0.0) ? (st.rxBytes * 8.0 / rxDuration
            / 1000.0) : 0.0;

        totalAppTx += st.txPackets;
        totalAppRx += st.rxPackets;
        totalAppLost += lost;
        weightedDelaySumMs += (avgDelayMs * st.rxPackets);
        totalThroughputKbps += tputKbps;

        csvFile << modeLabel << "," << flowId << "," << st.srcAddr << "," << st.srcPort << ","
                << st.dstAddr << "," << st.dstPort << ",Application_E2E," << st.txPackets << ","
                << st.rxPackets << "," << lost << "," << pdr << "," << avgDelayMs << ","
                << tputKbps << "\n";

        std::cout << "E2E PAIR " << flowId << " (" << st.srcAddr << ":" << st.srcPort << " -> "
                  << st.dstAddr << ":" << st.dstPort << ")\n"
                  << "  Tx Packets : " << st.txPackets << " | Rx Packets : " << st.rxPackets
                  << " | Lost : " << lost << "\n"
                  << "  PDR: " << std::fixed << std::setprecision(2) << pdr
                  << " % | Avg Delay: " << avgDelayMs << " ms | Throughput: " << tputKbps
                  << " Kbps\n";
    }

    if (monitor)
    {
        monitor->CheckForLostPackets();
        Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper
            .GetClassifier());
        FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();

        for (auto iter = stats.begin(); iter != stats.end(); ++iter)
        {
            Ipv4FlowClassifier::FiveTuple tuple = classifier->FindFlow(iter->first);
            std::string flowType = "Control";

            if (tuple.destinationPort >= 9 && tuple.destinationPort <= 12)
            {
                flowType = "Application_L3_Fwd";
            }
            else if (tuple.sourcePort >= 9 && tuple.sourcePort <= 12)
            {
                flowType = "Application_EchoReply";
            }
            else if (tuple.destinationPort == 9999 || tuple.sourcePort == 9999)
            {
                flowType = "Overlay_RelayHop";
            }
            else if (tuple.destinationPort == 654 || tuple.sourcePort == 654)
            {
                flowType = "AODV_Control";
            }
            else if (tuple.destinationPort == 698 || tuple.sourcePort == 698)
            {
                flowType = "OLSR_Control";
            }
            else if (tuple.destinationPort == 269 || tuple.sourcePort == 269)
            {
                flowType = "DSDV_Control";
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

            csvFile << modeLabel << "," << (iter->first + 100) << "," << tuple.sourceAddress << ","
                    << tuple.sourcePort << "," << tuple.destinationAddress << ","
                    << tuple.destinationPort << "," << flowType << "," << iter->second.txPackets << ","
                    << iter->second.rxPackets << "," << iter->second.lostPackets << "," << pdr << ","
                    << meanDelay << "," << throughputKbps << "\n";
        }
    }

    csvFile.close();

    double overallPdr = (totalAppTx > 0) ? (static_cast<double>(totalAppRx) / totalAppTx * 100.0)
    : 0.0;
    double overallAvgDelayMs = (totalAppRx > 0) ? (weightedDelaySumMs / totalAppRx) : 0.0;

    bool summaryExists = std::ifstream("all_protocols_summary.csv").good();
    std::ofstream summaryFile("all_protocols_summary.csv", std::ios::out | std::ios::app);

    if (!summaryExists)
    {
        summaryFile << "Protocol_Mode,TotalTxPackets,TotalRxPackets,TotalLostPackets,"
                       "Overall_PDR_Percent,Overall_AvgDelay_ms,Aggregate_Throughput_Kbps\n";
    }
    summaryFile << modeLabel << "," << totalAppTx << "," << totalAppRx << "," << totalAppLost << ","
                << overallPdr << "," << overallAvgDelayMs << "," << totalThroughputKbps << "\n";

    summaryFile.close();

    std::cout << "OVERALL SUMMARY [" << modeLabel << "]: Tx=" << totalAppTx
                  << " | Rx=" << totalAppRx << " | PDR=" << overallPdr
                  << "% | AvgDelay=" << overallAvgDelayMs
                  << " ms | TotalThroughput=" << totalThroughputKbps << " Kbps\n";
    std::cout << "Detailed flows exported to: " << csvFileName << "\n";
    std::cout << "Aggregate row appended to : all_protocols_summary.csv\n\n";

    Simulator::Destroy();
    return 0;
}