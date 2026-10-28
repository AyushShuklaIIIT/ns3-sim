#include "../src/aodv/helper/aodv-helper.h"
#include "../src/applications/helper/udp-echo-helper.h"
#include "../src/core/model/command-line.h"
#include "../src/core/model/config.h"
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

#include "ns3/pointer.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <deque>
#include <fstream>
#include <iomanip>
#include <map>
#include <ranges>
#include <set>
#include <vector>

namespace ns3
{
class UniformRandomVariable;
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
    auto itFallback = g_uidToFlowMap.find(key);
    if (itFallback != g_uidToFlowMap.end())
    {
        RecordE2ERx(flowId, itFallback->second.seqNum, p->GetSize(), itFallback->second.txTimeNs);
    }
}


enum OverlayPacketType : uint8_t
{
    PKT_DATA_BUNDLE = 1,
    PKT_HELLO_BEACON = 2,
    PKT_WATCHDOG_OVERHEAR = 3
};

#pragma pack(push, 1)
struct OverlayWireHeader
{
    uint8_t pktType;
    uint32_t srcIp;
    uint32_t dstIp;
    uint32_t prevHopIp;
    uint32_t seqNum;
    uint64_t txTimeNs;
    uint16_t flowId;
    uint16_t tickets;
    uint8_t ttl;
    float posX;
    float posY;
    float batteryPct;
    uint8_t neighborCnt;
    uint32_t neighbors[6];
};
#pragma pack(pop)

struct NeighborEntry
{
    Ipv4Address ip;
    uint32_t nodeId;
    Vector position;
    double battery;
    uint8_t degree;
    std::vector<Ipv4Address> twoHopNeighbors;
    Time lastSeen;
};

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
    std::set<uint32_t> sprayedToNodes;
};


class UnifiedMeshRoutingApp : public Application
{
public:
    UnifiedMeshRoutingApp()
        : m_initialTickets(16),
          m_maxBufferSize(250),
          m_checkInterval(Seconds(0.25)),
          m_beaconInterval(Seconds(1.0)),
          m_nodeId(0),
          m_mode("AODV"),
          m_enableDtn(false),
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
        m_socket->SetAllowBroadcast(true);
        m_socket->BindToNetDevice(allNodes.Get(nodeIndex)->GetDevice(0));
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
                            18,
                            Simulator::Now(),
                            {}};

        m_buffer.push_back(bundle);
        ProcessRoutingQueue();
    }

protected:
    void StartApplication() override
    {
        m_socket->SetRecvCallback(MakeCallback(&UnifiedMeshRoutingApp::HandleReceive, this));
        // Stagger initial beacons with random jitter to prevent 802.11 broadcast collisions
        Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
        Simulator::Schedule(Seconds(jitter->GetValue(0.01, 0.4)),
                            &UnifiedMeshRoutingApp::SendHelloBeacon,
                            this);
        ScheduleNextCheck();
    }

    void StopApplication() override
    {
        Simulator::Cancel(m_timerEvent);
        Simulator::Cancel(m_beaconEvent);
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

    Vector GetMyPosition() const
    {
        return m_allNodes.Get(m_nodeId)->GetObject<MobilityModel>()->GetPosition();
    }

    Vector GetDestinationPosition(uint32_t dstNodeIdx) const
    {
        auto it = m_neighborTable.find(dstNodeIdx);
        if (it != m_neighborTable.end())
        {
            return it->second.position;
        }
        return m_allNodes.Get(dstNodeIdx)->GetObject<MobilityModel>()->GetPosition();
    }

    std::vector<NeighborEntry> GetActiveBeaconNeighbors()
    {
        Time now = Simulator::Now();
        std::vector<NeighborEntry> active;
        for (auto it = m_neighborTable.begin(); it != m_neighborTable.end();)
        {
            if ((now - it->second.lastSeen) > Seconds(3.0))
            {
                it = m_neighborTable.erase(it);
            }
            else
            {
                active.push_back(it->second);
                ++it;
            }
        }
        return active;
    }

    void SendHelloBeacon()
    {
        std::vector<NeighborEntry> activeNbs = GetActiveBeaconNeighbors();
        Vector myPos = GetMyPosition();
        Ipv4Address myIp = GetNodeIp(m_nodeId);

        OverlayWireHeader beacon = {};
        beacon.pktType = PKT_HELLO_BEACON;
        beacon.srcIp = myIp.Get();
        beacon.prevHopIp = myIp.Get();
        beacon.posX = static_cast<float>(myPos.x);
        beacon.posY = static_cast<float>(myPos.y);
        beacon.batteryPct = static_cast<float>(m_battery);
        beacon.neighborCnt = static_cast<uint8_t>(std::min<size_t>(6, activeNbs.size()));

        for (size_t i = 0; i < beacon.neighborCnt; ++i)
        {
            beacon.neighbors[i] = activeNbs[i].ip.Get();
        }

        Ptr<Packet> pkt = Create<Packet>(reinterpret_cast<const uint8_t*>(&beacon),
                                         sizeof(OverlayWireHeader));
        m_socket->SendTo(pkt, 0, InetSocketAddress(Ipv4Address::GetBroadcast(), 9999));

        if (m_mode == "ADAPTIVE")
        {
            if (activeNbs.size() == m_lastNeighborCount)
            {
                m_beaconInterval = Seconds(std::min(3.0, m_beaconInterval.GetSeconds() * 1.5));
            }
            else
            {
                m_beaconInterval = Seconds(0.5);
                m_lastNeighborCount = activeNbs.size();
            }
        }

        m_beaconEvent = Simulator::Schedule(m_beaconInterval,
                                            &UnifiedMeshRoutingApp::SendHelloBeacon,
                                            this);
    }

    bool GetActiveL3NextHop(Ipv4Address dstIp, Ipv4Address& outGateway) const
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

        if (route && route->GetGateway() != Ipv4Address("127.0.0.1") &&
            route->GetGateway() != GetNodeIp(m_nodeId))
        {
            outGateway = (route->GetGateway() == Ipv4Address("0.0.0.0")) ? dstIp
                                                                         : route->GetGateway();
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

        Ipv4Address myIp = GetNodeIp(m_nodeId);
        OverlayWireHeader wireHdr = {};
        wireHdr.pktType = PKT_DATA_BUNDLE;
        wireHdr.srcIp = b.source.Get();
        wireHdr.dstIp = b.destination.Get();
        wireHdr.prevHopIp = myIp.Get();
        wireHdr.seqNum = b.seqNum;
        wireHdr.txTimeNs = b.txTimeNs;
        wireHdr.flowId = b.flowId;
        wireHdr.tickets = ticketsToGive;
        wireHdr.ttl = static_cast<uint8_t>(b.ttl - 1);

        uint32_t totalSize = std::max<uint32_t>(b.payloadSize, sizeof(OverlayWireHeader));
        std::vector<uint8_t> rawBuf(totalSize, 0);
        std::memcpy(rawBuf.data(), &wireHdr, sizeof(OverlayWireHeader));

        Ptr<Packet> pkt = Create<Packet>(rawBuf.data(), totalSize);
        m_socket->SendTo(pkt, 0, InetSocketAddress(nextHopIp, b.port));
        m_battery = std::max(5.0, m_battery - 0.05);

        if (m_mode == "SECURITY" && nextHopIp != b.destination)
        {
            uint32_t relayIdx = GetNodeIndexByIp(nextHopIp);
            uint64_t wdKey = (static_cast<uint64_t>(b.seqNum) << 16) | relayIdx;
            m_pendingWatchdog[wdKey] = Simulator::Now();
            Simulator::Schedule(Seconds(0.8),
                                &UnifiedMeshRoutingApp::VerifyWatchdogForwarding,
                                this,
                                b.seqNum,
                                relayIdx);
        }
    }

    void VerifyWatchdogForwarding(uint32_t seqNum, uint32_t relayIdx)
    {
        uint64_t wdKey = (static_cast<uint64_t>(seqNum) << 16) | relayIdx;
        auto it = m_pendingWatchdog.find(wdKey);
        if (it != m_pendingWatchdog.end())
        {
            m_trustScores[relayIdx] = std::max(0.0, m_trustScores[relayIdx] - 0.30);
            m_pendingWatchdog.erase(it);
        }
    }

    void ProcessRoutingQueue()
    {
        std::vector<NeighborEntry> neighbors = GetActiveBeaconNeighbors();
        Time now = Simulator::Now();
        Vector myPos = GetMyPosition();

        for (auto it = m_buffer.begin(); it != m_buffer.end();)
        {
            if (!m_enableDtn && (now - it->creationTime) > Seconds(2.5))
            {
                it = m_buffer.erase(it);
                continue;
            }

            uint32_t dstNodeIdx = GetNodeIndexByIp(it->destination);
            Vector dstPos = GetDestinationPosition(dstNodeIdx);
            bool forwardedPrimary = false;

            if (m_neighborTable.find(dstNodeIdx) != m_neighborTable.end())
            {
                TransmitBundleTo(*it, it->destination, 1);
                it = m_buffer.erase(it);
                continue;
            }

            if (m_mode == "AODV" || m_mode == "OLSR" || m_mode == "DSDV" || m_mode == "HYBRID")
            {
                Ipv4Address l3NextHop;
                if (GetActiveL3NextHop(it->destination, l3NextHop))
                {
                    TransmitBundleTo(*it, it->destination, 1);
                    forwardedPrimary = true;
                }
            }
            else if (m_mode == "GRP" || m_mode == "GPSR")
            {
                double myDist = (myPos - dstPos).GetLength();
                Ipv4Address bestNbIp = Ipv4Address("0.0.0.0");
                double bestDist = myDist;

                for (const auto& nb : neighbors)
                {
                    double d = (nb.position - dstPos).GetLength();
                    if (d < bestDist)
                    {
                        bestDist = d;
                        bestNbIp = nb.ip;
                    }
                }
                if (bestNbIp == Ipv4Address("0.0.0.0") && !neighbors.empty() && !m_enableDtn)
                {
                    bestNbIp = neighbors.front().ip;
                }
                if (bestNbIp != Ipv4Address("0.0.0.0"))
                {
                    TransmitBundleTo(*it, bestNbIp, 1);
                    forwardedPrimary = true;
                }
            }
            else if (m_mode == "ZRP")
            {
                Ipv4Address iarpNextHop = Ipv4Address("0.0.0.0");
                std::vector<NeighborEntry> borderNodes;

                for (const auto& nb : neighbors)
                {
                    for (const auto& twoHopIp : nb.twoHopNeighbors)
                    {
                        if (twoHopIp == it->destination)
                        {
                            iarpNextHop = nb.ip;
                            break;
                        }
                    }
                    if (nb.degree > 1)
                    {
                        borderNodes.push_back(nb);
                    }
                }

                if (iarpNextHop != Ipv4Address("0.0.0.0"))
                {
                    TransmitBundleTo(*it, iarpNextHop, 1);
                    forwardedPrimary = true;
                }
                else if (!borderNodes.empty())
                {
                    std::sort(borderNodes.begin(),
                              borderNodes.end(),
                              [&](const NeighborEntry& a, const NeighborEntry& b) {
                                  return (a.position - dstPos).GetLength() <
                                         (b.position - dstPos).GetLength();
                              });
                    TransmitBundleTo(*it, borderNodes.front().ip, 1);
                    forwardedPrimary = true;
                }
            }
            else if (m_mode == "MULTIPATH")
            {
                Ipv4Address primaryGateway = Ipv4Address("0.0.0.0");
                if (GetActiveL3NextHop(it->destination, primaryGateway))
                {
                    TransmitBundleTo(*it, primaryGateway, 1);
                    forwardedPrimary = true;
                }

                std::vector<NeighborEntry> sortedNbs = neighbors;
                std::sort(sortedNbs.begin(),
                          sortedNbs.end(),
                          [&](const NeighborEntry& a, const NeighborEntry& b) {
                              return (a.position - dstPos).GetLength() <
                                     (b.position - dstPos).GetLength();
                          });

                uint32_t sentCount = forwardedPrimary ? 1 : 0;
                for (const auto& nb : sortedNbs)
                {
                    if (nb.ip != primaryGateway && sentCount < 2)
                    {
                        TransmitBundleTo(*it, nb.ip, 1);
                        forwardedPrimary = true;
                        sentCount++;
                    }
                }
            }
            else if (m_mode == "SECURITY")
            {
                Ipv4Address aodvGateway;
                if (GetActiveL3NextHop(it->destination, aodvGateway))
                {
                    uint32_t gwIdx = GetNodeIndexByIp(aodvGateway);
                    if (m_trustScores[gwIdx] >= 0.5)
                    {
                        TransmitBundleTo(*it, aodvGateway, 1);
                        forwardedPrimary = true;
                    }
                }

                if (!forwardedPrimary)
                {
                    Ipv4Address bestTrustedIp = Ipv4Address("0.0.0.0");
                    double minCost = 1e9;
                    for (const auto& nb : neighbors)
                    {
                        if (m_trustScores[nb.nodeId] < 0.5)
                        {
                            continue; // Isolate Blackhole node flagged by Watchdog
                        }
                        double dist = (nb.position - dstPos).GetLength();
                        double cost = dist / std::max(0.1, m_trustScores[nb.nodeId]);
                        if (cost < minCost)
                        {
                            minCost = cost;
                            bestTrustedIp = nb.ip;
                        }
                    }
                    if (bestTrustedIp != Ipv4Address("0.0.0.0"))
                    {
                        TransmitBundleTo(*it, bestTrustedIp, 1);
                        forwardedPrimary = true;
                    }
                }
            }
            else if (m_mode == "ADAPTIVE")
            {
                if (neighbors.size() >= 3)
                {
                    Ipv4Address l3Gw;
                    if (GetActiveL3NextHop(it->destination, l3Gw))
                    {
                        TransmitBundleTo(*it, it->destination, 1);
                        forwardedPrimary = true;
                    }
                    else
                    {
                        double w2 = (m_battery < 30.0) ? 0.8 : 0.2;
                        double w1 = 1.0 - w2;
                        Ipv4Address bestIp = Ipv4Address("0.0.0.0");
                        double bestScore = 1e9;
                        for (const auto& nb : neighbors)
                        {
                            double normDist = (nb.position - dstPos).GetLength() / 450.0;
                            double energyPen = (100.0 - nb.battery) / 100.0;
                            double cost = (w1 * normDist) + (w2 * energyPen);
                            if (cost < bestScore)
                            {
                                bestScore = cost;
                                bestIp = nb.ip;
                            }
                        }
                        if (bestIp != Ipv4Address("0.0.0.0"))
                        {
                            TransmitBundleTo(*it, bestIp, 1);
                            forwardedPrimary = true;
                        }
                    }
                }
            }

            if (m_enableDtn || m_mode == "ADAPTIVE")
            {
                for (const auto& nb : neighbors)
                {
                    if (m_mode == "SECURITY" && m_trustScores[nb.nodeId] < 0.5)
                    {
                        continue;
                    }
                    if (it->tickets > 1 &&
                        it->sprayedToNodes.find(nb.nodeId) == it->sprayedToNodes.end())
                    {
                        uint16_t sprayed = it->tickets / 2;
                        it->tickets -= sprayed;
                        it->sprayedToNodes.insert(nb.nodeId);
                        TransmitBundleTo(*it, nb.ip, sprayed);
                    }
                }
            }

            if (forwardedPrimary && !m_enableDtn)
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

            if (wireHdr.pktType == PKT_HELLO_BEACON)
            {
                Ipv4Address senderIp(wireHdr.srcIp);
                if (senderIp == myIp)
                {
                    continue;
                }
                uint32_t senderIdx = GetNodeIndexByIp(senderIp);
                NeighborEntry entry;
                entry.ip = senderIp;
                entry.nodeId = senderIdx;
                entry.position = Vector(wireHdr.posX, wireHdr.posY, 0.0);
                entry.battery = wireHdr.batteryPct;
                entry.degree = wireHdr.neighborCnt;
                entry.lastSeen = Simulator::Now();
                for (uint8_t k = 0; k < wireHdr.neighborCnt && k < 6; ++k)
                {
                    entry.twoHopNeighbors.emplace_back(wireHdr.neighbors[k]);
                }
                m_neighborTable[senderIdx] = entry;
                continue;
            }

            if (wireHdr.pktType == PKT_WATCHDOG_OVERHEAR)
            {
                uint32_t relayIdx = GetNodeIndexByIp(Ipv4Address(wireHdr.prevHopIp));
                uint64_t wdKey = (static_cast<uint64_t>(wireHdr.seqNum) << 16) | relayIdx;
                if (m_pendingWatchdog.erase(wdKey) > 0)
                {
                    m_trustScores[relayIdx] = std::min(1.0, m_trustScores[relayIdx] + 0.05);
                }
                continue;
            }

            if (m_mode == "SECURITY" && (m_nodeId == 7 || m_nodeId == 14 || m_nodeId == 21))
            {
                continue;
            }

            Ipv4Address dstIp(wireHdr.dstIp);
            Ipv4Address srcIp(wireHdr.srcIp);
            Ipv4Address prevHopIp(wireHdr.prevHopIp);

            if (dstIp == myIp)
            {
                RecordE2ERx(wireHdr.flowId,
                            wireHdr.seqNum,
                            packet->GetSize(),
                            wireHdr.txTimeNs);
                continue;
            }

            if (m_mode == "SECURITY" && prevHopIp != myIp)
            {
                OverlayWireHeader wdAck = {};
                wdAck.pktType = PKT_WATCHDOG_OVERHEAR;
                wdAck.prevHopIp = myIp.Get();
                wdAck.seqNum = wireHdr.seqNum;
                Ptr<Packet> wdPkt = Create<Packet>(reinterpret_cast<const uint8_t*>(&wdAck),
                                                   sizeof(OverlayWireHeader));
                m_socket->SendTo(wdPkt, 0, InetSocketAddress(prevHopIp, 9999));
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
                                         Simulator::Now(),
                                         {GetNodeIndexByIp(prevHopIp)}};
                m_buffer.push_back(relayBundle);
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_initialTickets;
    uint32_t m_maxBufferSize;
    Time m_checkInterval;
    Time m_beaconInterval;
    EventId m_timerEvent;
    EventId m_beaconEvent;
    NodeContainer m_allNodes;
    uint32_t m_nodeId;
    std::string m_mode;
    bool m_enableDtn;
    double m_battery;
    size_t m_lastNeighborCount;
    std::deque<DtnBundle> m_buffer;
    std::set<uint32_t> m_seenPackets;
    std::map<uint32_t, NeighborEntry> m_neighborTable;
    std::map<uint32_t, double> m_trustScores;
    std::map<uint64_t, Time> m_pendingWatchdog;
};

uint32_t UnifiedMeshRoutingApp::s_globalSeqCounter = 0;


int main(int argc, char* argv[])
{
    Config::SetDefault("ns3::aodv::RoutingProtocol::RreqRetries", UintegerValue(2));
    Config::SetDefault("ns3::aodv::RoutingProtocol::ActiveRouteTimeout", TimeValue(Seconds(10.0)));
    double simTime = 110.0;
    uint32_t numNodes = 30;
    std::string protocol = "ADAPTIVE";
    bool enableDtn = false;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Total simulation time in seconds", simTime);
    cmd.AddValue("protocol",
                 "Protocol: AODV, OLSR, DSDV, DSR, HWMP, HYBRID, ZRP, GRP, MULTIPATH, SECURITY, ADAPTIVE",
                 protocol);
    cmd.AddValue("enableDtn", "Enable DTN Spray & Wait Fallback Application", enableDtn);
    cmd.Parse(argc, argv);

    std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::toupper);

    Time::SetResolution(Time::NS);
    PacketMetadata::Enable();

    NodeContainer nodes;
    nodes.Create(numNodes);

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                                   "Exponent",
                                   DoubleValue(2.5),
                                   "ReferenceDistance",
                                   DoubleValue(1.0),
                                   "ReferenceLoss",
                                   DoubleValue(40.0));
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                   "MaxRange",
                                   DoubleValue(200.0));

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.Set("TxPowerStart", DoubleValue(20.0));
    wifiPhy.Set("TxPowerEnd", DoubleValue(20.0));
    wifiPhy.Set("TxGain", DoubleValue(3.0));
    wifiPhy.Set("RxGain", DoubleValue(3.0));
    Config::SetDefault("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue("500"));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("ErpOfdmRate12Mbps"),
                                 "ControlMode",
                                 StringValue("ErpOfdmRate6Mbps"));

    NetDeviceContainer devices;
    InternetStackHelper stack;

    bool useOverlayEngine = enableDtn || (protocol == "ZRP" || protocol == "GRP" ||
                                          protocol == "GPSR" || protocol == "MULTIPATH" ||
                                          protocol == "SECURITY" || protocol == "ADAPTIVE");

    if (protocol == "HWMP")
    {
        MeshHelper mesh = MeshHelper::Default();
        mesh.SetStackInstaller("ns3::Dot11sStack");
        mesh.SetSpreadInterfaceChannels(MeshHelper::ZERO_CHANNEL);
        mesh.SetMacType("RandomStart", TimeValue(Seconds(0.1)));
        mesh.SetNumberOfInterfaces(1);
        devices = mesh.Install(wifiPhy, nodes);
        stack.Install(nodes);
    }
    else
    {
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
            dsdv.Set("PeriodicUpdateInterval", TimeValue(Seconds(10.0)));
            dsdv.Set("SettlingTime", TimeValue(Seconds(2.0)));
            stack.SetRoutingHelper(dsdv);
            stack.Install(nodes);
        }
        else if (protocol == "DSR")
        {
            stack.Install(nodes);
            if (!enableDtn)
            {
                Simulator::Schedule(Seconds(0.001), [nodes]() {
                    DsrMainHelper dsrMain;
                    DsrHelper dsr;
                    dsrMain.Install(dsr, nodes);
                });
            }
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
    positionAlloc->SetAttribute("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=350.0]"));
    positionAlloc->SetAttribute("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=350.0]"));

    NodeContainer rescuerNodes;
    NodeContainer carrierNodes;
    for (uint32_t i = 0; i < numNodes; ++i)
    {
        if (i < 24)
        {
            rescuerNodes.Add(nodes.Get(i));
        }
        else
        {
            carrierNodes.Add(nodes.Get(i));
        }
    }

    MobilityHelper rescuerMobility;
    rescuerMobility.SetPositionAllocator(positionAlloc);
    rescuerMobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                     "Speed",
                                     StringValue("ns3::UniformRandomVariable[Min=0.5|Max=1.5]"),
                                     "Pause",
                                     StringValue("ns3::ConstantRandomVariable[Constant=10.0]"),
                                     "PositionAllocator",
                                     PointerValue(positionAlloc));
    rescuerMobility.Install(rescuerNodes);

    MobilityHelper carrierMobility;
    carrierMobility.SetPositionAllocator(positionAlloc);
    carrierMobility.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                     "Speed",
                                     StringValue("ns3::UniformRandomVariable[Min=5.0|Max=12.0]"),
                                     "Pause",
                                     StringValue("ns3::ConstantRandomVariable[Constant=2.0]"),
                                     "PositionAllocator",
                                     PointerValue(positionAlloc));
    carrierMobility.Install(carrierNodes);

    uint32_t pktSize = 1024;
    uint32_t numPktsPerFlow = 200;
    double pktIntervalSec = 0.25;

    uint16_t basePort = useOverlayEngine ? 9999 : 9;
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
        uint32_t srcNodes[4] = {0, 5, 10, 15};
        uint32_t dstNodes[4] = {29, 25, 20, 28};
        uint16_t ports[4] = {9, 10, 11, 12};
        double startTimes[4] = {3.0, 4.0, 5.0, 6.0};

        for (int f = 0; f < 4; ++f)
        {
            uint16_t flowId = static_cast<uint16_t>(f + 1);
            UdpEchoServerHelper server(ports[f]);
            ApplicationContainer sApps = server.Install(nodes.Get(dstNodes[f]));
            sApps.Start(Seconds(1.0));
            sApps.Stop(Seconds(simTime));
            sApps.Get(0)->TraceConnectWithoutContext(
                "Rx",
                MakeBoundCallback(&OnUdpEchoServerRx, flowId));

            UdpEchoClientHelper client(interfaces.GetAddress(dstNodes[f]), ports[f]);
            client.SetAttribute("MaxPackets", UintegerValue(numPktsPerFlow));
            client.SetAttribute("Interval", TimeValue(Seconds(pktIntervalSec)));
            client.SetAttribute("PacketSize", UintegerValue(pktSize));
            ApplicationContainer cApps = client.Install(nodes.Get(srcNodes[f]));
            cApps.Start(Seconds(startTimes[f]));
            cApps.Stop(Seconds(simTime));
            cApps.Get(0)->TraceConnectWithoutContext(
                "Tx",
                MakeBoundCallback(&OnUdpEchoClientTx, flowId));
        }
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
            overlayApps[i]->Setup(sock, 16, nodes, i, protocol, enableDtn);
            nodes.Get(i)->AddApplication(overlayApps[i]);
            overlayApps[i]->SetStartTime(Seconds(0.5));
            overlayApps[i]->SetStopTime(Seconds(simTime));
        }

        uint32_t srcNodes[4] = {0, 5, 10, 15};
        uint32_t dstNodes[4] = {29, 25, 20, 28};
        double startTimes[4] = {3.0, 4.0, 5.0, 6.0};

        for (int f = 0; f < 4; ++f)
        {
            uint16_t flowId = static_cast<uint16_t>(f + 1);
            for (uint32_t p = 0; p < numPktsPerFlow; ++p)
            {
                Simulator::Schedule(Seconds(startTimes[f] + p * pktIntervalSec),
                                    &UnifiedMeshRoutingApp::SendEmergencyAlert,
                                    overlayApps[srcNodes[f]],
                                    flowId,
                                    interfaces.GetAddress(dstNodes[f]),
                                    9999,
                                    pktSize);
            }
        }

        std::cout << "Overlay/DTN Engine Active [Protocol: " << protocol
                  << " | DTN Fallback: " << (enableDtn ? "ON (L=16)" : "OFF") << "]\n";
    }

    AnimationInterface anim("emergency_mesh_" + protocol + (enableDtn ? "_DTN.xml" : ".xml"));
    anim.SetMaxPktsPerTraceFile(0xFFFFFFFF);

    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        std::string role = (i < 24) ? "Rescuer (" : "CarrierMule (";
        std::string label = role + std::to_string(i) + ")";
        anim.UpdateNodeSize(nodes.Get(i), 10.0, 10.0);
        anim.UpdateNodeColor(nodes.Get(i), (i < 24) ? 255 : 0, (i < 24) ? 140 : 220, (i < 24) ? 0 : 220);

        if (i == 0) { label = "Src 1 (Rescuer)"; anim.UpdateNodeColor(nodes.Get(i), 0, 200, 0); }
        else if (i == 5) { label = "Src 2 (Rescuer)"; anim.UpdateNodeColor(nodes.Get(i), 0, 180, 252); }
        else if (i == 10) { label = "Src 3 (Rescuer)"; anim.UpdateNodeColor(nodes.Get(i), 30, 144, 255); }
        else if (i == 15) { label = "Src 4 (Rescuer)"; anim.UpdateNodeColor(nodes.Get(i), 238, 130, 238); }
        else if (i == 29) { label = "Dst 1 (CommandMule)"; anim.UpdateNodeColor(nodes.Get(i), 255, 0, 0); }
        else if (i == 25) { label = "Dst 2 (CommandMule)"; anim.UpdateNodeColor(nodes.Get(i), 178, 34, 34); }
        else if (i == 20) { label = "Dst 3 (RescuerPost)"; anim.UpdateNodeColor(nodes.Get(i), 128, 0, 128); }
        else if (i == 28) { label = "Dst 4 (CommandMule)"; anim.UpdateNodeColor(nodes.Get(i), 139, 0, 0); }
        else if (protocol == "SECURITY" && (i == 7 || i == 14 || i == 21))
        {
            label = "Blackhole (" + std::to_string(i) + ")";
            anim.UpdateNodeColor(nodes.Get(i), 20, 20, 20);
        }

        anim.UpdateNodeDescription(nodes.Get(i), label);
    }

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = nullptr;
    if (protocol != "DSR")
    {
        monitor = flowmonHelper.InstallAll();
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

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
                         ? (static_cast<double>(st.rxPackets) / st.txPackets * 100.0)
                         : 0.0;
        double avgDelayMs =
            (st.rxPackets > 0) ? (st.delaySum.GetSeconds() / st.rxPackets * 1000.0) : 0.0;

        double rxDuration = (st.timeLastRx - st.timeFirstTx).GetSeconds();
        double tputKbps =
            (st.rxPackets > 0 && rxDuration > 0.0) ? (st.rxBytes * 8.0 / rxDuration / 1000.0) : 0.0;

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
        Ptr<Ipv4FlowClassifier> classifier =
            DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
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
                double rxDuration = iter->second.timeLastRxPacket.GetSeconds() -
                                    iter->second.timeFirstTxPacket.GetSeconds();
                if (rxDuration > 0)
                {
                    throughputKbps = (iter->second.rxBytes * 8.0 / rxDuration) / 1000.0;
                }
            }

            csvFile << modeLabel << "," << (iter->first + 100) << "," << tuple.sourceAddress << ","
                    << tuple.sourcePort << "," << tuple.destinationAddress << ","
                    << tuple.destinationPort << "," << flowType << "," << iter->second.txPackets
                    << "," << iter->second.rxPackets << "," << iter->second.lostPackets << ","
                    << pdr << "," << meanDelay << "," << throughputKbps << "\n";
        }
    }

    csvFile.close();

    double overallPdr =
        (totalAppTx > 0) ? (static_cast<double>(totalAppRx) / totalAppTx * 100.0) : 0.0;
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