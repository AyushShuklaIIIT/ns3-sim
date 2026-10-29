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

NS_LOG_COMPONENT_DEFINE("DisasterSarMeshSimulation");

// ============================================================================
// 1. Node Role Definitions & Decentralized MAC-to-IPv4 Zero-Config Hashing
// ============================================================================
enum DisasterNodeRole : uint8_t
{
    ROLE_TRAPPED_VICTIM = 1,      // Nodes 0..11  : Generate SOS Anycast Distress Calls
    ROLE_CIVILIAN_RELAY = 2,      // Nodes 12..29 : Intermediate Bystander / IoT Relays
    ROLE_SAR_FOOT_SQUAD = 3,      // Nodes 30..39 : On-Foot Search & Rescue Solvers
    ROLE_SAR_COMMAND_VEHICLE = 4  // Nodes 40..44 : Mobile SAR Command & Response Vehicles
};

static DisasterNodeRole GetNodeDisasterRole(uint32_t nodeId)
{
    if (nodeId < 12)
        return ROLE_TRAPPED_VICTIM;
    if (nodeId < 30)
        return ROLE_CIVILIAN_RELAY;
    if (nodeId < 40)
        return ROLE_SAR_FOOT_SQUAD;
    return ROLE_SAR_COMMAND_VEHICLE;
}

static bool IsSarSolverNode(uint32_t nodeId)
{
    DisasterNodeRole role = GetNodeDisasterRole(nodeId);
    return (role == ROLE_SAR_FOOT_SQUAD || role == ROLE_SAR_COMMAND_VEHICLE);
}

// Autonomous Zero-Configuration MAC-to-IPv4 Hashing (No DHCP Server / No Pre-Flashed Kits)
static Ipv4InterfaceContainer AssignAutonomousMacDerivedIpv4(NodeContainer& nodes,
                                                             NetDeviceContainer& devices)
{
    Ipv4InterfaceContainer interfaces;
    std::set<uint32_t> usedIps;

    for (uint32_t i = 0; i < devices.GetN(); ++i)
    {
        Ptr<NetDevice> dev = devices.Get(i);
        Ptr<Node> node = nodes.Get(i);

        Mac48Address mac = Mac48Address::ConvertFrom(dev->GetAddress());
        uint8_t macBytes[6];
        mac.CopyTo(macBytes);

        // FNV-1a 16-bit hash fold of the 6 hardware MAC bytes
        uint32_t hash = 2166136261u;
        for (int b = 0; b < 6; ++b)
        {
            hash ^= macBytes[b];
            hash *= 16777619u;
        }

        uint8_t octet3 = static_cast<uint8_t>(((hash >> 8) & 0xFE) + 1);
        uint8_t octet4 = static_cast<uint8_t>((hash & 0xFE) + 1);

        uint32_t rawIp = (10u << 24) | (254u << 16) | (static_cast<uint32_t>(octet3) << 8) | octet4;
        while (usedIps.find(rawIp) != usedIps.end())
        {
            octet4 = static_cast<uint8_t>((octet4 % 253) + 1);
            rawIp = (10u << 24) | (254u << 16) | (static_cast<uint32_t>(octet3) << 8) | octet4;
        }
        usedIps.insert(rawIp);

        Ptr<Ipv4> ipv4 = node->GetObject<Ipv4>();
        int32_t ifIndex = ipv4->GetInterfaceForDevice(dev);
        if (ifIndex == -1)
        {
            ifIndex = ipv4->AddInterface(dev);
        }

        Ipv4InterfaceAddress ipv4Addr(Ipv4Address(rawIp), Ipv4Mask("255.255.0.0"));
        ipv4->AddAddress(ifIndex, ipv4Addr);
        ipv4->SetMetric(ifIndex, 1);
        ipv4->SetUp(ifIndex);

        interfaces.Add(ipv4, ifIndex);
    }
    return interfaces;
}

// ============================================================================
// 2. End-to-End Flow Tracker (Flows 1..4 = Victim SOS Anycast, Flows 5..6 = SAR Coord)
// ============================================================================
struct E2EFlowStats
{
    uint16_t flowId = 0;
    std::string flowLabel;
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
static uint32_t g_nativeSeqCounter = 0;

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
    uint32_t seq = ++g_nativeSeqCounter;
    uint64_t nowNs = Simulator::Now().GetNanoSeconds();
    RecordE2ETx(flowId, seq, p->GetSize());

    g_uidToFlowMap[p->GetUid()] = {flowId, seq, nowNs};
    uint32_t flowLocalIdx = g_e2eFlows[flowId].txPackets;
    g_uidToFlowMap[(static_cast<uint64_t>(flowId) << 32) | flowLocalIdx] = {flowId, seq, nowNs};
}

static void OnUdpEchoServerRx(uint16_t flowId, Ptr<const Packet> p, const Address& from)
{
    auto it = g_uidToFlowMap.find(p->GetUid());
    if (it != g_uidToFlowMap.end())
    {
        RecordE2ERx(it->second.flowId, it->second.seqNum, p->GetSize(), it->second.txTimeNs);
        return;
    }
    uint32_t nextRxIdx = g_e2eFlows[flowId].rxPackets + 1;
    uint64_t key = (static_cast<uint64_t>(flowId) << 32) | nextRxIdx;
    auto itFallback = g_uidToFlowMap.find(key);
    if (itFallback != g_uidToFlowMap.end())
    {
        RecordE2ERx(flowId, itFallback->second.seqNum, p->GetSize(), itFallback->second.txTimeNs);
    }
}

// ============================================================================
// 3. Wire Headers for SOS Anycast, SAR Coordination, Beacons & Location Gossip
// ============================================================================
enum OverlayPacketType : uint8_t
{
    PKT_SOS_ANYCAST = 1,      // Trapped Victim SOS Distress Call (Deliver to ANY SAR Solver)
    PKT_SAR_COORD = 2,        // Unicast SAR-to-SAR Team Sector & Triage Coordination
    PKT_HELLO_BEACON = 3,     // Over-the-Air 1-Hop/2-Hop Neighborhood & SAR Location Gossip
    PKT_WATCHDOG_CUSTODY = 4  // 1-Hop Custody/Forwarding Confirmation for Watchdog Trust
};

enum GpsrRoutingState : uint8_t
{
    GPSR_MODE_GREEDY = 0,     // Standard Greedy Geographic Forwarding
    GPSR_MODE_PERIMETER = 1   // Right-Hand Rule Perimeter Mode around a Local Void
};

#pragma pack(push, 1)
struct OverlayWireHeader
{
    uint8_t pktType;          // OverlayPacketType
    uint8_t senderRole;       // DisasterNodeRole of immediate sender
    uint8_t survivorCount;    // Number of trapped survivors reported in Victim SOS (1..4)
    uint8_t gpsrMode;         // GPSR_MODE_GREEDY (0) or GPSR_MODE_PERIMETER (1)
    float failureDist;        // Distance to destination where packet entered Perimeter Mode
    uint32_t srcIp;           // Original Victim or SAR Sender IP
    uint32_t dstIp;           // 0.0.0.0 for PKT_SOS_ANYCAST; Target SAR IP for PKT_SAR_COORD
    uint32_t prevHopIp;       // Immediate Relay IP
    uint32_t seqNum;          // Unique Bundle Sequence ID
    uint64_t txTimeNs;        // Creation Timestamp (ns)
    uint16_t flowId;          // Flow ID (1..4 = Victim SOS Clusters, 5..6 = SAR Coordination)
    uint16_t tickets;         // Binary Spray-and-Wait Tickets
    uint8_t ttl;              // Remaining Hop Count
    float originGpsX;         // Sender's own GPS X (from onboard GNSS receiver)
    float originGpsY;         // Sender's own GPS Y (from onboard GNSS receiver)
    float dstGpsX;            // Target's last known GPS X stamped in packet header
    float dstGpsY;            // Target's last known GPS Y stamped in packet header
    uint8_t hasValidDstGps;   // 1 if sender knew target's GPS via OTA Location Cache, 0 otherwise
    float batteryPct;         // Node Battery Percentage
    uint8_t neighborCnt;      // Advertised 1-Hop Neighbor Count (for ZRP 2-Hop Zone)
    uint32_t neighbors[6];    // Advertised 1-Hop Neighbor IPs
    // Over-the-Air Decentralized SAR Location Service Gossip (No Simulator God-View!)
    uint32_t nearestSarIp;    // Known 1-Hop/Multi-Hop SAR Responder IP
    float nearestSarGpsX;     // Known SAR Responder GPS X
    float nearestSarGpsY;     // Known SAR Responder GPS Y
    uint32_t gossipSarIp;     // Rotating Gossiped SAR Unit IP for Unicast SAR-to-SAR Coord
    float gossipSarGpsX;      // Gossiped SAR Unit GPS X
    float gossipSarGpsY;      // Gossiped SAR Unit GPS Y
    uint64_t gossipTimeNs;    // Timestamp when gossiped SAR GPS was recorded
};
#pragma pack(pop)

// Over-the-Air Learned Position Entry (Populated strictly from received packets/beacons)
struct LearnedLocationEntry
{
    Ipv4Address ip;
    Vector position;
    Time timestamp;
};

struct NeighborEntry
{
    Ipv4Address ip;
    uint32_t nodeId;
    DisasterNodeRole role;
    Vector position;
    double battery;
    uint8_t degree;
    Ipv4Address advertisedSarIp;
    Vector advertisedSarPos;
    std::vector<Ipv4Address> twoHopNeighbors;
    Time lastSeen;
};

struct DtnBundle
{
    uint8_t pktType;
    uint8_t survivorCount;
    uint8_t gpsrMode;
    float failureDist;
    uint32_t payloadSize;
    Ipv4Address source;
    Ipv4Address destination;
    Ipv4Address prevHop;
    uint16_t port;
    uint16_t flowId;
    uint32_t seqNum;
    uint64_t txTimeNs;
    uint16_t tickets;
    uint8_t ttl;
    float originX;
    float originY;
    float dstX;
    float dstY;
    bool hasValidDstGps;
    Time creationTime;
    bool primaryForwarded;
    std::set<uint32_t> sprayedToNodes;
};

// ============================================================================
// 4. Unified Disaster SAR & Multi-Protocol Overlay Application
// ============================================================================
class UnifiedMeshRoutingApp : public Application
{
public:
    UnifiedMeshRoutingApp()
        : m_initialTickets(16),
          m_maxBufferSize(250),
          m_checkInterval(Seconds(0.25)),
          m_beaconInterval(Seconds(1.0)),
          m_nodeId(0),
          m_role(ROLE_CIVILIAN_RELAY),
          m_baseProtocol("AODV"),
          m_enableDtn(false),
          m_enableSecurity(false),
          m_enableAdaptive(false),
          m_battery(100.0),
          m_lastNeighborCount(0),
          m_gossipCursor(0)
    {
    }

    void Setup(const Ptr<Socket>& socket,
               uint16_t L,
               uint32_t maxQueuePackets,
               NodeContainer allNodes,
               uint32_t nodeIndex,
               std::string baseProtocol,
               bool enableDtnFlag,
               bool enableSecurityFlag,
               bool enableAdaptiveFlag)
    {
        m_socket = socket;
        m_socket->SetAllowBroadcast(true);
        m_socket->BindToNetDevice(allNodes.Get(nodeIndex)->GetDevice(0));
        m_initialTickets = (enableDtnFlag || enableAdaptiveFlag) ? L : 1;
        m_maxBufferSize = maxQueuePackets;
        m_allNodes = allNodes;
        m_nodeId = nodeIndex;
        m_role = GetNodeDisasterRole(nodeIndex);
        m_baseProtocol = baseProtocol;
        m_enableDtn = enableDtnFlag;
        m_enableSecurity = enableSecurityFlag;
        m_enableAdaptive = enableAdaptiveFlag;

        for (uint32_t i = 0; i < allNodes.GetN(); ++i)
        {
            m_trustScores[i] = 1.0;
        }
    }

    // Trapped Victim broadcasts Destination-Agnostic SOS Distress Signal (No Destination IP!)
    void TriggerVictimSosDistress(uint16_t flowId, uint8_t trappedCount, uint32_t packetSize)
    {
        if (m_buffer.size() >= m_maxBufferSize)
        {
            m_buffer.pop_front();
        }

        uint32_t seq = ++s_globalSeqCounter;
        uint64_t nowNs = Simulator::Now().GetNanoSeconds();
        Vector myPos = GetMyOwnGnssPosition();
        Ipv4Address myIp = GetNodeIp(m_nodeId);
        m_seenPackets.insert(seq);

        RecordE2ETx(flowId, seq, packetSize);

        DtnBundle bundle = {PKT_SOS_ANYCAST,
                            trappedCount,
                            GPSR_MODE_GREEDY,
                            1e9f,
                            packetSize,
                            myIp,
                            Ipv4Address::GetAny(), // 0.0.0.0 -> Destination-Agnostic Anycast
                            myIp,
                            9999,
                            flowId,
                            seq,
                            nowNs,
                            m_initialTickets,
                            20,
                            static_cast<float>(myPos.x),
                            static_cast<float>(myPos.y),
                            0.0f,
                            0.0f,
                            false,
                            Simulator::Now(),
                            false,
                            {}};

        m_buffer.push_back(bundle);
        ProcessRoutingQueue();
    }

    // SAR Team Squad / Vehicle sends Unicast Tactical Coordination Packet to another SAR Unit
    void SendSarTeamCoordination(uint16_t flowId,
                                 Ipv4Address targetSarIp,
                                 uint32_t packetSize)
    {
        if (m_buffer.size() >= m_maxBufferSize)
        {
            m_buffer.pop_front();
        }

        uint32_t seq = ++s_globalSeqCounter;
        uint64_t nowNs = Simulator::Now().GetNanoSeconds();
        Vector myPos = GetMyOwnGnssPosition();
        Ipv4Address myIp = GetNodeIp(m_nodeId);
        m_seenPackets.insert(seq);

        RecordE2ETx(flowId, seq, packetSize);

        Vector knownTargetPos;
        bool hasTargetGps = LookupOtaLocation(targetSarIp, knownTargetPos);

        DtnBundle bundle = {PKT_SAR_COORD,
                            0,
                            GPSR_MODE_GREEDY,
                            1e9f,
                            packetSize,
                            myIp,
                            targetSarIp,
                            myIp,
                            9999,
                            flowId,
                            seq,
                            nowNs,
                            m_initialTickets,
                            20,
                            static_cast<float>(myPos.x),
                            static_cast<float>(myPos.y),
                            static_cast<float>(hasTargetGps ? knownTargetPos.x : 0.0),
                            static_cast<float>(hasTargetGps ? knownTargetPos.y : 0.0),
                            hasTargetGps,
                            Simulator::Now(),
                            false,
                            {}};

        m_buffer.push_back(bundle);
        ProcessRoutingQueue();
    }

protected:
    void StartApplication() override
    {
        // Record our own onboard GNSS position in our local table
        Ipv4Address myIp = GetNodeIp(m_nodeId);
        m_locationCache[myIp.Get()] = {myIp, GetMyOwnGnssPosition(), Simulator::Now()};

        m_socket->SetRecvCallback(MakeCallback(&UnifiedMeshRoutingApp::HandleReceive, this));
        Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
        Simulator::Schedule(Seconds(jitter->GetValue(0.01, 0.45)),
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

    // A node is ONLY allowed to query its OWN onboard GNSS receiver (m_nodeId)!
    // It NEVER queries another node's MobilityModel (No Simulator God-View).
    Vector GetMyOwnGnssPosition() const
    {
        return m_allNodes.Get(m_nodeId)->GetObject<MobilityModel>()->GetPosition();
    }

    void UpdateOtaLocationCache(Ipv4Address ip, Vector pos, Time timestamp)
    {
        if (ip == Ipv4Address::GetAny() || ip == Ipv4Address("0.0.0.0"))
        {
            return;
        }
        uint32_t key = ip.Get();
        auto it = m_locationCache.find(key);
        if (it == m_locationCache.end() || timestamp >= it->second.timestamp)
        {
            m_locationCache[key] = {ip, pos, timestamp};
        }
    }

    // Looks up a remote node's position strictly from Over-the-Air Beacons & Location Cache!
    bool LookupOtaLocation(Ipv4Address targetIp, Vector& outPos) const
    {
        if (targetIp == Ipv4Address::GetAny())
        {
            return false;
        }
        // 1. Check 1-hop neighbor beacon table first (freshest direct observation)
        for (const auto& [nIdx, nb] : m_neighborTable)
        {
            if (nb.ip == targetIp)
            {
                outPos = nb.position;
                return true;
            }
        }
        // 2. Check multi-hop Over-the-Air Location Gossip Cache
        auto it = m_locationCache.find(targetIp.Get());
        if (it != m_locationCache.end())
        {
            outPos = it->second.position;
            return true;
        }
        return false; // Position unknown! Must fall back to topological/perimeter/DTN routing
    }

    std::vector<NeighborEntry> GetActiveBeaconNeighbors()
    {
        Time now = Simulator::Now();
        std::vector<NeighborEntry> active;
        for (auto it = m_neighborTable.begin(); it != m_neighborTable.end();)
        {
            if ((now - it->second.lastSeen) > Seconds(3.5))
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

    // Resolves target IP and target GPS coordinates strictly via Over-the-Air knowledge
    bool ResolveTargetForBundle(DtnBundle& b,
                                const std::vector<NeighborEntry>& neighbors,
                                Ipv4Address& outTargetIp,
                                Vector& outTargetPos) const
    {
        if (b.pktType != PKT_SOS_ANYCAST)
        {
            outTargetIp = b.destination;
            if (LookupOtaLocation(b.destination, outTargetPos))
            {
                b.dstX = static_cast<float>(outTargetPos.x);
                b.dstY = static_cast<float>(outTargetPos.y);
                b.hasValidDstGps = true;
                return true;
            }
            if (b.hasValidDstGps)
            {
                outTargetPos = Vector(b.dstX, b.dstY, 0.0);
                return true;
            }
            return false; // Destination IP is known, but GPS coordinates have not been gossiped yet
        }

        // For PKT_SOS_ANYCAST: Find the closest SAR Solver learned via Beacons or OTA Cache
        Vector myPos = GetMyOwnGnssPosition();
        double minDist = 1e9;
        Ipv4Address bestSarIp = Ipv4Address::GetAny();
        Vector bestSarPos(0.0, 0.0, 0.0);

        // 1. Direct 1-Hop SAR Neighbors
        for (const auto& nb : neighbors)
        {
            if (IsSarSolverNode(nb.nodeId))
            {
                double d = (myPos - nb.position).GetLength();
                if (d < minDist)
                {
                    minDist = d;
                    bestSarIp = nb.ip;
                    bestSarPos = nb.position;
                }
            }
        }
        if (bestSarIp != Ipv4Address::GetAny())
        {
            outTargetIp = bestSarIp;
            outTargetPos = bestSarPos;
            b.dstX = static_cast<float>(bestSarPos.x);
            b.dstY = static_cast<float>(bestSarPos.y);
            b.hasValidDstGps = true;
            return true;
        }

        // 2. Multi-Hop SAR Gradient Advertised in 1-Hop Neighbor Beacons
        for (const auto& nb : neighbors)
        {
            if (nb.advertisedSarIp != Ipv4Address::GetAny())
            {
                double d = (myPos - nb.advertisedSarPos).GetLength();
                if (d < minDist)
                {
                    minDist = d;
                    bestSarIp = nb.advertisedSarIp;
                    bestSarPos = nb.advertisedSarPos;
                }
            }
        }
        if (bestSarIp != Ipv4Address::GetAny())
        {
            outTargetIp = bestSarIp;
            outTargetPos = bestSarPos;
            b.dstX = static_cast<float>(bestSarPos.x);
            b.dstY = static_cast<float>(bestSarPos.y);
            b.hasValidDstGps = true;
            return true;
        }

        // 3. Any SAR Solver learned in our Over-the-Air Location Cache
        for (const auto& [ipRaw, locEntry] : m_locationCache)
        {
            uint32_t idx = GetNodeIndexByIp(locEntry.ip);
            if (IsSarSolverNode(idx))
            {
                double d = (myPos - locEntry.position).GetLength();
                if (d < minDist)
                {
                    minDist = d;
                    bestSarIp = locEntry.ip;
                    bestSarPos = locEntry.position;
                }
            }
        }
        if (bestSarIp != Ipv4Address::GetAny())
        {
            outTargetIp = bestSarIp;
            outTargetPos = bestSarPos;
            b.dstX = static_cast<float>(bestSarPos.x);
            b.dstY = static_cast<float>(bestSarPos.y);
            b.hasValidDstGps = true;
            return true;
        }

        // 4. Check if our L3 Routing Table (AODV/OLSR/DSDV) knows a topological path to any SAR node
        Ipv4Address dummyGw;
        for (uint32_t sarIdx = 30; sarIdx < m_allNodes.GetN(); ++sarIdx)
        {
            Ipv4Address candidateSarIp = GetNodeIp(sarIdx);
            if (GetActiveL3NextHop(candidateSarIp, dummyGw))
            {
                outTargetIp = candidateSarIp;
                return false; // Have topological route, no GPS needed
            }
        }

        outTargetIp = Ipv4Address::GetAny();
        return false;
    }

    // Right-Hand Rule Planar Perimeter Forwarding for GPSR/GRP when stuck in a Local Minimum (Void)
    Ipv4Address SelectRightHandRulePerimeterNeighbor(
        const Vector& myPos,
        const Vector& dstPos,
        Ipv4Address prevHopIp,
        const std::vector<NeighborEntry>& neighbors) const
    {
        if (neighbors.empty())
        {
            return Ipv4Address("0.0.0.0");
        }

        // Reference vector: from current node toward the previous hop (or toward destination if source)
        double refAngle = std::atan2(dstPos.y - myPos.y, dstPos.x - myPos.x);
        for (const auto& nb : neighbors)
        {
            if (nb.ip == prevHopIp)
            {
                refAngle = std::atan2(nb.position.y - myPos.y, nb.position.x - myPos.x);
                break;
            }
        }

        // Pick the first neighbor counter-clockwise from refAngle (Right-Hand Rule)
        double minAngleDelta = 1e9;
        Ipv4Address bestPerimeterIp = Ipv4Address("0.0.0.0");

        for (const auto& nb : neighbors)
        {
            if (m_enableSecurity && m_trustScores.at(nb.nodeId) < 0.5)
            {
                continue;
            }
            if (nb.ip == prevHopIp && neighbors.size() > 1)
            {
                continue;
            }
            double nbAngle = std::atan2(nb.position.y - myPos.y, nb.position.x - myPos.x);
            double delta = nbAngle - refAngle;
            while (delta <= 0.0)
            {
                delta += 2.0 * M_PI;
            }
            if (delta < minAngleDelta)
            {
                minAngleDelta = delta;
                bestPerimeterIp = nb.ip;
            }
        }
        return bestPerimeterIp;
    }

    void SendHelloBeacon()
    {
        std::vector<NeighborEntry> activeNbs = GetActiveBeaconNeighbors();
        Vector myPos = GetMyOwnGnssPosition();
        Ipv4Address myIp = GetNodeIp(m_nodeId);
        Time now = Simulator::Now();

        // Keep our own GNSS coordinates fresh in the local cache
        UpdateOtaLocationCache(myIp, myPos, now);

        OverlayWireHeader beacon = {};
        beacon.pktType = PKT_HELLO_BEACON;
        beacon.senderRole = static_cast<uint8_t>(m_role);
        beacon.srcIp = myIp.Get();
        beacon.prevHopIp = myIp.Get();
        beacon.originGpsX = static_cast<float>(myPos.x);
        beacon.originGpsY = static_cast<float>(myPos.y);
        beacon.batteryPct = static_cast<float>(m_battery);
        beacon.neighborCnt = static_cast<uint8_t>(std::min<size_t>(6, activeNbs.size()));

        // 1. Advertise closest known SAR Solver (Self, 1-Hop, or 2-Hop Gradient)
        Ipv4Address knownSar = IsSarSolverNode(m_nodeId) ? myIp : Ipv4Address::GetAny();
        Vector knownSarPos = myPos;

        for (size_t i = 0; i < activeNbs.size(); ++i)
        {
            if (i < 6)
            {
                beacon.neighbors[i] = activeNbs[i].ip.Get();
            }
            if (knownSar == Ipv4Address::GetAny() && IsSarSolverNode(activeNbs[i].nodeId))
            {
                knownSar = activeNbs[i].ip;
                knownSarPos = activeNbs[i].position;
            }
        }
        if (knownSar == Ipv4Address::GetAny())
        {
            for (const auto& nb : activeNbs)
            {
                if (nb.advertisedSarIp != Ipv4Address::GetAny())
                {
                    knownSar = nb.advertisedSarIp;
                    knownSarPos = nb.advertisedSarPos;
                    break;
                }
            }
        }
        beacon.nearestSarIp = knownSar.Get();
        beacon.nearestSarGpsX = static_cast<float>(knownSarPos.x);
        beacon.nearestSarGpsY = static_cast<float>(knownSarPos.y);

        // 2. Rotate through our Over-the-Air Location Cache to gossip SAR team positions across the mesh
        if (!m_locationCache.empty())
        {
            auto it = m_locationCache.begin();
            std::advance(it, m_gossipCursor % m_locationCache.size());
            m_gossipCursor++;

            beacon.gossipSarIp = it->second.ip.Get();
            beacon.gossipSarGpsX = static_cast<float>(it->second.position.x);
            beacon.gossipSarGpsY = static_cast<float>(it->second.position.y);
            beacon.gossipTimeNs = it->second.timestamp.GetNanoSeconds();
        }

        Ptr<Packet> pkt = Create<Packet>(reinterpret_cast<const uint8_t*>(&beacon),
                                         sizeof(OverlayWireHeader));
        m_socket->SendTo(pkt, 0, InetSocketAddress(Ipv4Address::GetBroadcast(), 9999));

        // Orthogonal Adaptive Trickle Beacon Scaling (--enableAdaptive=true)
        if (m_enableAdaptive)
        {
            if (activeNbs.size() == m_lastNeighborCount)
            {
                m_beaconInterval = Seconds(std::min(2.5, m_beaconInterval.GetSeconds() * 1.35));
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
        if (m_baseProtocol == "DSR" || m_baseProtocol == "HWMP" ||
            dstIp == Ipv4Address::GetAny())
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

    // Helper: Selects best 1-hop neighbor combining Distance, Adaptive Battery Cost & Security Trust
    Ipv4Address SelectBestOverlayNeighbor(const Vector& myPos,
                                          const Vector& dstPos,
                                          bool requireCloserThanMe,
                                          const std::vector<NeighborEntry>& neighbors) const
    {
        double myDist = (myPos - dstPos).GetLength();
        double wBattery = (m_enableAdaptive && m_battery < 30.0) ? 0.6 : (m_enableAdaptive ? 0.15 : 0.0);
        double wDist = 1.0 - wBattery;

        Ipv4Address bestIp = Ipv4Address("0.0.0.0");
        double minCost = 1e9;

        for (const auto& nb : neighbors)
        {
            if (m_enableSecurity && m_trustScores.at(nb.nodeId) < 0.5)
            {
                continue; // Isolate malicious Blackhole neighbor flagged by Watchdog
            }
            double d = (nb.position - dstPos).GetLength();
            if (requireCloserThanMe && d >= myDist)
            {
                continue;
            }

            double normDist = d / 700.0;
            double energyPen = (100.0 - nb.battery) / 100.0;
            double cost = (wDist * normDist) + (wBattery * energyPen);

            if (m_enableSecurity)
            {
                cost /= std::max(0.1, m_trustScores.at(nb.nodeId));
            }

            if (cost < minCost)
            {
                minCost = cost;
                bestIp = nb.ip;
            }
        }
        return bestIp;
    }

    void TransmitBundleTo(const DtnBundle& b, Ipv4Address nextHopIp, uint16_t ticketsToGive)
    {
        if (b.ttl == 0)
        {
            return;
        }

        Ipv4Address myIp = GetNodeIp(m_nodeId);
        OverlayWireHeader wireHdr = {};
        wireHdr.pktType = b.pktType;
        wireHdr.senderRole = static_cast<uint8_t>(m_role);
        wireHdr.survivorCount = b.survivorCount;
        wireHdr.gpsrMode = b.gpsrMode;
        wireHdr.failureDist = b.failureDist;
        wireHdr.srcIp = b.source.Get();
        wireHdr.dstIp = b.destination.Get();
        wireHdr.prevHopIp = myIp.Get();
        wireHdr.seqNum = b.seqNum;
        wireHdr.txTimeNs = b.txTimeNs;
        wireHdr.flowId = b.flowId;
        wireHdr.tickets = ticketsToGive;
        wireHdr.ttl = static_cast<uint8_t>(b.ttl - 1);
        wireHdr.originGpsX = b.originX;
        wireHdr.originGpsY = b.originY;
        wireHdr.dstGpsX = b.dstX;
        wireHdr.dstGpsY = b.dstY;
        wireHdr.hasValidDstGps = b.hasValidDstGps ? 1 : 0;

        uint32_t totalSize = std::max<uint32_t>(b.payloadSize, sizeof(OverlayWireHeader));
        std::vector<uint8_t> rawBuf(totalSize, 0);
        std::memcpy(rawBuf.data(), &wireHdr, sizeof(OverlayWireHeader));

        Ptr<Packet> pkt = Create<Packet>(rawBuf.data(), totalSize);
        m_socket->SendTo(pkt, 0, InetSocketAddress(nextHopIp, b.port));
        m_battery = std::max(5.0, m_battery - 0.04);

        uint32_t relayIdx = GetNodeIndexByIp(nextHopIp);
        bool isFinalSink = (nextHopIp == b.destination) ||
                           (b.pktType == PKT_SOS_ANYCAST && IsSarSolverNode(relayIdx));

        if (m_enableSecurity && !isFinalSink)
        {
            uint64_t wdKey = (static_cast<uint64_t>(b.seqNum) << 16) | relayIdx;
            m_pendingWatchdog[wdKey] = Simulator::Now();
            Simulator::Schedule(Seconds(1.5),
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
        Vector myPos = GetMyOwnGnssPosition();

        for (auto it = m_buffer.begin(); it != m_buffer.end();)
        {
            if (!m_enableDtn && !m_enableAdaptive && (now - it->creationTime) > Seconds(2.5))
            {
                it = m_buffer.erase(it);
                continue;
            }

            // Step A1: Direct 1-Hop Delivery to ANY SAR Solver for Anycast SOS
            if (it->pktType == PKT_SOS_ANYCAST)
            {
                Ipv4Address directSarIp = Ipv4Address::GetAny();
                for (const auto& nb : neighbors)
                {
                    if (IsSarSolverNode(nb.nodeId))
                    {
                        directSarIp = nb.ip;
                        break;
                    }
                }
                if (directSarIp != Ipv4Address::GetAny())
                {
                    TransmitBundleTo(*it, directSarIp, 1);
                    it = m_buffer.erase(it);
                    continue;
                }
            }

            // Step A2: Resolve Target IP & Over-the-Air Target GPS Coordinates
            Ipv4Address targetIp = Ipv4Address::GetAny();
            Vector dstPos(0.0, 0.0, 0.0);
            bool hasOtaGps = ResolveTargetForBundle(*it, neighbors, targetIp, dstPos);

            if (targetIp != Ipv4Address::GetAny())
            {
                uint32_t dstNodeIdx = GetNodeIndexByIp(targetIp);
                if (m_neighborTable.find(dstNodeIdx) != m_neighborTable.end())
                {
                    TransmitBundleTo(*it, targetIp, 1);
                    it = m_buffer.erase(it);
                    continue;
                }
            }

            bool forwardedPrimaryNow = false;

            // Step B: Primary Multi-Hop Routing (With Orthogonal Security & Adaptive Overlays)
            if (!it->primaryForwarded)
            {
                if (m_baseProtocol == "AODV" || m_baseProtocol == "OLSR" ||
                    m_baseProtocol == "DSDV" || m_baseProtocol == "HYBRID")
                {
                    Ipv4Address l3NextHop;
                    if (targetIp != Ipv4Address::GetAny() &&
                        GetActiveL3NextHop(targetIp, l3NextHop))
                    {
                        uint32_t gwIdx = GetNodeIndexByIp(l3NextHop);
                        if (!m_enableSecurity || m_trustScores[gwIdx] >= 0.5)
                        {
                            TransmitBundleTo(*it, l3NextHop, 1);
                            forwardedPrimaryNow = true;
                        }
                    }

                    // If L3 next-hop was untrusted (Blackhole) or unavailable, use Security/Adaptive neighbor fallback
                    if (!forwardedPrimaryNow && (m_enableSecurity || m_enableAdaptive) && hasOtaGps)
                    {
                        Ipv4Address fallbackIp =
                            SelectBestOverlayNeighbor(myPos, dstPos, false, neighbors);
                        if (fallbackIp != Ipv4Address("0.0.0.0"))
                        {
                            TransmitBundleTo(*it, fallbackIp, 1);
                            forwardedPrimaryNow = true;
                        }
                    }
                }
                else if (m_baseProtocol == "GRP" || m_baseProtocol == "GPSR")
                {
                    // True God-View-Free GPSR/GRP:
                    // Requires Over-the-Air learned coordinates (hasOtaGps == true)
                    if (hasOtaGps)
                    {
                        double myDist = (myPos - dstPos).GetLength();

                        // Exit Condition from Perimeter Mode back to Greedy Mode
                        if (it->gpsrMode == GPSR_MODE_PERIMETER && myDist < it->failureDist)
                        {
                            it->gpsrMode = GPSR_MODE_GREEDY;
                        }

                        if (it->gpsrMode == GPSR_MODE_GREEDY)
                        {
                            Ipv4Address greedyNb =
                                SelectBestOverlayNeighbor(myPos, dstPos, true, neighbors);
                            if (greedyNb != Ipv4Address("0.0.0.0"))
                            {
                                TransmitBundleTo(*it, greedyNb, 1);
                                forwardedPrimaryNow = true;
                            }
                            else if (!neighbors.empty())
                            {
                                // Local Minimum (Void) Detected! Stamp Failure_Distance & Switch to Perimeter Mode
                                it->gpsrMode = GPSR_MODE_PERIMETER;
                                it->failureDist = static_cast<float>(myDist);
                                Ipv4Address perimNb = SelectRightHandRulePerimeterNeighbor(
                                    myPos, dstPos, it->prevHop, neighbors);
                                if (perimNb != Ipv4Address("0.0.0.0"))
                                {
                                    TransmitBundleTo(*it, perimNb, 1);
                                    forwardedPrimaryNow = true;
                                }
                            }
                        }
                        else
                        {
                            // Continue Right-Hand Rule Perimeter Traversal around Void
                            Ipv4Address perimNb = SelectRightHandRulePerimeterNeighbor(
                                myPos, dstPos, it->prevHop, neighbors);
                            if (perimNb != Ipv4Address("0.0.0.0"))
                            {
                                TransmitBundleTo(*it, perimNb, 1);
                                forwardedPrimaryNow = true;
                            }
                        }
                    }
                    else
                    {
                        // Coordinate Blindness Mitigation: Topological L3 Fallback if GPS not yet gossiped
                        Ipv4Address l3Backup;
                        if (targetIp != Ipv4Address::GetAny() &&
                            GetActiveL3NextHop(targetIp, l3Backup))
                        {
                            TransmitBundleTo(*it, l3Backup, 1);
                            forwardedPrimaryNow = true;
                        }
                    }
                }
                else if (m_baseProtocol == "ZRP")
                {
                    Ipv4Address iarpNextHop = Ipv4Address("0.0.0.0");
                    std::vector<NeighborEntry> borderNodes;

                    for (const auto& nb : neighbors)
                    {
                        if (m_enableSecurity && m_trustScores[nb.nodeId] < 0.5)
                        {
                            continue;
                        }
                        if (it->pktType == PKT_SOS_ANYCAST &&
                            nb.advertisedSarIp != Ipv4Address::GetAny())
                        {
                            iarpNextHop = nb.ip;
                            break;
                        }
                        for (const auto& twoHopIp : nb.twoHopNeighbors)
                        {
                            if (twoHopIp == targetIp)
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
                        forwardedPrimaryNow = true;
                    }
                    else if (!borderNodes.empty())
                    {
                        Ipv4Address brpHop = hasOtaGps
                                                 ? SelectBestOverlayNeighbor(myPos, dstPos, false, borderNodes)
                                                 : borderNodes.front().ip;
                        if (brpHop != Ipv4Address("0.0.0.0"))
                        {
                            TransmitBundleTo(*it, brpHop, 1);
                            forwardedPrimaryNow = true;
                        }
                    }
                }
                else if (m_baseProtocol == "MULTIPATH")
                {
                    Ipv4Address primaryGateway = Ipv4Address("0.0.0.0");
                    if (targetIp != Ipv4Address::GetAny() &&
                        GetActiveL3NextHop(targetIp, primaryGateway))
                    {
                        uint32_t gwIdx = GetNodeIndexByIp(primaryGateway);
                        if (!m_enableSecurity || m_trustScores[gwIdx] >= 0.5)
                        {
                            TransmitBundleTo(*it, primaryGateway, 1);
                            forwardedPrimaryNow = true;
                        }
                    }

                    uint32_t sentCount = forwardedPrimaryNow ? 1 : 0;
                    for (const auto& nb : neighbors)
                    {
                        if (m_enableSecurity && m_trustScores[nb.nodeId] < 0.5)
                        {
                            continue;
                        }
                        if (nb.ip != primaryGateway && sentCount < 2)
                        {
                            TransmitBundleTo(*it, nb.ip, 1);
                            forwardedPrimaryNow = true;
                            sentCount++;
                        }
                    }
                }

                if (forwardedPrimaryNow)
                {
                    it->primaryForwarded = true;
                }
            }

            // Step C: DTN Binary Spray-and-Wait Store-Carry-and-Forward Fallback
            // Triggered when --enableDtn=true OR when --enableAdaptive=true detects sparse connectivity (<3 neighbors)
            bool triggerDtnSpray = m_enableDtn || (m_enableAdaptive && neighbors.size() < 3) ||
                                   (m_enableAdaptive && !it->primaryForwarded);

            if (triggerDtnSpray)
            {
                for (const auto& nb : neighbors)
                {
                    if (m_enableSecurity && m_trustScores[nb.nodeId] < 0.5)
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

            if (it->primaryForwarded && !m_enableDtn && !m_enableAdaptive)
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
        Time now = Simulator::Now();

        while ((packet = socket->RecvFrom(from)))
        {
            if (packet->GetSize() < sizeof(OverlayWireHeader))
            {
                continue;
            }

            OverlayWireHeader wireHdr;
            packet->CopyData(reinterpret_cast<uint8_t*>(&wireHdr), sizeof(OverlayWireHeader));

            // 1. Process Incoming Over-the-Air HELLO Beacon & Location Gossip
            if (wireHdr.pktType == PKT_HELLO_BEACON)
            {
                Ipv4Address senderIp(wireHdr.srcIp);
                if (senderIp == myIp)
                {
                    continue;
                }
                uint32_t senderIdx = GetNodeIndexByIp(senderIp);
                Vector senderPos(wireHdr.originGpsX, wireHdr.originGpsY, 0.0);

                // Record 1-hop neighbor's position in Over-the-Air Location Cache
                UpdateOtaLocationCache(senderIp, senderPos, now);

                // Record advertised nearest SAR Solver position in Over-the-Air Location Cache
                Ipv4Address advSarIp(wireHdr.nearestSarIp);
                Vector advSarPos(wireHdr.nearestSarGpsX, wireHdr.nearestSarGpsY, 0.0);
                if (advSarIp != Ipv4Address::GetAny())
                {
                    UpdateOtaLocationCache(advSarIp, advSarPos, now);
                }

                // Record gossiped SAR Unit position in Over-the-Air Location Cache
                Ipv4Address gossipIp(wireHdr.gossipSarIp);
                if (gossipIp != Ipv4Address::GetAny() && wireHdr.gossipTimeNs > 0)
                {
                    UpdateOtaLocationCache(gossipIp,
                                           Vector(wireHdr.gossipSarGpsX, wireHdr.gossipSarGpsY, 0.0),
                                           NanoSeconds(wireHdr.gossipTimeNs));
                }

                NeighborEntry entry;
                entry.ip = senderIp;
                entry.nodeId = senderIdx;
                entry.role = static_cast<DisasterNodeRole>(wireHdr.senderRole);
                entry.position = senderPos;
                entry.battery = wireHdr.batteryPct;
                entry.degree = wireHdr.neighborCnt;
                entry.advertisedSarIp = advSarIp;
                entry.advertisedSarPos = advSarPos;
                entry.lastSeen = now;
                for (uint8_t k = 0; k < wireHdr.neighborCnt && k < 6; ++k)
                {
                    entry.twoHopNeighbors.emplace_back(wireHdr.neighbors[k]);
                }
                m_neighborTable[senderIdx] = entry;
                continue;
            }

            // 2. Process Incoming Watchdog Custody / Overhearing Confirmation
            if (wireHdr.pktType == PKT_WATCHDOG_CUSTODY)
            {
                uint32_t relayIdx = GetNodeIndexByIp(Ipv4Address(wireHdr.prevHopIp));
                uint64_t wdKey = (static_cast<uint64_t>(wireHdr.seqNum) << 16) | relayIdx;
                if (m_pendingWatchdog.erase(wdKey) > 0)
                {
                    m_trustScores[relayIdx] = std::min(1.0, m_trustScores[relayIdx] + 0.05);
                }
                continue;
            }

            // 3. Compromised / Selfish Blackhole Relay Nodes (Nodes 14, 19, 24) when Security Test is Active
            if (m_enableSecurity && (m_nodeId == 14 || m_nodeId == 19 || m_nodeId == 24))
            {
                continue;
            }

            Ipv4Address dstIp(wireHdr.dstIp);
            Ipv4Address srcIp(wireHdr.srcIp);
            Ipv4Address prevHopIp(wireHdr.prevHopIp);

            // Learn original sender's GPS from piggybacked packet header!
            UpdateOtaLocationCache(srcIp,
                                   Vector(wireHdr.originGpsX, wireHdr.originGpsY, 0.0),
                                   NanoSeconds(wireHdr.txTimeNs));
            if (wireHdr.hasValidDstGps)
            {
                UpdateOtaLocationCache(dstIp,
                                       Vector(wireHdr.dstGpsX, wireHdr.dstGpsY, 0.0),
                                       NanoSeconds(wireHdr.txTimeNs));
            }

            // 4. Check Final Delivery (Anycast SOS to ANY SAR Solver, or Unicast SAR Coord to dstIp)
            bool isSosDeliveredToSar =
                (wireHdr.pktType == PKT_SOS_ANYCAST && IsSarSolverNode(m_nodeId));
            bool isCoordDelivered = (wireHdr.pktType == PKT_SAR_COORD && dstIp == myIp);

            if (isSosDeliveredToSar || isCoordDelivered)
            {
                RecordE2ERx(wireHdr.flowId,
                            wireHdr.seqNum,
                            packet->GetSize(),
                            wireHdr.txTimeNs);
                continue;
            }

            // 5. Honest Relay sends 1-hop Watchdog Custody / Forwarding Confirmation
            if (m_enableSecurity && prevHopIp != myIp)
            {
                OverlayWireHeader wdAck = {};
                wdAck.pktType = PKT_WATCHDOG_CUSTODY;
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
                DtnBundle relayBundle = {wireHdr.pktType,
                                         wireHdr.survivorCount,
                                         wireHdr.gpsrMode,
                                         wireHdr.failureDist,
                                         packet->GetSize(),
                                         srcIp,
                                         dstIp,
                                         prevHopIp,
                                         9999,
                                         wireHdr.flowId,
                                         wireHdr.seqNum,
                                         wireHdr.txTimeNs,
                                         wireHdr.tickets,
                                         wireHdr.ttl,
                                         wireHdr.originGpsX,
                                         wireHdr.originGpsY,
                                         wireHdr.dstGpsX,
                                         wireHdr.dstGpsY,
                                         wireHdr.hasValidDstGps == 1,
                                         now,
                                         false,
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
    DisasterNodeRole m_role;
    std::string m_baseProtocol;
    bool m_enableDtn;
    bool m_enableSecurity;
    bool m_enableAdaptive;
    double m_battery;
    size_t m_lastNeighborCount;
    size_t m_gossipCursor;
    std::deque<DtnBundle> m_buffer;
    std::set<uint32_t> m_seenPackets;
    std::map<uint32_t, NeighborEntry> m_neighborTable;
    std::map<uint32_t, LearnedLocationEntry> m_locationCache;
    std::map<uint32_t, double> m_trustScores;
    std::map<uint64_t, Time> m_pendingWatchdog;
};

uint32_t UnifiedMeshRoutingApp::s_globalSeqCounter = 0;

// ============================================================================
// 5. Main Simulation Script
// ============================================================================
int main(int argc, char* argv[])
{
    double simTime = 150.0;
    uint32_t numNodes = 45;
    std::string protocol = "AODV";
    std::string hardware = "RPI";
    bool enableDtn = false;
    bool enableSecurity = false; // Orthogonal Cross-Layer Watchdog Security Flag
    bool enableAdaptive = false; // Orthogonal Cross-Layer Battery & Trickle Adaptive Flag

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Total simulation time in seconds", simTime);
    cmd.AddValue("protocol",
                 "Base Routing Protocol: AODV, OLSR, DSDV, DSR, HWMP, HYBRID, ZRP, GRP, MULTIPATH (or legacy SECURITY / ADAPTIVE)",
                 protocol);
    cmd.AddValue("hardware", "Hardware Profile: RPI or ESP32", hardware);
    cmd.AddValue("enableDtn", "Enable DTN Spray & Wait Fallback Application", enableDtn);
    cmd.AddValue("enableSecurity", "Enable Promiscuous Watchdog Security on ANY protocol", enableSecurity);
    cmd.AddValue("enableAdaptive", "Enable Energy-Aware & Trickle Adaptive Engine on ANY protocol", enableAdaptive);
    cmd.Parse(argc, argv);

    std::transform(protocol.begin(), protocol.end(), protocol.begin(), ::toupper);
    std::transform(hardware.begin(), hardware.end(), hardware.begin(), ::toupper);

    // Map legacy "SECURITY" and "ADAPTIVE" protocol strings cleanly to Option A orthogonal flags
    std::string baseProtocol = protocol;
    if (protocol == "SECURITY")
    {
        baseProtocol = "AODV";
        enableSecurity = true;
    }
    else if (protocol == "ADAPTIVE")
    {
        baseProtocol = "HYBRID";
        enableAdaptive = true;
    }

    bool isEsp32 = (hardware == "ESP32");

    double maxRadioRange = isEsp32 ? 60.0 : 200.0;
    double txPowerDbm = isEsp32 ? 16.0 : 20.0;
    double antennaGainDbi = isEsp32 ? 0.0 : 3.0;
    double pathLossExp = isEsp32 ? 2.7 : 2.5;
    std::string phyDataMode = isEsp32 ? "ErpOfdmRate6Mbps" : "ErpOfdmRate12Mbps";
    uint32_t aodvMaxQueue = isEsp32 ? 20 : 64;
    uint32_t appMaxBuffer = isEsp32 ? 50 : 250;
    uint16_t dtnTickets = isEsp32 ? 6 : 16;

    Config::SetDefault("ns3::aodv::RoutingProtocol::RreqRetries", UintegerValue(2));
    Config::SetDefault("ns3::aodv::RoutingProtocol::ActiveRouteTimeout", TimeValue(Seconds(10.0)));
    Config::SetDefault("ns3::aodv::RoutingProtocol::MaxQueueLen", UintegerValue(aodvMaxQueue));
    Config::SetDefault("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue("500"));

    Time::SetResolution(Time::NS);
    PacketMetadata::Enable();

    NodeContainer nodes;
    nodes.Create(numNodes);

    YansWifiChannelHelper wifiChannel;
    wifiChannel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    wifiChannel.AddPropagationLoss("ns3::LogDistancePropagationLossModel",
                                   "Exponent",
                                   DoubleValue(pathLossExp),
                                   "ReferenceDistance",
                                   DoubleValue(1.0),
                                   "ReferenceLoss",
                                   DoubleValue(40.0));
    wifiChannel.AddPropagationLoss("ns3::RangePropagationLossModel",
                                   "MaxRange",
                                   DoubleValue(maxRadioRange));

    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChannel.Create());
    wifiPhy.Set("TxPowerStart", DoubleValue(txPowerDbm));
    wifiPhy.Set("TxPowerEnd", DoubleValue(txPowerDbm));
    wifiPhy.Set("TxGain", DoubleValue(antennaGainDbi));
    wifiPhy.Set("RxGain", DoubleValue(antennaGainDbi));

    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211g);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue(phyDataMode),
                                 "ControlMode",
                                 StringValue("ErpOfdmRate6Mbps"));

    NetDeviceContainer devices;
    InternetStackHelper stack;

    bool useOverlayEngine = enableDtn || enableSecurity || enableAdaptive ||
                            (baseProtocol == "ZRP" || baseProtocol == "GRP" ||
                             baseProtocol == "GPSR" || baseProtocol == "MULTIPATH");

    if (baseProtocol == "HWMP")
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

        if (baseProtocol == "OLSR")
        {
            OlsrHelper olsr;
            stack.SetRoutingHelper(olsr);
            stack.Install(nodes);
        }
        else if (baseProtocol == "DSDV")
        {
            DsdvHelper dsdv;
            dsdv.Set("PeriodicUpdateInterval", TimeValue(Seconds(10.0)));
            dsdv.Set("SettlingTime", TimeValue(Seconds(2.0)));
            stack.SetRoutingHelper(dsdv);
            stack.Install(nodes);
        }
        else if (baseProtocol == "DSR")
        {
            stack.Install(nodes);
            if (!useOverlayEngine)
            {
                Simulator::Schedule(Seconds(0.001), [nodes]() {
                    DsrMainHelper dsrMain;
                    DsrHelper dsr;
                    dsrMain.Install(dsr, nodes);
                });
            }
        }
        else if (baseProtocol == "HYBRID")
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

    Ipv4InterfaceContainer interfaces = AssignAutonomousMacDerivedIpv4(nodes, devices);

    Ptr<RandomRectanglePositionAllocator> positionAlloc =
        CreateObject<RandomRectanglePositionAllocator>();
    positionAlloc->SetAttribute("X", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"));
    positionAlloc->SetAttribute("Y", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=500.0]"));

    NodeContainer victimNodes;
    NodeContainer civilianRelays;
    NodeContainer sarFootSquads;
    NodeContainer sarCommandVehicles;

    for (uint32_t i = 0; i < numNodes; ++i)
    {
        if (i < 12)
            victimNodes.Add(nodes.Get(i));
        else if (i < 30)
            civilianRelays.Add(nodes.Get(i));
        else if (i < 40)
            sarFootSquads.Add(nodes.Get(i));
        else
            sarCommandVehicles.Add(nodes.Get(i));
    }

    MobilityHelper victimMob;
    victimMob.SetPositionAllocator(positionAlloc);
    victimMob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                               "Speed",
                               StringValue("ns3::UniformRandomVariable[Min=0.05|Max=0.3]"),
                               "Pause",
                               StringValue("ns3::ConstantRandomVariable[Constant=30.0]"),
                               "PositionAllocator",
                               PointerValue(positionAlloc));
    victimMob.Install(victimNodes);

    MobilityHelper civilianMob;
    civilianMob.SetPositionAllocator(positionAlloc);
    civilianMob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                 "Speed",
                                 StringValue("ns3::UniformRandomVariable[Min=0.5|Max=1.5]"),
                                 "Pause",
                                 StringValue("ns3::ConstantRandomVariable[Constant=10.0]"),
                                 "PositionAllocator",
                                 PointerValue(positionAlloc));
    civilianMob.Install(civilianRelays);

    MobilityHelper sarFootMob;
    sarFootMob.SetPositionAllocator(positionAlloc);
    sarFootMob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                "Speed",
                                StringValue("ns3::UniformRandomVariable[Min=0.8|Max=1.8]"),
                                "Pause",
                                StringValue("ns3::ConstantRandomVariable[Constant=5.0]"),
                                "PositionAllocator",
                                PointerValue(positionAlloc));
    sarFootMob.Install(sarFootSquads);

    MobilityHelper sarVehicleMob;
    sarVehicleMob.SetPositionAllocator(positionAlloc);
    sarVehicleMob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                                   "Speed",
                                   StringValue("ns3::UniformRandomVariable[Min=5.0|Max=12.0]"),
                                   "Pause",
                                   StringValue("ns3::ConstantRandomVariable[Constant=2.0]"),
                                   "PositionAllocator",
                                   PointerValue(positionAlloc));
    sarVehicleMob.Install(sarCommandVehicles);

    uint32_t sosPktSize = 1024;
    uint32_t pktsPerVictim = 50;
    double sosIntervalSec = 2.0;

    uint32_t coordPktSize = 512;
    uint32_t coordPktsPerFlow = 100;
    double coordIntervalSec = 1.0;

    uint16_t basePort = useOverlayEngine ? 9999 : 9;
    g_e2eFlows[1] = {1, "Victim_Cluster_1_SOS", interfaces.GetAddress(0), basePort, Ipv4Address("0.0.0.0"), basePort};
    g_e2eFlows[2] = {2, "Victim_Cluster_2_SOS", interfaces.GetAddress(3), static_cast<uint16_t>(useOverlayEngine ? 9999 : 10), Ipv4Address("0.0.0.0"), static_cast<uint16_t>(useOverlayEngine ? 9999 : 10)};
    g_e2eFlows[3] = {3, "Victim_Cluster_3_SOS", interfaces.GetAddress(6), static_cast<uint16_t>(useOverlayEngine ? 9999 : 11), Ipv4Address("0.0.0.0"), static_cast<uint16_t>(useOverlayEngine ? 9999 : 11)};
    g_e2eFlows[4] = {4, "Victim_Cluster_4_SOS", interfaces.GetAddress(9), static_cast<uint16_t>(useOverlayEngine ? 9999 : 12), Ipv4Address("0.0.0.0"), static_cast<uint16_t>(useOverlayEngine ? 9999 : 12)};
    g_e2eFlows[5] = {5, "SAR_Vehicle40_to_FootSquad30", interfaces.GetAddress(40), static_cast<uint16_t>(useOverlayEngine ? 9999 : 13), interfaces.GetAddress(30), static_cast<uint16_t>(useOverlayEngine ? 9999 : 13)};
    g_e2eFlows[6] = {6, "SAR_FootSquad35_to_Vehicle44", interfaces.GetAddress(35), static_cast<uint16_t>(useOverlayEngine ? 9999 : 14), interfaces.GetAddress(44), static_cast<uint16_t>(useOverlayEngine ? 9999 : 14)};

    if (!useOverlayEngine)
    {
        for (int c = 0; c < 4; ++c)
        {
            uint16_t flowId = static_cast<uint16_t>(c + 1);
            uint16_t port = static_cast<uint16_t>(9 + c);
            for (uint32_t sarIdx = 30; sarIdx < numNodes; ++sarIdx)
            {
                UdpEchoServerHelper sosSink(port);
                ApplicationContainer sApps = sosSink.Install(nodes.Get(sarIdx));
                sApps.Start(Seconds(1.0));
                sApps.Stop(Seconds(simTime));
                sApps.Get(0)->TraceConnectWithoutContext(
                    "Rx",
                    MakeBoundCallback(&OnUdpEchoServerRx, flowId));
            }
        }

        for (uint32_t vIdx = 0; vIdx < 12; ++vIdx)
        {
            uint16_t clusterFlowId = static_cast<uint16_t>((vIdx / 3) + 1);
            uint16_t port = static_cast<uint16_t>(8 + clusterFlowId);
            uint32_t targetSarNode = 30 + (vIdx % 15);

            UdpEchoClientHelper sosClient(interfaces.GetAddress(targetSarNode), port);
            sosClient.SetAttribute("MaxPackets", UintegerValue(pktsPerVictim));
            sosClient.SetAttribute("Interval", TimeValue(Seconds(sosIntervalSec)));
            sosClient.SetAttribute("PacketSize", UintegerValue(sosPktSize));
            ApplicationContainer cApps = sosClient.Install(nodes.Get(vIdx));
            cApps.Start(Seconds(5.0 + (vIdx * 0.35)));
            cApps.Stop(Seconds(simTime));
            cApps.Get(0)->TraceConnectWithoutContext(
                "Tx",
                MakeBoundCallback(&OnUdpEchoClientTx, clusterFlowId));
        }

        UdpEchoServerHelper coordSrv5(13);
        ApplicationContainer sApps5 = coordSrv5.Install(nodes.Get(30));
        sApps5.Start(Seconds(1.0));
        sApps5.Stop(Seconds(simTime));
        sApps5.Get(0)->TraceConnectWithoutContext(
            "Rx",
            MakeBoundCallback(&OnUdpEchoServerRx, static_cast<uint16_t>(5)));

        UdpEchoClientHelper coordCli5(interfaces.GetAddress(30), 13);
        coordCli5.SetAttribute("MaxPackets", UintegerValue(coordPktsPerFlow));
        coordCli5.SetAttribute("Interval", TimeValue(Seconds(coordIntervalSec)));
        coordCli5.SetAttribute("PacketSize", UintegerValue(coordPktSize));
        ApplicationContainer cApps5 = coordCli5.Install(nodes.Get(40));
        cApps5.Start(Seconds(6.0));
        cApps5.Stop(Seconds(simTime));
        cApps5.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(5)));

        UdpEchoServerHelper coordSrv6(14);
        ApplicationContainer sApps6 = coordSrv6.Install(nodes.Get(44));
        sApps6.Start(Seconds(1.0));
        sApps6.Stop(Seconds(simTime));
        sApps6.Get(0)->TraceConnectWithoutContext(
            "Rx",
            MakeBoundCallback(&OnUdpEchoServerRx, static_cast<uint16_t>(6)));

        UdpEchoClientHelper coordCli6(interfaces.GetAddress(44), 14);
        coordCli6.SetAttribute("MaxPackets", UintegerValue(coordPktsPerFlow));
        coordCli6.SetAttribute("Interval", TimeValue(Seconds(coordIntervalSec)));
        coordCli6.SetAttribute("PacketSize", UintegerValue(coordPktSize));
        ApplicationContainer cApps6 = coordCli6.Install(nodes.Get(35));
        cApps6.Start(Seconds(6.5));
        cApps6.Stop(Seconds(simTime));
        cApps6.Get(0)->TraceConnectWithoutContext(
            "Tx",
            MakeBoundCallback(&OnUdpEchoClientTx, static_cast<uint16_t>(6)));
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
            overlayApps[i]->Setup(sock,
                                  dtnTickets,
                                  appMaxBuffer,
                                  nodes,
                                  i,
                                  baseProtocol,
                                  enableDtn,
                                  enableSecurity,
                                  enableAdaptive);
            nodes.Get(i)->AddApplication(overlayApps[i]);
            overlayApps[i]->SetStartTime(Seconds(0.5));
            overlayApps[i]->SetStopTime(Seconds(simTime));
        }

        for (uint32_t vIdx = 0; vIdx < 12; ++vIdx)
        {
            uint16_t clusterFlowId = static_cast<uint16_t>((vIdx / 3) + 1);
            uint8_t survivorsInGroup = static_cast<uint8_t>((vIdx % 4) + 1);
            double startOffset = 5.0 + (vIdx * 0.35);

            for (uint32_t p = 0; p < pktsPerVictim; ++p)
            {
                Simulator::Schedule(Seconds(startOffset + p * sosIntervalSec),
                                    &UnifiedMeshRoutingApp::TriggerVictimSosDistress,
                                    overlayApps[vIdx],
                                    clusterFlowId,
                                    survivorsInGroup,
                                    sosPktSize);
            }
        }

        for (uint32_t p = 0; p < coordPktsPerFlow; ++p)
        {
            Simulator::Schedule(Seconds(6.0 + p * coordIntervalSec),
                                &UnifiedMeshRoutingApp::SendSarTeamCoordination,
                                overlayApps[40],
                                static_cast<uint16_t>(5),
                                interfaces.GetAddress(30),
                                coordPktSize);
        }

        for (uint32_t p = 0; p < coordPktsPerFlow; ++p)
        {
            Simulator::Schedule(Seconds(6.5 + p * coordIntervalSec),
                                &UnifiedMeshRoutingApp::SendSarTeamCoordination,
                                overlayApps[35],
                                static_cast<uint16_t>(6),
                                interfaces.GetAddress(44),
                                coordPktSize);
        }

        std::cout << "Disaster SAR Mesh Engine Active [Hardware: " << hardware
                  << " | Base Protocol: " << baseProtocol
                  << " | DTN: " << (enableDtn ? "ON" : "OFF")
                  << " | Security Watchdog: " << (enableSecurity ? "ON" : "OFF")
                  << " | Adaptive QoS: " << (enableAdaptive ? "ON" : "OFF") << "]\n";
    }

    // Build descriptive label for CSV and NetAnim files
    std::string protoTag = protocol;
    if (protocol != "SECURITY" && enableSecurity)
        protoTag += "_SEC";
    if (protocol != "ADAPTIVE" && enableAdaptive)
        protoTag += "_ADAPT";
    if (enableDtn)
        protoTag += "_DTN";

    std::string modeLabel = hardware + "_" + protoTag;
    AnimationInterface anim("emergency_mesh_" + modeLabel + ".xml");
    anim.SetMaxPktsPerTraceFile(0xFFFFFFFF);

    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        anim.UpdateNodeSize(nodes.Get(i), 11.0, 11.0);
        DisasterNodeRole role = GetNodeDisasterRole(i);

        if (role == ROLE_TRAPPED_VICTIM)
        {
            anim.UpdateNodeDescription(nodes.Get(i), "Victim-SOS (" + std::to_string(i) + ")");
            anim.UpdateNodeColor(nodes.Get(i), 220, 20, 60);
        }
        else if (role == ROLE_CIVILIAN_RELAY)
        {
            if (enableSecurity && (i == 14 || i == 19 || i == 24))
            {
                anim.UpdateNodeDescription(nodes.Get(i), "Blackhole (" + std::to_string(i) + ")");
                anim.UpdateNodeColor(nodes.Get(i), 25, 25, 25);
            }
            else
            {
                anim.UpdateNodeDescription(nodes.Get(i), "Civilian-Relay (" + std::to_string(i) + ")");
                anim.UpdateNodeColor(nodes.Get(i), 255, 140, 0);
            }
        }
        else if (role == ROLE_SAR_FOOT_SQUAD)
        {
            anim.UpdateNodeDescription(nodes.Get(i), "SAR-Foot-Squad (" + std::to_string(i) + ")");
            anim.UpdateNodeColor(nodes.Get(i), 0, 180, 70);
        }
        else
        {
            anim.UpdateNodeDescription(nodes.Get(i), "SAR-Command-Vehicle (" + std::to_string(i) + ")");
            anim.UpdateNodeColor(nodes.Get(i), 0, 190, 240);
        }
    }

    FlowMonitorHelper flowmonHelper;
    Ptr<FlowMonitor> monitor = nullptr;
    if (baseProtocol != "DSR")
    {
        monitor = flowmonHelper.InstallAll();
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    std::string csvFileName = "flowmon_results_" + modeLabel + ".csv";
    std::ofstream csvFile(csvFileName, std::ios::out);

    csvFile << "Hardware,Protocol,FlowID,FlowLabel,SrcAddr,SrcPort,DstAddr,DstPort,FlowType,"
               "TxPackets,RxPackets,LostPackets,PDR_Percent,AvgDelay_ms,Throughput_Kbps\n";

    std::cout << "DISASTER SAR PERFORMANCE REPORT [Mode: " << modeLabel << "]\n";

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

        std::string flowCategory = (flowId <= 4) ? "Victim_SOS_Anycast" : "SAR_Team_Coordination";

        csvFile << hardware << "," << protoTag << "," << flowId << "," << st.flowLabel << ","
                << st.srcAddr << "," << st.srcPort << "," << st.dstAddr << "," << st.dstPort << ","
                << flowCategory << "," << st.txPackets << "," << st.rxPackets << "," << lost << ","
                << pdr << "," << avgDelayMs << "," << tputKbps << "\n";

        std::cout << "FLOW " << flowId << " [" << st.flowLabel << "] (Src=" << st.srcAddr
                  << " -> Dst=" << (flowId <= 4 ? "ANY_SAR_RESCUER" : "SAR_UNIT") << ")\n"
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

            if (tuple.destinationPort >= 9 && tuple.destinationPort <= 14)
            {
                flowType = "Application_L3_Fwd";
            }
            else if (tuple.sourcePort >= 9 && tuple.sourcePort <= 14)
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

            csvFile << hardware << "," << protoTag << "," << (iter->first + 100) << ",L3_Flow,"
                    << tuple.sourceAddress << "," << tuple.sourcePort << ","
                    << tuple.destinationAddress << "," << tuple.destinationPort << "," << flowType
                    << "," << iter->second.txPackets << "," << iter->second.rxPackets << ","
                    << iter->second.lostPackets << "," << pdr << "," << meanDelay << ","
                    << throughputKbps << "\n";
        }
    }

    csvFile.close();

    double overallPdr =
        (totalAppTx > 0) ? (static_cast<double>(totalAppRx) / totalAppTx * 100.0) : 0.0;
    double overallAvgDelayMs = (totalAppRx > 0) ? (weightedDelaySumMs / totalAppRx) : 0.0;

    std::string summaryFileName = "all_protocols_summary_" + hardware + ".csv";
    bool summaryExists = std::ifstream(summaryFileName).good();
    std::ofstream summaryFile(summaryFileName, std::ios::out | std::ios::app);

    if (!summaryExists)
    {
        summaryFile << "Hardware,Protocol_Mode,TotalTxPackets,TotalRxPackets,TotalLostPackets,"
                       "Overall_PDR_Percent,Overall_AvgDelay_ms,Aggregate_Throughput_Kbps\n";
    }
    summaryFile << hardware << "," << protoTag << "," << totalAppTx << "," << totalAppRx << ","
                << totalAppLost << "," << overallPdr << "," << overallAvgDelayMs << ","
                << totalThroughputKbps << "\n";

    summaryFile.close();

    std::cout << "OVERALL SUMMARY [" << modeLabel << "]: Tx=" << totalAppTx
              << " | Rx=" << totalAppRx << " | PDR=" << overallPdr
              << "% | AvgDelay=" << overallAvgDelayMs
              << " ms | TotalThroughput=" << totalThroughputKbps << " Kbps\n";
    std::cout << "Detailed flows exported to: " << csvFileName << "\n";
    std::cout << "Aggregate row appended to : " << summaryFileName << "\n\n";

    Simulator::Destroy();
    return 0;
}