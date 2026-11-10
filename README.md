# Disaster Emergency Ad-Hoc &amp; Mesh Network Simulation in NS-3

An advanced Network Simulator 3 (NS-3) C++ simulation framework evaluating multi-protocol Mobile Ad-Hoc Networks (MANET), IEEE 802.11s Wireless Mesh Networks, and Delay-Tolerant Networking (DTN) overlays for off-grid disaster Search-and-Rescue (SAR) scenarios.

## Prerequisites

This project is designed for **Linux (Ubuntu 22.04 LTS / 24.04 LTS or Debian 11/12)** and **Windows Subsystem for Linux (WSL2)**.

### System Dependencies

Open your terminal and install the required C++ toolchain, CMake build system, Python dependencies, and Qt5 libraries for NetAnim:

```bash
sudo apt update
sudo apt install -y g++ python3 python3-dev pkg-config sqlite3 cmake git qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools ccache
```

## NS-3 & NetAnim Setup

### 1. Download and Extract NS-3 (Version 3.36+ / 3.48)

NS-3 releases can be viewed and downloaded from the [NS-3 releases page](https://www.nsnam.org/releases/). To directly download the version used in this project, v3.48, download the [NS-3.48 release archive](https://www.nsnam.org/releases/ns-allinone-3.48.tar.bz2). After downloading open the terminal and go to the Linux folder where the package was downloaded, then run the following commands to unpack NS-3:

```bash
tar xfj ns-allinone-3.48.tar.bz2  # change name according to your own folder name
cd ns-allinone-3.48/ns-3.48
```

### 2. Configure and Build Base NS-3

Initialize CMake configuration and run the build wrapper:

```bash
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

### 3. Compile NetAnim Visualizer

Navigate to the `netanim` directory inside `ns-allinone-3.48` and build the GUI binary using `qmake`:

```bash
cd ~/ns-allinone-3.48/netanim-3.109
qmake NetAnim.pro
make -j$(nproc)
```

## Repository Structure & Placement

In NS-3, user simulation C++ scripts must reside inside the `scratch/` directory located at the root of your NS-3 installation (`~/ns-allinone-3.48/ns-3.48/scratch/`).

Place your C++ simulation file into the `scratch/` folder:

```text
ns-3.48/ 
├── build/ 
├── src/ 
├── examples/ 
├── scratch/ 
│ └── ad-hoc-network.cc   <-- Place your script here 
└── ns3
```

## Building the Project

Always compile from the main NS-3 directory (`~/ns-allinone-3.48/ns-3.48/`).

### Recommended Single Target Build (Memory Safe)

To prevent terminal crashes or RAM exhaustion during parallel compilation, limit build jobs to **2 threads** (`-j 2`) and target specifically `scratch/ad-hoc-network`:

```bash
cd ~/ns-allinone-3.48/ns-3.48
./ns3 build scratch/ad-hoc-network -j 2
```

## Running Simulations

Execute the compiled script using `./ns3 run`:

### Basic Execution

```bash
./ns3 run scratch/ad-hoc-network
```

### Running with Custom Parameters

Pass command-line flags inside quotes:

```bash
# Run AODV with DTN Store-Carry-Forward enabled
./ns3 run "scratch/ad-hoc-network --protocol=AODV --enableDtn=true --simTime=150.0"

# Run Hybrid Routing (OLSR -> AODV -> DSDV) on Raspberry Pi Hardware profile
./ns3 run "scratch/ad-hoc-network --protocol=HYBRID --hardware=RPI --enableDtn=false"

# Run IEEE 802.11s HWMP Mesh Protocol
./ns3 run "scratch/ad-hoc-network --protocol=HWMP --hardware=ESP32"
```

### Running without Re-building (`--no-build`)

If you are repeatedly running simulations with different parameters without changing the C++ code, bypass the build check to speed up execution:

```bash
./ns3 run "scratch/ad-hoc-network --protocol=OLSR --enableDtn=true" --no-build
```

## Command-Line Parameters

The `ad-hoc-network.cc` script supports dynamic runtime configuration via `ns3::CommandLine`:

| Parameter          | Type       | Default | Description                                                                                |
| ------------------ | ---------- | ------- | ------------------------------------------------------------------------------------------ |
| `--protocol`       | `string`   | `AODV`  | Active routing protocol (`AODV`, `OLSR`, `DSDV`, `DSR`, `HWMP`, `HYBRID`, `ZRP`, `GRP`)    |
| `--hardware`       | `string`   | `RPI`   | Radio profile (`RPI` \= 802.11g 54Mbps / 200m range, `ESP32` \= 802.11g 6Mbps / 60m range) |
| `--enableDtn`      | `bool`     | `false` | Enable/disable Spray &amp; Wait Delay-Tolerant Networking persistent buffering             |
| `--enableSecurity` | `bool`     | `false` | Enable/disable L3 security watchdog monitoring for blackhole nodes                         |
| `--enableAdaptive` | `bool`     | `false` | Enable/disable dynamic adaptive QoS queue prioritization                                   |
| `--simTime`        | `double`   | `150.0` | Total simulation execution time in seconds                                                 |
| `--nVictims`       | `uint32_t` | `10`    | Number of moving victim nodes                                                              |

To list all available attributes and options built into the binary:

```bash
./ns3 run "scratch/ad-hoc-network --PrintHelp"
```

## Automated Batch Campaign

To run all permutations across routing protocols, DTN flags, security settings, and hardware profiles, use the bash control script below.

Save this script as **`run_disaster_campaign.sh`** in `~/ns-allinone-3.48/ns-3.48/`:

```bash
#!/bin/bash

PROTOCOLS=("AODV" "OLSR" "DSDV" "DSR" "HWMP" "HYBRID" "ZRP" "GRP" "MULTIPATH")
HARDWARE_PROFILES=("RPI" "ESP32")
BOOL_FLAGS=("false" "true")

echo "Building ONLY scratch/ad-hoc-network with 2 threads (-j 2) to prevent RAM crash..."
./ns3 build scratch/ad-hoc-network -j 2

if [ $? -ne 0 ]; then
    echo "Build failed! Please check compiler output above."
    exit 1
fi

for hw in "${HARDWARE_PROFILES[@]}"; do
    rm -f "all_protocols_summary_${hw}.csv"
done

echo "Starting automated simulation campaign (--no-build mode)..."

for hw in "${HARDWARE_PROFILES[@]}"; do
    echo "HARDWARE PROFILE: $hw"

    for proto in "${PROTOCOLS[@]}"; do
        for dtn in "${BOOL_FLAGS[@]}"; do
            for sec in "${BOOL_FLAGS[@]}"; do
                for adapt in "${BOOL_FLAGS[@]}"; do

                    echo "Running: HW=$hw | Proto=$proto | DTN=$dtn | Sec=$sec | Adapt=$adapt"

                    ./ns3 run "scratch/ad-hoc-network \
                        --hardware=$hw \
                        --protocol=$proto \
                        --enableDtn=$dtn \
                        --enableSecurity=$sec \
                        --enableAdaptive=$adapt \
                        --simTime=150.0" --no-build

                done
            done
        done
    done
done

echo "CAMPAIGN COMPLETE!"
```

Make it executable and launch:

```bash
chmod +x run_disaster_campaign.sh
./run_disaster_campaign.sh
```

## Visualizing in NetAnim

When the simulation runs, it automatically outputs an XML trace file (`emergency_mesh_animation.xml` or similar) in the main NS-3 root directory.

1. Launch NetAnim:

```bash
cd ~/ns-allinone-3.48/netanim-3.109
./NetAnim
```
1. Click the **Folder Icon** in the top-left toolbar.
2. Open `~/ns-allinone-3.48/ns-3.48/emergency_mesh_animation.xml`.
3. Click **Play** to animate node movement, wireless range circles, and packet transmissions.
