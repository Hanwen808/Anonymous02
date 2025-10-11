## Chronus

### Introduction

Detecting flows with persistently high round-trip times (RTTs) is critical for load balancing, fault diagnosis, and anomaly detection in high-speed networks. 
Existing approaches either collect per-flow RTT samples for offline analysis or employ sketches to summarize RTT information in the data plane. 
However, these methods suffer from unacceptable communication overhead and latency, or fail to capture the packet-acknowledgment dependencies essential for RTT measurement.
In this paper, we present Chronus, a sketch-based framework for accurate and memory-efficient high-RTT flow detection at line rate. 
Chronus incorporates two key components. 
The Approximate RTT Collector leverages lightweight timeouts to generate available RTT samples while recycling outdated records to conserve memory. 
The RTT-Sketch, tailored for highly skewed RTT distributions, employs a multi-level bucket array and a probabilistic replacement strategy that preferentially evicts low-RTT flows, thereby retaining more high-RTT flows.
We further prove that Chronus provides unbiased RTT estimation and derive tight bounds on relative error and misreport probability. 
Finally, we implement Chronus on both CPU and P4 switch platforms.

### About this repo

The core **Chronus** structure is implemented in **./C++**.

Other baseline methods are also implemented in **./C++**.

We also provide a P4-16 implementation of Chronus for deployment on both software and hardware programmable network switches (i.e., Tofino switch) in and **./P4/**.

### Requirements

- g++ (gcc-version >= 13.1.0)

### How to build

We preprocessed the datasets to remove all IPv6 packets to ensure that each packet contains a source IP address, a destination IP address, a source port, a destination port, a sequence number, an ack number, and a timestamp.

You can use the following commands to build and run.

```
cd ./C++
cmake .
cmake --build . --config Release
```
