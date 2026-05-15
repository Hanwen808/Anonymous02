## Chronus

### Introduction

High-Cumulative-RTT flow detection (HCRD) is essential for fine-grained network management and security, as it identifies flows that consistently incur high round-trip times (RTTs), a key indicator of sustained attacks or persistent network congestion. Existing approaches either cannot provide lightweight detection or rely on assumptions that do not reflect practical RTT characteristics. In this paper, we present Chronus, a novel sketchbased framework that tackles these challenges by exploiting the highly skewed nature of RTT distributions at both packet and flow levels. Our key observation is that the vast majority of RTT samples and flows exhibit normal latency, whereas only a small fraction of flows accumulate persistently high RTTs. Guided by this insight, Chronus integrates abnormal RTT filtering, invalid record reclamation, and RTT-aware tracking, enabling reliable RTT sample construction, efficient memory reuse, and preferential retention of high-cumulative-RTT flows under extreme memory budgets (e.g., 64KB). We provide theoretical analysis and implement Chronus on CPU and P4. Experiments on real traffic traces show that Chronus improves F1-score by up to 0.778× and reduces measurement error by up to 96.636% over state-of-the-art solutions.

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
