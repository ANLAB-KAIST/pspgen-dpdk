# pspgen-dpdk
The pspgen utility on top of DPDK

## Overview
It is a port of [pspgen in the psio examples](https://github.com/PacketShader/Packet-IO-Engine/tree/master/samples/packet_generator).  Our team uses pspgen as a packet generator and latency measurement tool in a daily basis, and now it works with DPDK as well.
All functionalities are in a self-contained pspgen.c file which demonstrates a minimal code to use DPDK.

## How to compile and run

Here is an example on a 8 core machine with three memory channels, which generates 64 bytes IPv4 packets randomly.
```
export RTE_TARGET=x86_64-native-linuxapp-gcc
export RTE_SDK=$HOME/dpdk/$RTE_TARGET
export PSPGEN_PMD=ixgbe
make
sudo ./pspgen -cff -n3 -- -i all -f 0 -v 4 -p 64
```
Differently from the psio version, it takes two disjoin sets of arguments: one set for DPDK EAL and the other set for pspgen itself, separated by `--`.
To see detailed arguments, just run `sudo ./pspgen`.
You may not need `sudo` depending on your system configuration (`/dev/uioX` and hugepage permissions).
Change the EAL arguments according to your hardware.

Another difference is that the device names are no longer `xge#` but `rte_ixgbe_pmd.#` (a string composed of DPDK driver name, dot, and the enumeration index) instead because DPDK-managed interfaces does not have host-bound interface names.

## Highlighted Features

 * Latency measurement: use `-l` to show average latency and `--latency-record-prefix` to get histograms (0 to 10 msec in microsecond accuracy)
 * Rate limiting: use `-g` to specify total offered throughput by the generator in Gbps (including ethernet overheads).  If the DPDK driver supports, it uses hardware rate limiter.  Otherwise, it falls back to software rate limiter.  (Note that activating latency measurement *always* falls back to software rate limiter to exclude delays inserted by the hardware, which is not accessible from the software.)

## Future Work (pull requests are welcome!)

 * Hardware timestamping for latency measurement (e.g., for Mellanox cards)
 * More generalized random packet generation. (Maybe scriptable?)
 * TCP flow generation
 * A daemon to run experiments faster
