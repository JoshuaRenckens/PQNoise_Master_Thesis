#!/bin/bash
set -x

##########################
# Setup network namespaces
##########################

#Taken from https://github.com/xvzcf/pq-tls-benchmark, with some minor changes, currently only additional comments

# Some constants
SERVER_VETH_LL_ADDR=00:00:00:00:00:02
SERVER_NS=srv_ns
SERVER_VETH=srv_ve

CLIENT_NS=cli_ns
CLIENT_VETH_LL_ADDR=00:00:00:00:00:01
CLIENT_VETH=cli_ve

# Create the two network namespaces
ip netns add ${SERVER_NS}
ip netns add ${CLIENT_NS}

# Creates the server and client virtual ethernet interfaces(veth) as a pair.
ip link add \
   name ${SERVER_VETH} \
   address ${SERVER_VETH_LL_ADDR} \
   netns ${SERVER_NS} type veth \
   peer name ${CLIENT_VETH} \
   address ${CLIENT_VETH_LL_ADDR} \
   netns ${CLIENT_NS}

# Enables the server veth
ip netns exec ${SERVER_NS} \
   ip link set dev ${SERVER_VETH} up
# Creates a loopback interface in the server namespace
ip netns exec ${SERVER_NS} \
   ip link set dev lo up
# Assigns the following IP address to the veth of the server
ip netns exec ${SERVER_NS} \
   ip addr add 10.0.0.1/24 dev ${SERVER_VETH}

# Assigns the following IP address to the veth of the client
ip netns exec ${CLIENT_NS} \
   ip addr add 10.0.0.2/24 dev ${CLIENT_VETH}
# Creates a loopback interface in the client namespace
ip netns exec ${CLIENT_NS} \
   ip link set dev lo up
# Enables the client veth
ip netns exec ${CLIENT_NS} \
   ip link set dev ${CLIENT_VETH} up
# Creates a loopback interface in the client namespace, why twice?
ip netns exec ${CLIENT_NS} \
   ip link set dev lo up

# Currently unsure what this does. Maybe it sets up the namespaces as neighbours?
ip netns exec ${SERVER_NS} \
   ip neigh add 10.0.0.2 \
      lladdr ${CLIENT_VETH_LL_ADDR} \
      dev ${SERVER_VETH}
ip netns exec ${CLIENT_NS} \
   ip neigh add 10.0.0.1 \
      lladdr ${SERVER_VETH_LL_ADDR} \
      dev ${CLIENT_VETH}

# Turn off optimizations that dent realism, those being GSO(Generis Segmentation Offload), GRO(Generic Receive Offload), TSO(TCP Segmentation Offload)
ip netns exec ${CLIENT_NS} \
   ethtool -K ${CLIENT_VETH} gso off gro off tso off
ip netns exec ${SERVER_NS} \
   ethtool -K ${SERVER_VETH} gso off gro off tso off

# Setup traffic connections for both veths with network emulation, this allows to add delay, packet loss, duplication and more other characteristics to outgoing packets.
ip netns exec ${CLIENT_NS} \
   tc qdisc add \
      dev ${CLIENT_VETH} \
      root netem
ip netns exec ${SERVER_NS} \
   tc qdisc add \
      dev ${SERVER_VETH} \
      root netem
      
# Set the delay and packet loss rate for both namespaces, this part will probably be automated in a python file later as we will probably want to test multiple values for both.
ip netns exec ${CLIENT_NS} \
   tc qdisc change \
      dev ${CLIENT_VETH} \
      root netem \
           limit 1000 \
           loss 0% \
           delay 2.684ms \
           rate 1000mbit

ip netns exec ${SERVER_NS} \
   tc qdisc change \
      dev ${SERVER_VETH} \
      root netem \
           limit 1000 \
           loss 0% \
           delay 2.684ms \
           rate 1000mbit
      
      
# Remove the network spaces after we are done
#ip netns del ${CLIENT_NS}
#ip netns del ${SERVER_NS}
