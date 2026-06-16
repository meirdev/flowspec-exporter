# To parse the output of each router, we need to test many combinations of flow attributes.
# This script cover a wide range of scenarios.
# You need to test each scenario one by one, run some traffic and save the output.

neighbor=127.0.0.1

destination=8.8.8.8/32

source=1.1.1.1/32

# destination,protocol,action

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=17' discard

# destination,source,action

exabgpcli neighbor $neighbor announce flow route destination $destination source $source discard

# destination,destination-protocol,action

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '=80' discard

# destination,source-port,action

exabgpcli neighbor $neighbor announce flow route destination $destination source-port '=3000' discard

# destination,port,action

exabgpcli neighbor $neighbor announce flow route destination $destination port '=7000' discard

# destination,icmp-type,action

exabgpcli neighbor $neighbor announce flow route destination $destination icmp-type 'echo-request' discard

# destination,icmp-code,action

exabgpcli neighbor $neighbor announce flow route destination $destination icmp-code 'host-unreachable' discard

# destination,fragment=first-fragment,action

exabgpcli neighbor $neighbor announce flow route destination $destination fragment 'first-fragment' discard

# destination,fragment=last-fragment,action

exabgpcli neighbor $neighbor announce flow route destination $destination fragment 'last-fragment' discard

# destination,fragment=is-fragment,action

exabgpcli neighbor $neighbor announce flow route destination $destination fragment 'is-fragment' discard

# destination,fragment=dont-fragment,action

exabgpcli neighbor $neighbor announce flow route destination $destination fragment 'dont-fragment' discard

# destination,fragment=6,action

exabgpcli neighbor $neighbor announce flow route destination $destination fragment '6' discard

exabgpcli neighbor $neighbor announce flow route destination $destination fragment '=6' discard

# destination,packet-length,action

exabgpcli neighbor $neighbor announce flow route destination $destination packet-length '=1200' discard

# destination,tcp-flags,action

exabgpcli neighbor $neighbor announce flow route destination $destination tcp-flags 'syn' discard

# destination,dscp,action

exabgpcli neighbor $neighbor announce flow route destination $destination dscp '=400' discard

# gt

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '>500' discard

# lt

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '<200' discard

# gte

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '>=500' discard

# lte

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '<=200' discard

# ne

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '!=700' discard

# range

exabgpcli neighbor $neighbor announce flow route destination $destination destination-port '>=700&<=1000' discard

# tcp-flags

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' tcp-flags '=14' discard

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' tcp-flags '!syn' discard

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' tcp-flags 'syn' tcp-flags 'ack' discard

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' tcp-flags 'syn&ack' discard

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' tcp-flags '=syn' discard

# rate-limit

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' destination-port '=8080' rate-limit 100000

# accept

exabgpcli neighbor $neighbor announce flow route destination $destination protocol '=6' destination-port '=9000' accept
