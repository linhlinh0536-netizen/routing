####################################################
# DVrouter.py
# Name:
# HUID:
#####################################################

import json

from packet import Packet
from router import Router

# "Infinity" for the count-to-infinity problem (16 is enough for these networks)
INFINITY = 16


class DVrouter(Router):
    """Distance vector routing protocol implementation.

    Add your own class fields and initialization code (e.g. to create forwarding table
    data structures). See the `Router` base class for docstrings of the methods to
    override.
    """

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)  # Initialize base class - DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        # port -> (neighbor address, link cost) for every link of this router
        self.neighbors = {}
        # port -> last distance vector received from the neighbor on that port
        self.neighbor_vectors = {}
        # Distance vector of this router: destination -> cost
        self.distance_vector = {self.addr: 0}
        # Forwarding table: destination -> output port
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            # Normal data packet: forward it based on the forwarding table.
            # If the destination is unknown, the packet is dropped.
            if packet.dst_addr in self.forwarding_table:
                self.send(self.forwarding_table[packet.dst_addr], packet)
        else:
            # Routing packet: the content is the neighbor's distance vector.
            if port not in self.neighbors:
                return
            received_vector = json.loads(packet.content)
            if received_vector != self.neighbor_vectors.get(port):
                self.neighbor_vectors[port] = received_vector
                if self.update_distance_vector():
                    self.broadcast_distance_vector()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.neighbors[port] = (endpoint, cost)
        self.update_distance_vector()
        # Always broadcast so the new neighbor gets our distance vector right away
        self.broadcast_distance_vector()

    def handle_remove_link(self, port):
        """Handle removed link."""
        self.neighbors.pop(port, None)
        self.neighbor_vectors.pop(port, None)
        if self.update_distance_vector():
            self.broadcast_distance_vector()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # Periodic broadcast even if nothing has changed
            self.broadcast_distance_vector()

    def update_distance_vector(self):
        """Recompute the distance vector and forwarding table (Bellman-Ford).

        D(x, y) = min over neighbors v of { c(x, v) + D(v, y) }
        Returns True if the distance vector changed.
        """
        new_vector = {self.addr: 0}
        new_table = {}

        for port, (neighbor, cost) in self.neighbors.items():
            # Path through the direct link to the neighbor itself
            if cost < new_vector.get(neighbor, INFINITY):
                new_vector[neighbor] = cost
                new_table[neighbor] = port

            # Paths through the neighbor, using its last distance vector
            for dest, dist in self.neighbor_vectors.get(port, {}).items():
                if dest == self.addr:
                    continue
                total = cost + dist
                if total < new_vector.get(dest, INFINITY):
                    new_vector[dest] = total
                    new_table[dest] = port

        # Destinations with cost >= INFINITY are left out (= unreachable)
        changed = new_vector != self.distance_vector
        self.distance_vector = new_vector
        self.forwarding_table = new_table
        return changed

    def broadcast_distance_vector(self):
        """Send this router's own distance vector to every neighbor.

        Poisoned reverse: if the route to a destination goes through a neighbor,
        tell that neighbor the cost is INFINITY, so it never routes back through us
        (this avoids the two-node count-to-infinity loop).
        """
        for port, (neighbor, _) in self.neighbors.items():
            vector = {}
            for dest, dist in self.distance_vector.items():
                if self.forwarding_table.get(dest) == port and dest != neighbor:
                    vector[dest] = INFINITY
                else:
                    vector[dest] = dist
            packet = Packet(Packet.ROUTING, self.addr, neighbor, json.dumps(vector))
            self.send(port, packet)

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        table = ", ".join(
            f"{dest}: cost {self.distance_vector[dest]} via port {port}"
            for dest, port in sorted(self.forwarding_table.items())
        )
        return f"DVrouter(addr={self.addr}, table={{{table}}})"
