####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################

import heapq
import json

from packet import Packet
from router import Router


class LSrouter(Router):
    """Link state routing protocol implementation.

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
        # Sequence number of this router's own link state
        self.seq_num = 0
        # Link state database: router address -> (seq_num, {neighbor: cost})
        self.link_state_db = {self.addr: (self.seq_num, {})}
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
            # Routing packet: a link state (LSP) created by some router `origin`
            lsp = json.loads(packet.content)
            origin, seq_num, links = lsp["origin"], lsp["seq"], lsp["links"]

            if origin == self.addr:
                return  # our own link state came back: we already have it
            stored = self.link_state_db.get(origin)
            if stored is not None and seq_num <= stored[0]:
                return  # old or duplicate link state: disregard it

            # Newer link state: store it, recompute routes if the links changed,
            # then flood it to all other neighbors
            self.link_state_db[origin] = (seq_num, links)
            if stored is None or links != stored[1]:
                self.update_forwarding_table()
            for out_port in self.neighbors:
                if out_port != port:
                    self.send(out_port, packet)

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self.neighbors[port] = (endpoint, cost)
        self.update_own_link_state()
        # Database synchronization: give the new neighbor every link state we
        # know (with its original origin and sequence number). Without this, a
        # router that joins after a link state was flooded (or after a network
        # partition heals) would never learn routers whose links never change.
        for origin, (seq_num, links) in self.link_state_db.items():
            if origin != self.addr:
                self.send_link_state(port, endpoint, origin, seq_num, links)

    def handle_remove_link(self, port):
        """Handle removed link."""
        self.neighbors.pop(port, None)
        self.update_own_link_state()

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            # Periodic broadcast of our own link state (same sequence number).
            # Routers that already have it drop it, routers with an older copy
            # (e.g. after a network partition heals) accept and flood it.
            self.broadcast_own_link_state()

    def update_own_link_state(self):
        """Our links changed: new link state with a higher sequence number."""
        self.seq_num += 1
        links = {neighbor: cost for neighbor, cost in self.neighbors.values()}
        self.link_state_db[self.addr] = (self.seq_num, links)
        self.update_forwarding_table()
        self.broadcast_own_link_state()

    def broadcast_own_link_state(self):
        """Send this router's own link state to all neighbors."""
        seq_num, links = self.link_state_db[self.addr]
        for port, (neighbor, _) in self.neighbors.items():
            self.send_link_state(port, neighbor, self.addr, seq_num, links)

    def send_link_state(self, port, neighbor, origin, seq_num, links):
        """Send the link state of router `origin` out of `port`."""
        content = json.dumps({"origin": origin, "seq": seq_num, "links": links})
        self.send(port, Packet(Packet.ROUTING, self.addr, neighbor, content))

    def update_forwarding_table(self):
        """Run Dijkstra on the link state database and rebuild the forwarding table."""
        dist = {self.addr: 0}
        first_hop = {}  # destination -> neighbor of this router on the shortest path
        visited = set()
        heap = [(0, self.addr)]

        while heap:
            d, node = heapq.heappop(heap)
            if node in visited:
                continue
            visited.add(node)
            # Clients (and unknown nodes) have no link state, so they are only
            # path endpoints, never used to forward traffic.
            if node not in self.link_state_db:
                continue
            for neighbor, cost in self.link_state_db[node][1].items():
                if not self.link_is_two_way(node, neighbor):
                    continue
                new_dist = d + cost
                if new_dist < dist.get(neighbor, float("inf")):
                    dist[neighbor] = new_dist
                    first_hop[neighbor] = neighbor if node == self.addr else first_hop[node]
                    heapq.heappush(heap, (new_dist, neighbor))

        # Map each destination's first hop to the port of that neighbor
        neighbor_port = {neighbor: port for port, (neighbor, _) in self.neighbors.items()}
        self.forwarding_table = {
            dest: neighbor_port[hop]
            for dest, hop in first_hop.items()
            if hop in neighbor_port
        }

    def link_is_two_way(self, u, v):
        """Only use a router-to-router link if both routers report it.

        Right after a link goes down, one router may still have the other's old
        link state; the two-way check stops us from using the dead link.
        """
        if v not in self.link_state_db:
            return True  # v is a client (or not known yet)
        return u in self.link_state_db[v][1]

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        table = ", ".join(
            f"{dest}: port {port}" for dest, port in sorted(self.forwarding_table.items())
        )
        return f"LSrouter(addr={self.addr}, seq={self.seq_num}, table={{{table}}})"
