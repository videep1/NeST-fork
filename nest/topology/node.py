# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2019-2020 NITK Surathkal

"""API related to node creation in topology"""

from .address import Address
from .. import engine
from .id_generator import ID_GEN
from ..topology_map import TopologyMap


class Node:
    """
    Abstraction for a network namespace.
    
    Attributes
    ----------
    name: str
        User given name for the node.
    id: str
        This value is used by `engine` to create emulated node entity
    interface_list: list
        List of interfaces in this node
    """

    def __init__(self, name):
        """
        Create a node with given `name`.

        An unique `id` is assigned to this node which is used by
        `engine` module to create the network namespace.
        This ensures that there is no naming conflict between any two
        nodes.

        Parameters
        ----------
        name: str
            The name of the node to be created
        
        """
        if name == '':
            raise ValueError('Node name can\'t be an empty string')
        
        # TODO: id and interface_list should be private
        self.name = name
        self.id = ID_GEN.get_id(name)
        self.interface_list = []

        engine.create_ns(self.id)
        TopologyMap.add_namespace(self.id, self.name)

    def get_name(self):
        # TODO: Remove this function
        return self.name

    def get_id(self):
        # TODO: Remove this function
        return self.id

    def add_route(self, dest_addr, via_interface, next_hop_addr=''):
        """
        Add a route to the routing table of `Node`.

        Parameters
        ----------
        dest_addr: Address/str
            Destination ip address of node to route to. 'DEFAULT' is
            for all addresses 
        via_interface: Interface
            `Interface` in `Node` to route via
        next_hop_addr: Address/str, optional
            IP address of next hop Node (or router), by default ''
        
        """
        if type(dest_addr) == str:
            dest_addr = Address(dest_addr)

        if next_hop_addr != '':
            if type(next_hop_addr) == str:
                next_hop_addr = Address(next_hop_addr)
        else:
            # Assuming veth pair
            next_hop_addr = via_interface.get_pair().get_address()

        dest_addr_str = ''
        if dest_addr.is_subnet():
            dest_addr_str = dest_addr.get_addr()
        else:
            dest_addr_str = dest_addr.get_addr(with_subnet=False)

        engine.add_route(
            self.id, dest_addr_str, next_hop_addr.get_addr(with_subnet=False),
            via_interface.get_id())

    def _add_interface(self, interface):
        """
        Add `interface` to `Node`

        Parameters
        ----------
        interface: Interface
            `Interface` to be added to `Node`

        """
        self.interface_list.append(interface)
        interface._set_node(self)
        engine.add_int_to_ns(self.id, interface.get_id())
        TopologyMap.add_interface(
            self.id, interface.get_id(), interface.get_name())

    def configure_tcp_param(self, param, value):
        """
        Configure TCP parameters of `Node` available at 
        /proc/sys/net/ipv4/tcp_*.
        
        Eg. 'window_scaling', 'wmem', 'ecn', etc.

        Parameters
        ----------
        param: str
            TCP parameter to be configured
        value: str
            New value of TCP parameter `param`

        Returns
        -------
        str
            If TCP Parameter `param` is valid, then new `value` is set
            for this `param`.
        
        """
        engine.configure_kernel_param(self.id, 'net.ipv4.tcp_', param, value)

    def configure_udp_param(self, param, value):
        """
        Configure UDP parameters of `Node` available at 
        /proc/sys/net/ipv4/udp_*.
        
        Eg. 'early_demux', 'l3mdev_accept', 'rmem_min', 'wmem_min'

        Parameters
        ----------
        param: str
            TCP parameter to be configured
        value: str
            New value of TCP parameter `param`

        Returns
        -------
        str
            If TCP Parameter `param` is valid, then new `value` is set
            for this `param`.
        
        """
        engine.configure_kernel_param(self.id, 'net.ipv4.udp_', param, value)

    def read_tcp_param(self, param):
        """
        Read TCP parameters of `Node` available at 
        `/proc/sys/net/ipv4/tcp_*`.
        
        Eg. 'window_scaling', 'wmem', 'ecn', etc.

        Parameters
        ----------
        param: str
            TCP parameter to be read

        Returns
        -------
        str
            If TCP Parameter `param` is valid, then corresponding value
            is returned.

        read tcp_parameters available at /proc/sys/net/ipv4/tcp_*
        Eg. window_scaling, wmem, ecn, etc.
        
        """
        return engine.read_kernel_param(self.id, 'net.ipv4.tcp_', param)

    def read_udp_param(self, param):
        """
        Read UDP parameters of `Node`available at
        `/proc/sys/net/ipv4/udp_*`.

        Eg. 'early_demux', 'l3mdev_accept', 'rmem_min', 'wmem_min'

        Parameters
        ----------
        param: str
            UDP parameter to be read

        Returns
        -------
        str
            If UDP Parameter `param` is valid, then corresponding value
            is returned.
        
        """
        return engine.read_kernel_param(self.id, 'net.ipv4.udp_', param)

    def ping(self, destination_address, verbose=True):
        """
        Ping from current `Node` to destination address
        if there is a route.

        Parameters
        ----------
        destination_address: Address/str
            IP address to ping to
        verbose: bool
            If `True`, print extensive ping success/failure details
        
        Returns
        -------
        bool
            `True` if `Node` can succesfully ping `destination_address`.
            Else `False`.

        """
        if type(destination_address) == str:
            destination_address = Address(destination_address)

        status = engine.ping(
            self.id, destination_address.get_addr(with_subnet=False))
        if verbose:
            if status:
                print('SUCCESS: ', end='')
            else:
                print('FAILURE: ', end='')
            print(f'ping from {self.name} to' 
                ' {destination_address.get_addr(with_subnet=False)}')

        return status

    def enable_ip_forwarding(self):
        """
        Enable IP forwarding in `Node`.
        
        After this method runs, the `Node` can be used as a router.

        """
        engine.en_ip_forwarding(self.id)