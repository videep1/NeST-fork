import os
import pwd
import time
import logging
import importlib
from os import mkdir, kill, path, listdir
import atexit
from shutil import rmtree, chown
from signal import SIGTERM
from typing import List
from nest.exception import RequiredDependencyNotFound
from nest.input_validator.input_validator import input_validator

from nest.topology.id_generator import IdGen
from nest.routing.static_routing import StaticRouting
from nest.routing.zebra import Zebra
from nest.routing.ldp import Ldp
from nest.topology_map import TopologyMap
from nest.user import User
from nest import config
from nest.topology import Node
from nest.routing.routing_helper import RoutingHelper
logger = logging.getLogger(__name__)

class Quagga(RoutingHelper):
    _module_map = {
        "ospf": ["nest.routing.ospf", "Ospf"],
        "rip": ["nest.routing.rip", "Rip"],
        "isis": ["nest.routing.isis", "Isis"],
        "static": ["nest.routing.static_routing", "StaticRouting"],
    }
    



    def _create_directory(self, dir_path):
        """
        Creates a quagga owned directory at `dir_path`

        Parmeters
        ---------
        dir_path: path of the directory to be created

        """
        if path.exists(dir_path):
            logger.warning("{dir_path} already exists")
        else:
            mkdir(dir_path)
            chown(dir_path, user=config.get_value("routing_suite"))

    def _create_conf_directory(self):
        """
        Creates a directory for holding routing related config
        and pid files.
        Override this to create directory at a location other than /tmp

        Returns
        -------
        str:
            path of the created directory
        """
        salt = config.get_value("routing_suite") + str(time.clock_gettime(0))
        dir_path = f"/tmp/{salt}-configs_{IdGen.topology_id}"
        self._create_directory(dir_path)
        return dir_path

    def _create_log_directory(self):
        """
        Creates a directory for holding routing log files.
        Returns
        -------
        str:
            path of the created directory
        """
        timestamp = time.strftime("%d-%m-%Y-%H:%M:%S")
        log_path = f"{config.get_value('routing_suite')}-logs_{timestamp}"
        self._create_directory(log_path)
        return log_path

    def _setup_default_routes(self):
        """
        Setup default routes in hosts
        """
        
        for host in self.hosts:
            host.add_route(
                "DEFAULT",
                host.interfaces[0],
                host.interfaces[0].pair.get_address(
                    not self.ipv6_routing, self.ipv6_routing, True
                )[0],
            )

    

    def _run_dyn_routing(self):
        """
        Run zebra and `self.protocol`
        """
        if self.ipv6_routing:
            logger.info("Running zebra and %s on routers (IPv6)", self.protocol)
        else:
            logger.info("Running zebra and %s on routers", self.protocol)
        self.conf_dir = self._create_conf_directory()
        if config.get_value("routing_logs"):
            self.log_dir = self._create_log_directory()

        for router in self.routers:
            self._run_zebra(router)
            self._run_routing_protocol(router)
            if router in self.ldp_routers:
                self._run_ldp(router)
        self._check_for_convergence()

    def _run_zebra(self, router):
        """
        Create required config file and run zebra
        """
        zebra = Zebra(
            router.id,
            self.ipv6_routing,
            router.interfaces,
            self.conf_dir,
            log_dir=self.log_dir,
        )
        zebra.create_basic_config()
        zebra.run()
        self.zebra_list.append(zebra)

    def _run_routing_protocol(self, router):
        """
        Create required config file and run `self.protocol`
        """
        
        protocol = self.protocol_class(
                router.id,
                self.ipv6_routing,
                router.interfaces,
                self.conf_dir,
                log_dir=self.log_dir,
            )
        protocol.create_basic_config()
        protocol.run()
        self.protocol_list.append(protocol)

    def _run_ldp(self, router):
        """
        Create required config file and run ldp
        """
        mpls_interfaces = []
        for interface in router.interfaces:
            if interface.is_mpls_enabled():
                mpls_interfaces.append(interface)
        if len(mpls_interfaces) == 0:
            raise Exception("MPLS isn't enabled in any interface!")
        ldp = Ldp(
            router.id,
            self.ipv6_routing,
            mpls_interfaces,
            self.conf_dir,
            log_dir=self.log_dir,
        )
        ldp.create_basic_config()
        ldp.run()
        self.ldp_list.append(ldp)

    def _check_for_convergence(self):
        """
        Wait for the routing protocol to converge.
        Override this for custom convergence check
        """
        logger.info("Waiting for %s to converge", self.protocol)
        interval = 2
        converged = False
        # Ping between hosts until convergence
        while not converged:
            time.sleep(interval)
            converged = True
            for i in range(len(self.hosts)):
                for j in range(i + 1, len(self.hosts)):
                    for k_addr in (
                        self.hosts[j]
                        .interfaces[0]
                        .get_address(not self.ipv6_routing, self.ipv6_routing, True)
                    ):
                        if not self.hosts[i].ping(k_addr.get_addr(), verbose=0):
                            converged = False
                            break
                    if not converged:
                        break
                if not converged:
                    break

        logger.info("Routing completed")

    

   