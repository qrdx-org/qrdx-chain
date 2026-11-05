"""
Nodes on separate machines, emulated (docs/PERFORMANCE.md, "Across machines").

The local test network runs every node as a process on one machine: they share its cores and
talk over loopback, where a message arrives in microseconds. Here each node runs in a container
of its own:

* **its own CPUs**: ``--cpus`` caps each node (default 2), as a machine of that size would;
* **its own address** on a Docker network;
* **a link with latency**: every connection into a node crosses a relay that delays it both ways
  (integration_tests/delay_proxy.py; netem is not in every kernel, WSL2's among them). A node
  advertises its relay's address as its URL, so peers reach it only through the relay, over
  HTTP and the peer transport alike. With ``--delay-ms 25`` a round trip between two nodes is
  50 ms, about New York to Chicago and back.

It is an emulation, not a deployment: the containers share one machine's memory bandwidth and
disk, and the relays its cores. What it adds over the local network is what a deployment adds
to it: CPUs that are each node's own, and time on the wire.

Each container mounts the test tree at the path it has here, so every path in a node's
configuration is the same inside; it runs as this user, so what it writes stays this user's.
The image must have the node's Python dependencies, liboqs and the native module: the node image
(docker/Dockerfile) has. ``python -m integration_tests.load --hosts containers`` runs the load
ladder this way.
"""

import asyncio
import os
import subprocess
from typing import IO, Dict, List, Optional

from integration_tests.config import DATA_DIR, PROJECT_ROOT, NodeSpec

NETWORK = "qrdx-multihost"
SUBNET = "172.31.7.0/24"
PREFIX = "qrdx-mh-"
# The transport listens on the HTTP port plus this (qrdx/node/netd.py).
P2P_OFFSET = 10_000
# Variables of this process a node in a container takes (a harness knob such as the RPC limits).
PASSED = ("QRDX_", "LOG_", "PYTHONWARNINGS")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


class ContainerHosts:
    """A container per node, each behind a delaying link (see the module's note)."""

    def __init__(
        self,
        image: str,
        cpus: float = 2.0,
        delay_ms: float = 25.0,
        jitter_ms: float = 0.0,
        mbps: Optional[float] = None,
        extra_mounts: Optional[List[str]] = None,
    ):
        self.image = image
        self.cpus = cpus
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.mbps = mbps
        # Directories mounted at their own paths besides the tree (an editable py-evm).
        self.extra_mounts = list(extra_mounts or [])
        self._ready = False

    @staticmethod
    def node_ip(spec: NodeSpec) -> str:
        return f"172.31.7.{10 + spec.node_id}"

    @staticmethod
    def link_ip(spec: NodeSpec) -> str:
        return f"172.31.7.{100 + spec.node_id}"

    def _network(self) -> None:
        if self._ready:
            return
        for line in _docker("ps", "-aq", "--filter", f"name={PREFIX}", check=False).stdout.split():
            _docker("rm", "-f", line, check=False)
        if _docker("network", "inspect", NETWORK, check=False).returncode != 0:
            _docker("network", "create", "--subnet", SUBNET, NETWORK)
        self._ready = True

    def configure(self, spec: NodeSpec, env: Dict[str, str]) -> Dict[str, str]:
        """The node's environment, placed: it listens on its own address and is known by its
        link's."""
        from integration_tests.config import build_node_specs

        others = [s for s in build_node_specs() if s.node_id != spec.node_id]
        bootstrap = next(s for s in build_node_specs() if s.is_bootstrap)
        env = dict(env)
        env["QRDX_NODE_HOST"] = "0.0.0.0"
        env["QRDX_P2P_HOST"] = "0.0.0.0"
        env["QRDX_SELF_URL"] = f"http://{self.link_ip(spec)}:{spec.node_port}"
        env["QRDX_BOOTSTRAP_NODE"] = f"http://{self.link_ip(bootstrap)}:{bootstrap.node_port}"
        env["QRDX_BOOTSTRAP_NODES"] = ",".join(
            f"http://{self.link_ip(s)}:{s.node_port}" for s in others
        )
        env["HOME"] = str(DATA_DIR / f"node{spec.node_id}")
        return env

    def process(self, spec: NodeSpec, env: Dict[str, str], project_root: str) -> "ContainerNode":
        self._network()
        return ContainerNode(self, spec, env, project_root)


class ContainerNode:
    """A node in its container, with its link: what NodeProcess is for a local node."""

    def __init__(self, hosts: ContainerHosts, spec: NodeSpec, env: Dict[str, str], root: str):
        self.hosts = hosts
        self.spec = spec
        self.env = env
        self.project_root = root
        self.process: Optional[asyncio.subprocess.Process] = None
        self.log_file: Optional[str] = None
        self._log_fd: Optional[IO[str]] = None
        self.name = f"{PREFIX}node{spec.node_id}"
        self.link = f"{PREFIX}link{spec.node_id}"

    def _mounts(self) -> List[str]:
        out = ["-v", f"{self.project_root}:{self.project_root}"]
        for path in self.hosts.extra_mounts:
            out += ["-v", f"{path}:{path}:ro"]
        return out

    async def start(self) -> None:
        from integration_tests.orchestrator import _inherited_env

        h, spec = self.hosts, self.spec
        node_ip, link_ip = h.node_ip(spec), h.link_ip(spec)
        routes = [
            f"0.0.0.0:{port}={node_ip}:{port}"
            for port in (spec.node_port, spec.node_port + P2P_OFFSET)
        ]
        link = [
            "run", "-d", "--rm", "--name", self.link, "--network", NETWORK, "--ip", link_ip,
            "--cpus", "1", "--user", f"{os.getuid()}:{os.getgid()}", *self._mounts(),
            "-w", self.project_root, "-e", f"PYTHONPATH={self.project_root}",
            "--entrypoint", "python", h.image, "-m", "integration_tests.delay_proxy",
            "--delay-ms", str(h.delay_ms), "--jitter-ms", str(h.jitter_ms),
        ]
        if h.mbps:
            link += ["--mbps", str(h.mbps)]
        _docker(*link, *routes)

        env = {k: v for k, v in _inherited_env().items() if k.startswith(PASSED)}
        env.update(self.env)
        env["PYTHONPATH"] = ":".join([*h.extra_mounts, self.project_root])
        os.makedirs(env["HOME"], exist_ok=True)
        flags: List[str] = []
        for k, v in sorted(env.items()):
            flags += ["-e", f"{k}={v}"]
        os.makedirs(spec.log_dir, exist_ok=True)
        self.log_file = os.path.join(spec.log_dir, "node.log")
        self._log_fd = open(self.log_file, "w")
        self.process = await asyncio.create_subprocess_exec(
            "docker", "run", "--rm", "--name", self.name, "--network", NETWORK,
            "--ip", node_ip, "--cpus", str(h.cpus), "--user", f"{os.getuid()}:{os.getgid()}",
            *self._mounts(), "-w", self.project_root, *flags,
            "--entrypoint", "python", h.image, "-W", "ignore", "run_node.py",
            stdout=self._log_fd,
            stderr=asyncio.subprocess.STDOUT,
        )
        print(f"Started {spec.name} in {self.name} at {node_ip}, reached through {link_ip}")

    async def stop(self, timeout: float = 10.0) -> None:
        await asyncio.to_thread(_docker, "stop", "-t", str(int(timeout)), self.name, check=False)
        await asyncio.to_thread(_docker, "rm", "-f", self.link, check=False)
        if self.process is not None:
            try:
                await asyncio.wait_for(self.process.wait(), timeout)
            except asyncio.TimeoutError:
                self.process.kill()
        if self._log_fd and not self._log_fd.closed:
            self._log_fd.close()

    @property
    def is_running(self) -> bool:
        return self.process is not None and self.process.returncode is None

    @property
    def url(self) -> str:
        return f"http://{self.hosts.node_ip(self.spec)}:{self.spec.node_port}"


def default_mounts() -> List[str]:
    """An editable py-evm next to the tree, when there is one (the node imports ``eth``)."""
    for candidate in (PROJECT_ROOT / "py-evm", PROJECT_ROOT.parent / "py-evm"):
        if (candidate / "eth" / "__init__.py").exists():
            return [str(candidate)]
    return []
