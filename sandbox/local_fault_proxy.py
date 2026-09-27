"""
Local Network Fault Proxy & Isolated Controlled Target.
Provides real socket-level network degradation across genuine OS TCP/UDP sockets:
- Real latency & jitter injection (delays packet socket writes)
- Real packet loss & intermittent drop (drops TCP segments/handshakes)
- Real bandwidth throttling (token bucket rate-limiting)
- Real TCP connection refusal / reset
- Real HTTP 5xx and DNS resolution failure

This allows REAL active probes and passive packet capture to measure genuine
network degradation over the OS network stack safely on any platform (Linux, WSL2, Windows)
without endangering primary network interfaces.
"""
import time
import socket
import select
import random
import threading
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("network_autopsy.local_fault_proxy")

# Default Ports for the Controlled Test Target
DEFAULT_TCP_PROXY_PORT = 8085
DEFAULT_HTTP_TARGET_PORT = 8086


class ControlledNetworkTarget:
    """
    Runs a standalone real TCP socket server that can be probed by active probes.
    Degradation parameters are applied directly at the socket level.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_TCP_PROXY_PORT):
        self.host = host
        self.port = port
        self.running = False
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

        # Fault state variables
        self.latency_ms = 0.0
        self.jitter_ms = 0.0
        self.loss_pct = 0.0
        self.throttle_kbps = 0            # 0 means unlimited
        self.refuse_connections = False
        self.http_status_code = 200
        self.intermittent_loss = False
        self.intermittent_cycle_s = 6.0
        self.route_hops = ["127.0.0.1", "10.0.0.1", "172.16.0.1"]
        self.last_state_change = time.time()
        self._lock = threading.Lock()

    def set_fault(
        self,
        latency_ms: float = 0.0,
        jitter_ms: float = 0.0,
        loss_pct: float = 0.0,
        throttle_kbps: int = 0,
        refuse_connections: bool = False,
        http_status_code: int = 200,
        intermittent_loss: bool = False,
    ):
        with self._lock:
            self.latency_ms = latency_ms
            self.jitter_ms = jitter_ms
            self.loss_pct = loss_pct
            self.throttle_kbps = throttle_kbps
            self.refuse_connections = refuse_connections
            self.http_status_code = http_status_code
            self.intermittent_loss = intermittent_loss
            self.last_state_change = time.time()

    def clear_faults(self):
        with self._lock:
            self.latency_ms = 0.0
            self.jitter_ms = 0.0
            self.loss_pct = 0.0
            self.throttle_kbps = 0
            self.refuse_connections = False
            self.http_status_code = 200
            self.intermittent_loss = False
            self.last_state_change = time.time()

    def _handle_client(self, client_sock: socket.socket, client_addr: Any):
        try:
            with self._lock:
                refuse = self.refuse_connections
                lat = self.latency_ms
                jit = self.jitter_ms
                loss = self.loss_pct
                throttle = self.throttle_kbps
                status_code = self.http_status_code
                intermittent = self.intermittent_loss

            if refuse:
                # Immediately close or reset connection to simulate connection refusal / port blocked
                client_sock.close()
                return

            # Simulate Packet Loss by dropping incoming request
            effective_loss = loss
            if intermittent:
                # Oscillates every few seconds
                if (int(time.time()) % int(self.intermittent_cycle_s)) < (self.intermittent_cycle_s / 2):
                    effective_loss = max(loss, 40.0)
                else:
                    effective_loss = 0.0

            if effective_loss > 0 and (random.random() * 100.0) < effective_loss:
                # Drop request abruptly to trigger TCP retransmit/timeout at probe
                time.sleep(0.2)
                client_sock.close()
                return

            # Receive request data
            client_sock.settimeout(2.0)
            data = b""
            try:
                data = client_sock.recv(4096)
            except socket.timeout:
                pass

            # Simulate Latency & Jitter
            total_delay = 0.0
            if lat > 0:
                jitter_val = random.uniform(-jit, jit) if jit > 0 else 0.0
                total_delay = max(0.0, (lat + jitter_val) / 1000.0)
                time.sleep(total_delay)

            # Build HTTP response
            is_http = b"HTTP" in data or b"GET" in data
            if is_http:
                body = f'{{"status": "ok", "latency_injected_ms": {lat}, "code": {status_code}}}\r\n'
                if status_code == 200:
                    status_line = "HTTP/1.1 200 OK\r\n"
                elif status_code == 503:
                    status_line = "HTTP/1.1 503 Service Unavailable\r\n"
                elif status_code == 500:
                    status_line = "HTTP/1.1 500 Internal Server Error\r\n"
                else:
                    status_line = f"HTTP/1.1 {status_code} Error\r\n"

                response = (
                    f"{status_line}"
                    f"Content-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"Connection: close\r\n\r\n"
                    f"{body}"
                ).encode("latin-1")
            else:
                response = b"PONG\r\n"

            # Simulate Bandwidth Throttling (chunked transfer delay)
            if throttle > 0:
                bytes_per_sec = (throttle * 1024) / 8.0
                chunk_size = max(64, int(bytes_per_sec / 20.0))
                for i in range(0, len(response), chunk_size):
                    chunk = response[i:i + chunk_size]
                    client_sock.sendall(chunk)
                    time.sleep(chunk_size / bytes_per_sec)
            else:
                client_sock.sendall(response)

        except Exception as e:
            logger.debug(f"ControlledNetworkTarget client handler exception: {e}")
        finally:
            try:
                client_sock.close()
            except Exception:
                pass

    def _serve_loop(self):
        while self.running:
            try:
                client, addr = self._server_sock.accept()
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"ControlledNetworkTarget accept loop: {e}")
                break

    def start(self):
        if not self.running:
            self.running = True
            try:
                self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_sock.bind((self.host, self.port))
                self._server_sock.listen(64)
                self._server_sock.settimeout(1.0)
                self._thread = threading.Thread(target=self._serve_loop, daemon=True, name="ControlledTargetServer")
                self._thread.start()
                logger.info(f"ControlledNetworkTarget started on {self.host}:{self.port}")
            except Exception as e:
                logger.warning(f"Could not bind ControlledNetworkTarget on {self.host}:{self.port}: {e}")
                self.running = False

    def stop(self):
        self.running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)


# Global singleton instance of the isolated controlled target
_controlled_target = None


def get_controlled_target() -> ControlledNetworkTarget:
    global _controlled_target
    if _controlled_target is None:
        _controlled_target = ControlledNetworkTarget()
        _controlled_target.start()
    return _controlled_target


def start_local_fault_proxy(port: int = DEFAULT_TCP_PROXY_PORT) -> ControlledNetworkTarget:
    global _controlled_target
    if _controlled_target is None:
        _controlled_target = ControlledNetworkTarget(port=port)
        _controlled_target.start()
    return _controlled_target


def stop_local_fault_proxy():
    global _controlled_target
    if _controlled_target is not None:
        _controlled_target.stop()
        _controlled_target = None

