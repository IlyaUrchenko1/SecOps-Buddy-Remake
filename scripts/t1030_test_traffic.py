from __future__ import annotations

import argparse
import signal
import socket
import time
from dataclasses import dataclass
from threading import Event


STOP_EVENT = Event()


@dataclass(slots=True)
class ClientStats:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0


def _register_signal_handlers() -> None:
    def _handle_signal(_signum: int, _frame: object) -> None:
        STOP_EVENT.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except ValueError:
            continue


def _validate_port(value: int) -> int:
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be in range 1..65535")
    return value


def _validate_non_negative_int(value: int, field_name: str) -> int:
    if value < 0:
        raise argparse.ArgumentTypeError(f"{field_name} must be >= 0")
    return value


def _validate_positive_float(value: float, field_name: str) -> float:
    if value <= 0:
        raise argparse.ArgumentTypeError(f"{field_name} must be > 0")
    return value


def _build_payload(seq: int, payload_size: int) -> bytes:
    base = f"secopsbuddy-t1030-test-{seq}".encode("utf-8")
    if len(base) >= payload_size:
        return base[:payload_size]
    return base + (b"x" * (payload_size - len(base)))


def run_server(args: argparse.Namespace) -> int:
    host = args.host
    port = args.port
    read_bytes = args.read_bytes
    read_timeout_seconds = args.read_timeout_seconds
    max_connections = args.max_connections
    quiet = args.quiet

    accepted = 0

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
        server.settimeout(1.0)

        if not quiet:
            print(f"[server] listening on {host}:{port}")
            print("[server] press Ctrl+C to stop")

        while not STOP_EVENT.is_set():
            if max_connections and accepted >= max_connections:
                if not quiet:
                    print(f"[server] reached max_connections={max_connections}, stopping")
                break

            try:
                conn, addr = server.accept()
            except TimeoutError:
                continue
            except OSError as exc:
                if not quiet:
                    print(f"[server] accept failed: {exc}")
                return 1

            accepted += 1
            with conn:
                conn.settimeout(read_timeout_seconds)
                try:
                    _ = conn.recv(read_bytes)
                except TimeoutError:
                    pass
                except OSError:
                    pass

            if not quiet and accepted % 25 == 0:
                print(f"[server] accepted connections: {accepted} (last from {addr[0]}:{addr[1]})")

    if not quiet:
        print(f"[server] done, accepted={accepted}")
    return 0


def run_client(args: argparse.Namespace) -> int:
    target_host = args.target_host
    target_port = args.target_port
    connections = args.connections
    payload_size = args.payload_size
    hold_ms = args.hold_ms
    delay_ms = args.delay_ms
    timeout_seconds = args.timeout_seconds
    quiet = args.quiet

    stats = ClientStats()

    if not quiet:
        print(f"[client] target={target_host}:{target_port}")
        print(
            "[client] mode=T1030 synthetic pattern "
            f"connections={connections} payload_size={payload_size} hold_ms={hold_ms} delay_ms={delay_ms}"
        )

    started = time.time()

    for seq in range(connections):
        if STOP_EVENT.is_set():
            break

        stats.attempted += 1
        payload = _build_payload(seq=seq, payload_size=payload_size)

        try:
            with socket.create_connection((target_host, target_port), timeout=timeout_seconds) as conn:
                conn.settimeout(timeout_seconds)
                conn.sendall(payload)
                if hold_ms > 0:
                    time.sleep(hold_ms / 1000.0)
            stats.succeeded += 1
        except OSError as exc:
            stats.failed += 1
            if not quiet:
                print(f"[client] connection #{seq + 1} failed: {exc}")

        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    elapsed = time.time() - started

    print(
        "[client] done: "
        f"attempted={stats.attempted} succeeded={stats.succeeded} failed={stats.failed} elapsed={elapsed:.2f}s"
    )

    return 0 if stats.succeeded > 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="t1030_test_traffic",
        description=(
            "Generate safe synthetic traffic to validate SecOps Buddy T1030 detection. "
            "Use only in your own lab environment."
        ),
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)

    server = subparsers.add_parser("server", help="start local TCP sink for test traffic")
    server.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    server.add_argument("--port", type=lambda v: _validate_port(int(v)), default=9443)
    server.add_argument("--read-bytes", type=lambda v: _validate_non_negative_int(int(v), "read-bytes"), default=4096)
    server.add_argument(
        "--read-timeout-seconds",
        type=lambda v: _validate_positive_float(float(v), "read-timeout-seconds"),
        default=1.0,
    )
    server.add_argument(
        "--max-connections",
        type=lambda v: _validate_non_negative_int(int(v), "max-connections"),
        default=0,
        help="0 means unlimited",
    )
    server.add_argument("--quiet", action="store_true")
    server.set_defaults(handler=run_server)

    client = subparsers.add_parser("client", help="generate repeated short outbound TCP sessions")
    client.add_argument("--target-host", default="127.0.0.1")
    client.add_argument("--target-port", type=lambda v: _validate_port(int(v)), default=9443)
    client.add_argument("--connections", type=lambda v: _validate_non_negative_int(int(v), "connections"), default=120)
    client.add_argument("--payload-size", type=lambda v: _validate_non_negative_int(int(v), "payload-size"), default=128)
    client.add_argument("--hold-ms", type=lambda v: _validate_non_negative_int(int(v), "hold-ms"), default=150)
    client.add_argument("--delay-ms", type=lambda v: _validate_non_negative_int(int(v), "delay-ms"), default=30)
    client.add_argument(
        "--timeout-seconds",
        type=lambda v: _validate_positive_float(float(v), "timeout-seconds"),
        default=2.0,
    )
    client.add_argument("--quiet", action="store_true")
    client.set_defaults(handler=run_client)

    return parser


def main(argv: list[str] | None = None) -> int:
    _register_signal_handlers()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.mode == "client" and args.connections == 0:
        print("[client] connections=0, nothing to do")
        return 0

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
