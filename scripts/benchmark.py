#!/usr/bin/env python3

import logging
import os
import argparse
import asyncio

from lib import tor
from dataclasses import dataclass

MODE_OPEN = "open"
MODE_RESTRICTED = "fully-restricted"
MODE_SENDER_RESTRICTED = "sender-restricted"
MODE_RECEIVER_RESTRICTED = "receiver-restricted"
MODES = [MODE_OPEN,MODE_SENDER_RESTRICTED, MODE_RECEIVER_RESTRICTED, MODE_RESTRICTED]

ANONYCAST_BINARY = "./bin/anonycast"


@dataclass(kw_only=True, frozen=True)
class PublishConfig:
    clients: int
    message_size: int

    def id(self) -> str:
        return f"c{self.clients}_ms{self.message_size}"


@dataclass(kw_only=True, frozen=True)
class RetreiveConfig:
    clients: int
    message_count: int
    message_size: int

    def id(self) -> str:
        return f"c{self.clients}_m{self.message_count}_s{self.message_size}"


@dataclass(kw_only=True, frozen=True)
class LatencyConfig:
    mode: str
    deaddrops: int
    allowed_receivers: int
    allowed_senders: int
    difficulty: int

    def id(self) -> str:
        return f"{self.mode}_dd{self.deaddrops}_ar{self.allowed_receivers}_as{self.allowed_senders}_d{self.difficulty}"


def generate_publish_configs() -> list[PublishConfig]:
    clients = [
        1,
        5,
        10,
        11,
        12,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        30,
        40,
        50,
        60,
        70,
        80,
        90,
        100,
        120,
        140,
        160,
        180,
        200,
        250,
        300,
        350,
        400,
        450,
        500,
        550,
        600,
    ]
    message_sizes = [128, 1024, 128 * 1024, 512 * 1024, 1024 * 1024]

    configs = []
    for message_size in message_sizes:
        for nclients in clients:
            configs.append(
                PublishConfig(
                    clients=nclients,
                    message_size=message_size,
                )
            )
    return configs


def generate_retreive_configs() -> list[RetreiveConfig]:
    clients = [
        1,
        10,
        20,
        30,
        40,
        50,
        60,
        70,
        80,
        90,
        100,
        120,
        140,
        160,
        180,
        200,
        400,
        600,
        800,
    ]
    message_counts = [1, 10, 100, 1000]
    message_sizes = [128, 1024, 128 * 1024, 512 * 1024, 1024 * 1024]

    configs = []
    for size in message_sizes:
        for n_messages in message_counts:
            for n_clients in clients:
                configs.append(
                    RetreiveConfig(
                        clients=n_clients, message_count=n_messages, message_size=size
                    )
                )
    return configs


def generate_latency_configs() -> list[LatencyConfig]:
    deaddrops = [3, 5, 7,9]
    allowed_receivers = [1, 2, 4, 8, 16, 32, 64, 128]
    allowed_senders = [2, 4, 8, 16, 32, 64]
    allowed_difficulty = [12, 16, 20]

    configs = []
    for mode in MODES:
        for deaddrop in deaddrops:
            mode_ar = (
                [0]
                if mode not in [MODE_RECEIVER_RESTRICTED, MODE_RESTRICTED]
                else allowed_receivers
            )
            for allowed_r in mode_ar:
                mode_as = (
                    [0]
                    if mode not in [MODE_SENDER_RESTRICTED, MODE_RESTRICTED]
                    else allowed_senders
                )
                for allowed_s in mode_as:
                    for difficulty in allowed_difficulty:
                        configs.append(
                            LatencyConfig(
                                mode=mode,
                                deaddrops=deaddrop,
                                allowed_senders=allowed_s,
                                allowed_receivers=allowed_r,
                                difficulty=difficulty,
                            )
                        )
    return configs


def cluster_machines() -> list[str]:
    """
    Return the list machine hostnames in the current job
    """
    with open(os.environ["OAR_NODEFILE"], "r") as f:
        return list(set([l.strip() for l in f.readlines()]))


def cluster_hostname() -> str:
    with open("/etc/hostname", "r") as f:
        return f.read().strip()


def cluster_remote_machine() -> str:
    """
    Assuming only 2 machines in the job, return the hostname of the machine that is not the one this script is currently running on
    """
    machines = cluster_machines()
    hostname = cluster_hostname()
    assert len(machines) == 2, "expected 2 machines in the job"
    assert (
        hostname in machines
    ), f"expected current machine to be part of the job: {machines}"
    return [x for x in machines if x != hostname][0]


def benchmark_filepath(bench: str, id: str) -> str:
    return os.path.abspath(f"benchmark/{bench}/{id}.json")


async def benchmark_publish_troughput(args):
    for config in generate_publish_configs():
        filepath = benchmark_filepath("publish", config.id())
        if os.path.exists(filepath):
            print(f"skipping: {config}")
            continue
        else:
            print(f"running: {config}")

        acceptance_window = str(2**32)

        dd_args = []
        dd_args += ["deaddrop"]
        dd_args += ["--mode", "open"]
        dd_args += ["--difficulty", "8"]
        dd_args += ["--acceptance-window", acceptance_window]

        bench_args = []
        bench_args += ["benchmark", "publish-troughput"]
        bench_args += ["--clients", str(config.clients)]
        bench_args += ["--runtime", "15"]
        bench_args += ["--difficulty", "8"]
        bench_args += ["--message-size", str(config.message_size)]
        bench_args += ["--prepared-messages", str(30 * 5000)]
        bench_args += ["--acceptance-window", acceptance_window]
        bench_args += ["--output", filepath]

        if args.cluster:
            local = cluster_hostname()
            remote = cluster_remote_machine()

            dd_args += ["--address", f"0.0.0.0:5000"]
            bench_args += ["--deaddrop-address", f"{remote}:5000"]

            await (
                await asyncio.create_subprocess_shell(
                    f"oarsh {local} killall anonycast"
                )
            ).wait()
            await (
                await asyncio.create_subprocess_shell(
                    f"oarsh {remote} killall anonycast"
                )
            ).wait()

            binary = os.path.abspath("./bin/anonycast")

            await asyncio.create_subprocess_shell(
                f"oarsh {remote} {binary} {' '.join(dd_args)}"
            )
            await asyncio.sleep(2)
            bench_proc = await asyncio.create_subprocess_shell(
                f"{binary} {' '.join(bench_args)}",
                stderr=asyncio.subprocess.STDOUT,
            )

            status = await bench_proc.wait()
            if status != 0:
                raise Exception("failed to run benchmark")

            await asyncio.create_subprocess_shell(f"oarsh {local} killall anonycast")
            await asyncio.create_subprocess_shell(f"oarsh {remote} killall anonycast")
        else:
            dd_args += ["--address", "127.0.0.1:5000"]
            bench_args += ["--deaddrop-address", "127.0.0.1:5000"]

            dd_proc = await asyncio.create_subprocess_exec(
                ANONYCAST_BINARY, *dd_args, stderr=asyncio.subprocess.STDOUT
            )
            await asyncio.sleep(1)
            bench_proc = await asyncio.create_subprocess_exec(
                ANONYCAST_BINARY, *bench_args, stderr=asyncio.subprocess.STDOUT
            )
            status = await bench_proc.wait()
            dd_proc.terminate()
            if status != 0:
                raise Exception("failed to run benchmark")


async def benchmark_retreive_troughput(args):
    for config in generate_retreive_configs():
        filepath = benchmark_filepath("retreive", config.id())
        if os.path.exists(filepath):
            print(f"skipping: {config}")
            continue
        else:
            print(f"running: {config}")

        dd_args = []
        dd_args += ["deaddrop"]
        dd_args += ["--mode", "open"]
        dd_args += ["--difficulty", "8"]
        dd_args += ["--acceptance-window", "100"]

        bench_args = []
        bench_args += ["benchmark", "retreive-troughput"]
        bench_args += ["--clients", str(config.clients)]
        bench_args += ["--runtime", "15"]
        bench_args += ["--difficulty", "8"]
        bench_args += ["--message-size", str(config.message_size)]
        bench_args += ["--message-count", str(config.message_count)]
        bench_args += ["--acceptance-window", "100"]
        bench_args += ["--output", filepath]

        if args.cluster:
            local = cluster_hostname()
            remote = cluster_remote_machine()

            dd_args += ["--address", f"0.0.0.0:5000"]
            bench_args += ["--deaddrop-address", f"{local}:5000"]

            await (
                await asyncio.create_subprocess_shell(
                    f"oarsh {local} killall anonycast"
                )
            ).wait()
            await (
                await asyncio.create_subprocess_shell(
                    f"oarsh {remote} killall anonycast"
                )
            ).wait()

            binary = os.path.abspath("./bin/anonycast")

            await asyncio.create_subprocess_shell(
                f"{binary} {' '.join(dd_args)}",
                stderr=asyncio.subprocess.STDOUT,
            )
            await asyncio.sleep(2)
            bench_proc = await asyncio.create_subprocess_shell(
                f"oarsh {remote} {binary} {' '.join(bench_args)}"
            )

            status = await bench_proc.wait()
            if status != 0:
                raise Exception("failed to run benchmark")

            await asyncio.create_subprocess_shell(f"oarsh {local} killall anonycast")
            await asyncio.create_subprocess_shell(f"oarsh {remote} killall anonycast")
        else:
            dd_args += ["--address", "127.0.0.1:5000"]
            bench_args += ["--deaddrop-address", "127.0.0.1:5000"]

            dd_proc = await asyncio.create_subprocess_exec(
                ANONYCAST_BINARY, *dd_args, stderr=asyncio.subprocess.STDOUT
            )
            await asyncio.sleep(1)
            bench_proc = await asyncio.create_subprocess_exec(
                ANONYCAST_BINARY, *bench_args, stderr=asyncio.subprocess.STDOUT
            )
            status = await bench_proc.wait()
            dd_proc.terminate()
            if status != 0:
                raise Exception("failed to run benchmark")


async def benchmark_latency(args):
    for config in generate_latency_configs():
        if args.mode is not None and config.mode != args.mode:  # type: ignore
            continue

        for i in range(5):
            filepath = benchmark_filepath(f"latency{i}", config.id())
            if os.path.exists(filepath):
                print(f"skipping: {config}")
                continue
            else:
                print(f"running: {config}")

            await (await asyncio.create_subprocess_shell("killall tor")).wait()
            await asyncio.sleep(2)

            keep = True
            while keep:
                socks_port = 9000
                tor_instance_co = []
                for i in range(config.deaddrops):
                    tor_instance_co.append(
                        tor.spawn(socks_port=socks_port, service_ports={80: 5000 + i})
                    )
                    socks_port += 1
                tor_instance_co.append(tor.spawn(socks_port=socks_port))

                try:
                    tor_instances: list[tor.TorInstance] = await asyncio.wait_for(asyncio.gather(*tor_instance_co), timeout=20)
                    keep = False 
                except asyncio.TimeoutError:
                    print("Refreshing Tor instances")
                    await (await asyncio.create_subprocess_shell("killall tor")).wait()
                    await asyncio.sleep(2)

            try:
                deaddrops_tor = tor_instances[: len(tor_instances) - 1]
                client_tor = tor_instances[-1]

                binary = os.path.abspath("./bin/anonycast")
                args = ["benchmark", "latency"]
                args += ["--deaddrops", str(config.deaddrops)]
                for t in deaddrops_tor:
                    addr = f"127.0.0.1:{t.services[80].local_port}"
                    args += ["--deaddrop-listen-address", addr]
                    args += ["--deaddrop-onion-address", t.services[80].address]
                args += ["--client-tor-proxy", f"127.0.0.1:{client_tor.socks_port}"]
                args += ["--allowed-receivers", str(config.allowed_receivers)]
                args += ["--allowed-senders", str(config.allowed_senders)]
                args += ["--difficulty", str(config.difficulty)]
                args += ["--mode", config.mode]
                args += ["--acceptance-window", "100"]
                args += ["--output", filepath]

                print(" ".join(args))
                proc = await asyncio.create_subprocess_shell(f"{binary} {' '.join(args)}")

                try:
                    await asyncio.wait_for(proc.wait(), timeout=500)
                except asyncio.TimeoutError:
                    raise Exception("Benchmark execution exceeded 15 minutes and will restart")
                
                if await proc.wait() != 0:
                    raise Exception("failed to run latency benchmark")
            finally:
                for instance in tor_instances:
                    instance.close()


async def main():
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", action="store_true", default=False)
    subparsers = parser.add_subparsers(title="subcommand", required=True)

    publish_troughput_parser = subparsers.add_parser("publish-troughput")
    publish_troughput_parser.set_defaults(entry=benchmark_publish_troughput)

    retreive_troughput_parser = subparsers.add_parser("retreive-troughput")
    retreive_troughput_parser.set_defaults(entry=benchmark_retreive_troughput)

    latency_parser = subparsers.add_parser("latency")
    latency_parser.add_argument("--mode", type=str)
    latency_parser.set_defaults(entry=benchmark_latency)

    while True:
        try:
            args = parser.parse_args()
            await args.entry(args)
            break
        except Exception as e:
            print(e)


if __name__ == "__main__":
    asyncio.run(main())

