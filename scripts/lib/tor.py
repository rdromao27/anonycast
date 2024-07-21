import os
import shutil
import tempfile
import asyncio
import logging

from dataclasses import dataclass


@dataclass(frozen=True)
class TorService:
    # the onion address for this service
    address: str
    # the port that should be used with the tor address
    tor_port: int
    # the port that will receive traffic on the localhost
    local_port: int


@dataclass(kw_only=True)
class TorInstance:
    directory: str
    socks_port: int
    process: asyncio.subprocess.Process
    services: dict[int, TorService]

    def close(self):
        self.process.kill()
        shutil.rmtree(self.directory)

    def __enter__(self):
        pass

    def __exit__(self, *_):
        self.close()


async def spawn(socks_port: int = 9050, service_ports: dict[int, int] = {}):
    directory = tempfile.mkdtemp()
    torrc = _gen_torrc(directory, socks_port, service_ports)
    logging.debug("torrc:\n" + torrc)
    torrc_path = os.path.join(directory, "torrc")
    with open(torrc_path, "w") as f:
        f.write(torrc)

    proc = await asyncio.create_subprocess_exec(
        "tor",
        "-f",
        torrc_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    assert proc.stdout is not None

    try:
        logging.info("waiting for tor to start")
        while True:
            line = await proc.stdout.readline()
            logging.debug(line)
            if len(line) == 0 or proc.returncode is not None:
                raise Exception(f"failed to start tor: {proc.returncode}")
            if "100%" in line.decode("utf-8"):
                break
        services = []
        for dir in os.listdir(directory):
            path = os.path.join(directory, dir)
            if not os.path.isdir(path):
                continue
            if "service_" not in dir:
                continue
            ports = dir.removeprefix("service_").split("_")
            tor_port = int(ports[0])
            local_port = int(ports[1])
            with open(os.path.join(path, "hostname"), "r") as f:
                addr = f.read().strip()
                services.append(
                    TorService(address=addr, tor_port=tor_port, local_port=local_port)
                )
        return TorInstance(
            directory=directory,
            socks_port=socks_port,
            process=proc,
            services={s.tor_port: s for s in services},
        )
    except Exception as e:
        proc.kill()
        raise e


def _gen_torrc(directory: str, socks_port: int, service_ports: dict[int, int]) -> str:
    torrc = ""
    torrc += f"SocksPort {socks_port}\n"
    torrc += f"DataDirectory {directory}\n"
    for tor_port, local_port in service_ports.items():
        torrc += f"HiddenServiceDir {directory}/service_{tor_port}_{local_port}\n"
        torrc += f"HiddenServicePort {tor_port} 127.0.0.1:{local_port}\n"
        torrc += "\n"
    return torrc

