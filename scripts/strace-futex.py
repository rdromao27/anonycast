# strace -p $(scripts/deaddrop-worker-tids.sh | head -n 1) -e trace=futex -T --stack-trace=source --stack-trace-frame-limit=24 -o trace.txt
# output when running retrieve benchmark with 200 clients
#
# anonycast::deaddrop::retreive_documents+0x5a
#         min = 0.016 ms
#         avg = 16.31932765957447 ms
#         max = 24.149 ms
# anonycast::deaddrop::retreive_document_ids+0x5c
#         min = 0.013 ms
#         avg = 16.695820105820108 ms
#         max = 25.285999999999998 ms
# anonycast::deaddrop::verify_signature+0x76
#         min = 0.016 ms
#         avg = 16.937067448680352 ms
#         max = 25.034 ms

import re

from dataclasses import dataclass


@dataclass(kw_only=True, frozen=True)
class RawFutexCall:
    line: str
    stacktrace: list[str]


@dataclass(kw_only=True, frozen=True)
class FutexCall:
    duration: float
    symbol: str


def parse_strace(output: str) -> list[RawFutexCall]:
    futex_calls = []
    current_line = None
    current_stacktrace = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(">"):
            # remove '> '
            current_stacktrace.append(line[2:].strip())
        else:
            if current_line is not None:
                futex_calls.append(
                    RawFutexCall(line=current_line, stacktrace=current_stacktrace)
                )
            current_line = line
            current_stacktrace = []
    return futex_calls


def parse_raw_futex_calls(calls: list[RawFutexCall]) -> list[FutexCall]:
    futex_calls = []
    for call in calls:
        if "_WAIT_" not in call.line:
            continue
        duration_match = re.match(r".*<(.*)>", call.line)
        if duration_match is None:
            print(call.line)
            raise Exception("invalid line")
        duration = float(duration_match[1])  # type: ignore
        symbol = None
        for s in call.stacktrace:
            s_symbol_match = re.match(r".*\((.*)\).*", s)
            if s_symbol_match is None:
                print(s)
                raise Exception("invalid symbol")
            s_symbol = s_symbol_match[1]  # type: ignore
            if "anonycast::" not in s_symbol:  # type: ignore
                continue
            symbol = s_symbol
            break
        if symbol is None:
            continue
        futex_calls.append(FutexCall(symbol=symbol, duration=duration))
    return futex_calls


content = open("trace.txt").read()
raw_futex_calls = parse_strace(content)
futex_calls = parse_raw_futex_calls(raw_futex_calls)
futex_by_symbol = {
    s: [f for f in futex_calls if f.symbol in s]
    for s in set([f.symbol for f in futex_calls])
}
symbol_info = []
for symbol, futexes in futex_by_symbol.items():
    min_d = min([f.duration for f in futexes])
    max_d = max([f.duration for f in futexes])
    avg_d = sum([f.duration for f in futexes]) / len(futexes)
    symbol_info.append({"symbol": symbol, "min": min_d, "max": max_d, "avg": avg_d})

symbol_info.sort(key=lambda i: i["avg"])
for info in symbol_info:
    print(info["symbol"])
    print(f"\tmin = {info['min'] * 1000} ms")
    print(f"\tavg = {info['avg'] * 1000} ms")
    print(f"\tmax = {info['max'] * 1000} ms")

