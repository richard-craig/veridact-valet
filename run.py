#!/usr/bin/env python3
"""
Run the clickable demo locally: Marula Bank on :8000 and Kaya on :8001.

    python run.py
    open http://localhost:8001   (Kaya)   and   http://localhost:8000   (Marula Bank: thandi / demo)
"""
from __future__ import annotations

import multiprocessing
import os
import time

import uvicorn


def bank() -> None:
    uvicorn.run("valet.bank.main:get_app", factory=True, host="0.0.0.0", port=int(os.environ.get("BANK_PORT", 8000)),
                log_level="warning")


def kaya() -> None:
    time.sleep(0.5)
    uvicorn.run("valet.agent.kaya:get_app", factory=True, host="0.0.0.0", port=int(os.environ.get("KAYA_PORT", 8001)),
                log_level="warning")


if __name__ == "__main__":
    procs = [multiprocessing.Process(target=f) for f in (bank, kaya)]
    for p in procs:
        p.start()
    print("Marula Bank  http://localhost:8000   (sign in as thandi / demo)")
    print("Kaya agent   http://localhost:8001")
    print("Bank ops     http://localhost:8000/ops   (withdraw trust, check the receipt chain)")
    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        for p in procs:
            p.terminate()
