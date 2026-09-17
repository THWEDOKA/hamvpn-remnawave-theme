"""Same bounded authenticated UDP diagnostic, isolated port-443 experiment.

No tunnel, firewall mutation, SO_REUSEPORT or takeover of an occupied socket.
"""
import importlib.util
from pathlib import Path
import sys


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


p = load('cloud140_udp443_protocol', 'udp_probe.py')
p.PORTS = (443,)


if __name__ == '__main__':
    sys.exit(p.main())
