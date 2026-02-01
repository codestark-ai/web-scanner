import os
import importlib
import inspect
from base.base_scanner import BaseScanner

def load_scanners():
    scanners = []

    scanner_path = os.path.join(os.path.dirname(__file__), "scanners")

    for file in os.listdir(scanner_path):
        if file.endswith(".py") and not file.startswith("__"):
            module = importlib.import_module(f"scanners.{file[:-3]}")

            for _, cls in inspect.getmembers(module, inspect.isclass):
                if issubclass(cls, BaseScanner) and cls is not BaseScanner:
                    scanners.append(cls())

    return scanners
