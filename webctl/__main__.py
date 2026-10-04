"""python -m webctl 也能跑（等同 webctl 命令）。"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
