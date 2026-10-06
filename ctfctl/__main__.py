"""python -m ctfctl 也能跑（等同 ctfctl 命令）。"""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
