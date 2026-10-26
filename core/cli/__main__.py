"""CLI package execution entry point: python -m core.cli"""
import sys
from core.cli.app import main

if __name__ == "__main__":
    sys.exit(main())
