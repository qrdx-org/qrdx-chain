"""Allow running as: python -m integration_tests"""
from integration_tests.run_scenarios import cli, main
import asyncio, sys

if __name__ == "__main__":
    args = cli()
    sys.exit(asyncio.run(main(args)))
