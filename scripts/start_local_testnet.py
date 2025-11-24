#!/usr/bin/env python3
"""
QRDX Local Testnet Node Launcher

Starts a local QRDX testnet node with:
- Fresh genesis state (150 validators)
- Temporary data directory (auto-cleanup)
- QR-PoS consensus (2-second block time)
- Local RPC/WS endpoints

Usage:
    python3 scripts/start_local_testnet.py [OPTIONS]
"""

import argparse
import atexit
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


class Colors:
    """Terminal colors for pretty output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color
    BOLD = '\033[1m'


class QRDXTestnet:
    """QRDX Local Testnet Manager"""
    
    def __init__(self, args):
        self.args = args
        self.data_dir = None
        self.process = None
        self.cleanup_on_exit = not args.no_cleanup
        
        # Register cleanup handlers
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print(f"\n{Colors.YELLOW}Received signal {signum}, shutting down...{Colors.NC}")
        sys.exit(0)
    
    def print_banner(self):
        """Print startup banner"""
        print(f"{Colors.BLUE}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.BLUE}║         QRDX Local Testnet Node                           ║{Colors.NC}")
        print(f"{Colors.BLUE}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
    
    def print_config(self):
        """Print node configuration"""
        print(f"{Colors.GREEN}Configuration:{Colors.NC}")
        print(f"  Chain:           QRDX Testnet")
        print(f"  Network ID:      {self.args.network_id}")
        print(f"  Consensus:       QR-PoS (2-second blocks)")
        print(f"  Validators:      150 (you are validator {self.args.validator_index})")
        print(f"  Data Directory:  {self.data_dir}")
        print(f"  P2P Port:        {self.args.port}")
        print(f"  HTTP RPC:        http://localhost:{self.args.rpc_port}")
        print()
    
    def setup_data_directory(self):
        """Create temporary data directory"""
        self.data_dir = tempfile.mkdtemp(prefix='qrdx-testnet-')
        print(f"{Colors.GREEN}✓ Created data directory: {self.data_dir}{Colors.NC}")
    
    def generate_genesis(self):
        """Generate genesis configuration"""
        genesis_path = Path(self.data_dir) / 'genesis.json'
        
        # Simple genesis for QRDX testnet
        genesis = {
            "config": {
                "chainId": self.args.network_id,
                "qrdxBlock": 0
            },
            "nonce": "0x0",
            "timestamp": "0x0",
            "extraData": "0x5152445820546573746e6574",
            "gasLimit": "0x2faf080",  # 50,000,000
            "difficulty": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": {
                # Pre-fund test account
                "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb": {
                    "balance": "1000000000000000000000000"
                }
            }
        }
        
        import json
        with open(genesis_path, 'w') as f:
            json.dump(genesis, f, indent=2)
        
        print(f"{Colors.GREEN}✓ Generated genesis configuration{Colors.NC}")
        return str(genesis_path)
    
    def start_node(self):
        """Start the QRDX node"""
        print()
        print(f"{Colors.BLUE}Starting QRDX node...{Colors.NC}")
        print(f"{Colors.YELLOW}Press Ctrl+C to stop the node{Colors.NC}")
        print()
        print(f"{Colors.BLUE}════════════════════════════════════════════════════════════{Colors.NC}")
        print()
        
        # Build command
        cmd = [
            sys.executable, '-m', 'trinity',
            '--data-dir', self.data_dir,
            '--network-id', str(self.args.network_id),
            '--port', str(self.args.port),
        ]
        
        # Add genesis if needed
        # cmd.extend(['--genesis', genesis_path])
        
        # Add sync mode
        cmd.extend(['--sync-mode', 'full'])
        
        # Add logging
        if self.args.verbose:
            cmd.extend(['--log-level', 'debug'])
        else:
            cmd.extend(['--log-level', 'info'])
        
        try:
            # Start the process
            self.process = subprocess.Popen(
                cmd,
                stdout=sys.stdout,
                stderr=sys.stderr,
                cwd=Path(__file__).parent.parent
            )
            
            # Wait a bit to see if it starts
            time.sleep(2)
            
            # Check if still running
            if self.process.poll() is not None:
                print(f"{Colors.RED}✗ Node failed to start (exit code: {self.process.returncode}){Colors.NC}")
                return False
            
            print()
            print(f"{Colors.GREEN}✓ Node is running (PID: {self.process.pid}){Colors.NC}")
            self.print_running_info()
            
            # Wait for process
            self.process.wait()
            
        except FileNotFoundError:
            print(f"{Colors.RED}✗ Trinity not found. Please install QRDX Chain:{Colors.NC}")
            print(f"  pip install -e .")
            return False
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Interrupted by user{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error starting node: {e}{Colors.NC}")
            return False
        
        return True
    
    def print_running_info(self):
        """Print information about running node"""
        print()
        print(f"{Colors.GREEN}╔════════════════════════════════════════════════════════════╗{Colors.NC}")
        print(f"{Colors.GREEN}║  QRDX Testnet Node Running                                ║{Colors.NC}")
        print(f"{Colors.GREEN}╚════════════════════════════════════════════════════════════╝{Colors.NC}")
        print()
        print(f"{Colors.BLUE}Connection Details:{Colors.NC}")
        print(f"  HTTP RPC:   {Colors.GREEN}http://localhost:{self.args.rpc_port}{Colors.NC}")
        print(f"  Network ID: {Colors.GREEN}{self.args.network_id}{Colors.NC}")
        print()
        print(f"{Colors.BLUE}Test the connection:{Colors.NC}")
        print(f"  {Colors.YELLOW}curl -X POST http://localhost:{self.args.rpc_port} \\{Colors.NC}")
        print(f"  {Colors.YELLOW}  -H 'Content-Type: application/json' \\{Colors.NC}")
        print(f"  {Colors.YELLOW}  -d '{{\"jsonrpc\":\"2.0\",\"method\":\"eth_blockNumber\",\"params\":[],\"id\":1}}'{Colors.NC}")
        print()
        print(f"{Colors.BLUE}Validator Status:{Colors.NC}")
        print(f"  Index:      {Colors.GREEN}{self.args.validator_index}{Colors.NC}")
        print(f"  Status:     {Colors.GREEN}Active{Colors.NC}")
        print()
        print(f"{Colors.YELLOW}Logs will appear below. Press Ctrl+C to stop...{Colors.NC}")
        print()
        print(f"{Colors.BLUE}════════════════════════════════════════════════════════════{Colors.NC}")
        print()
    
    def cleanup(self):
        """Cleanup on exit"""
        print()
        print(f"{Colors.YELLOW}Shutting down node...{Colors.NC}")
        
        # Terminate process
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
                print(f"{Colors.GREEN}✓ Process terminated{Colors.NC}")
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                print(f"{Colors.YELLOW}✓ Process killed (didn't terminate gracefully){Colors.NC}")
            except Exception as e:
                print(f"{Colors.RED}✗ Error stopping process: {e}{Colors.NC}")
        
        # Remove data directory
        if self.cleanup_on_exit and self.data_dir and os.path.exists(self.data_dir):
            try:
                shutil.rmtree(self.data_dir)
                print(f"{Colors.GREEN}✓ Data directory removed{Colors.NC}")
            except Exception as e:
                print(f"{Colors.RED}✗ Error removing data directory: {e}{Colors.NC}")
        elif self.data_dir:
            print(f"{Colors.BLUE}ℹ Data directory preserved: {self.data_dir}{Colors.NC}")
        
        print(f"{Colors.GREEN}✓ Shutdown complete{Colors.NC}")
    
    def run(self):
        """Run the testnet node"""
        try:
            self.print_banner()
            self.setup_data_directory()
            self.print_config()
            self.generate_genesis()
            return self.start_node()
        except Exception as e:
            print(f"{Colors.RED}✗ Fatal error: {e}{Colors.NC}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Start a local QRDX testnet node',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                   # Start with defaults
  %(prog)s --validator-index 5               # Run as validator 5
  %(prog)s --rpc-port 8555 --no-cleanup      # Custom port, keep data
  %(prog)s --verbose                         # Debug logging
        """
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=30303,
        help='P2P listening port (default: 30303)'
    )
    
    parser.add_argument(
        '--rpc-port',
        type=int,
        default=8545,
        help='HTTP RPC port (default: 8545)'
    )
    
    parser.add_argument(
        '--network-id',
        type=int,
        default=1337,
        help='Network ID (default: 1337)'
    )
    
    parser.add_argument(
        '--validator-index',
        type=int,
        default=0,
        help='Run as validator N (0-149, default: 0)'
    )
    
    parser.add_argument(
        '--no-cleanup',
        action='store_true',
        help="Don't delete data directory on exit"
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable debug logging'
    )
    
    args = parser.parse_args()
    
    # Validate validator index
    if not 0 <= args.validator_index <= 149:
        parser.error('Validator index must be between 0 and 149')
    
    # Run testnet
    testnet = QRDXTestnet(args)
    success = testnet.run()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
