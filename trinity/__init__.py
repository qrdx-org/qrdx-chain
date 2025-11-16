import sys

# TODO: update this to use the `trinity` version once extracted from py-evm
__version__: str
try:
    import pkg_resources
    __version__ = pkg_resources.get_distribution("trinity").version
except Exception:
    try:
        import pkg_resources
        __version__ = f"eth-{pkg_resources.get_distribution('py-evm').version}"
    except Exception:
        # Fallback for development/Docker environments where packages aren't installed
        __version__ = "0.1.0-dev+qrpos"


# Setup the `DEBUG2` logging level
from eth_utils import setup_DEBUG2_logging  # noqa: E402
setup_DEBUG2_logging()


def is_uvloop_supported() -> bool:
    return sys.platform in {'darwin', 'linux'} or sys.platform.startswith('freebsd')


if is_uvloop_supported():
    # Set `uvloop` as the default event loop
    import asyncio

    from eth._warnings import catch_and_ignore_import_warning
    with catch_and_ignore_import_warning():
        try:
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except ImportError:
            # uvloop not available, use default event loop
            pass

# DO NOT import main at module level - it triggers dependency chain
# from .main import (  # noqa: F401
#     main,
# )

def main():
    """Lazy import of main function to avoid dependency issues."""
    from .main import main as _main
    return _main()
