"""
QRDX Blockchain Package

Core imports are lazily loaded to avoid dependency conflicts.
For direct module access, import from submodules:
    
    from qrdx.crypto import PrivateKey, PublicKey
    from qrdx.database import Database
    from qrdx.exceptions import DoubleSpendException
"""

# Lazy imports to avoid loading everything at package import
def __getattr__(name):
    """Lazy module loading to prevent dependency conflicts."""
    if name == 'Database':
        from .database import Database
        return Database
    elif name == 'main':
        from .node import main
        return main
    elif name == 'DoubleSpendException':
        from .exceptions import DoubleSpendException
        return DoubleSpendException
    raise AttributeError(f"module 'qrdx' has no attribute {name!r}")

__all__ = ['Database', 'main', 'DoubleSpendException']


