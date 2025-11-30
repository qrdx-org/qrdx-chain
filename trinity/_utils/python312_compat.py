"""
Python 3.12 compatibility patches for third-party libraries.

Fixes issues with traceback handling in trio and other libraries
that use the removed 'compact' parameter.
"""
import sys
import traceback as _traceback_module


# Store original TracebackException.__init__
_original_traceback_exception_init = _traceback_module.TracebackException.__init__


def _patched_traceback_exception_init(
    self,
    exc_type,
    exc_value,
    exc_traceback,
    *,
    limit=None,
    lookup_lines=True,
    capture_locals=False,
    compact=False,  # Accept but ignore this parameter
    max_group_width=15,
    max_group_depth=10,
    _seen=None
):
    """
    Patched TracebackException.__init__ that accepts but ignores 'compact' parameter.
    
    In Python 3.11 and earlier, 'compact' was a valid parameter.
    In Python 3.12+, it was removed but some libraries still try to use it.
    This patch allows the code to work by accepting and ignoring the parameter.
    """
    # Call original without 'compact' parameter
    _original_traceback_exception_init(
        self,
        exc_type,
        exc_value,
        exc_traceback,
        limit=limit,
        lookup_lines=lookup_lines,
        capture_locals=capture_locals,
        max_group_width=max_group_width,
        max_group_depth=max_group_depth,
        _seen=_seen
    )


def apply_patches():
    """Apply Python 3.12 compatibility patches."""
    if sys.version_info >= (3, 12):
        # Patch TracebackException.__init__ to accept 'compact' parameter
        _traceback_module.TracebackException.__init__ = _patched_traceback_exception_init
