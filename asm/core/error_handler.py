"""
Central error handling and logging for ASM Tool
"""

import logging
from typing import TypeVar, Optional, Dict, Any
from functools import wraps
import traceback
from datetime import datetime, timezone

# Configure structured logging
logger = logging.getLogger("asm")
logger.setLevel(logging.DEBUG)

T = TypeVar("T", bound=Exception)


class ASMError(Exception):
    """Custom exception type for ASM operations"""

    def __init__(
        self, message: str, exit_code: int = 1, original: Optional[Exception] = None
    ):
        self.message = message
        self.exit_code = exit_code
        self.original = original
        super().__init__(message)

    def __str__(self) -> str:
        return self.message


def handle_errors(default_return: Any = None):
    """Decorator for consistent error handling"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ASMError:
                logger.error(f"[{func.__name__}] {e.message}")
                raise e
            except Exception as e:
                logger.error(f"[{func.__name__}] Unexpected error: {e}")
                logger.debug(traceback.format_exc())
                if default_return is not None:
                    return default_return
                raise

        return wrapper

    return decorator


def log_call(module: str, operation: str):
    """Decorator for logging all function calls"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger.info(
                f"[{module}.{operation}] Called with args: {args}, kwargs: {kwargs}"
            )
            result = func(*args, **kwargs)
            logger.debug(f"[{module}.{operation}] Returned: {result}")
            return result

        return wrapper

    return decorator
