"""Logging configuration module."""

import logging
from config import Config


def setup_logger(name):
    """Setup and return a logger.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured logger instance
    """
    config = Config()
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL))
    
    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(getattr(logging, config.LOG_LEVEL))
    
    # Create formatter
    formatter = logging.Formatter(config.LOG_FORMAT)
    ch.setFormatter(formatter)
    
    # Add handler to logger
    if not logger.handlers:
        logger.addHandler(ch)
    
    return logger
