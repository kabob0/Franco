"""Configuration management module."""

from pathlib import Path


class Config:
    """Application configuration."""
    
    # Thresholds
    HIGH_THRESHOLD = 90
    MEDIUM_THRESHOLD = 75
    
    # Paths
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_DIR = PROJECT_ROOT / "data"
    LOG_DIR = PROJECT_ROOT / "logs"
    
    # Logging
    LOG_LEVEL = "INFO"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    def __init__(self):
        """Initialize configuration and create necessary directories."""
        self.DATA_DIR.mkdir(exist_ok=True)
        self.LOG_DIR.mkdir(exist_ok=True)
    
    def __str__(self):
        """String representation of config."""
        return (
            f"Config(HIGH_THRESHOLD={self.HIGH_THRESHOLD}, "
            f"MEDIUM_THRESHOLD={self.MEDIUM_THRESHOLD})"
        )
