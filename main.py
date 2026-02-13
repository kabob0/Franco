#!/usr/bin/env python3
"""
Main entry point for the application.
A script that demonstrates data processing and configuration management.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from config import Config
from data_processor import DataProcessor
from logger import setup_logger

logger = setup_logger(__name__)


def main():
    """Main function to run the application."""
    logger.info("Starting application...")
    
    # Load configuration
    config = Config()
    logger.info(f"Loaded config: {config}")
    
    # Initialize data processor
    processor = DataProcessor(config)
    
    # Example: Process some data
    sample_data = [
        {"name": "Alice", "age": 28, "score": 85},
        {"name": "Bob", "age": 35, "score": 92},
        {"name": "Charlie", "age": 22, "score": 78},
    ]
    
    logger.info("Processing sample data...")
    results = processor.process(sample_data)
    
    # Display results
    print("\n=== Results ===")
    for result in results:
        print(f"  {result['name']}: {result['status']}")
    
    print(f"\nTotal processed: {len(results)}")
    logger.info("Application completed successfully")


if __name__ == "__main__":
    main()
