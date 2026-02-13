"""Test for data_processor module."""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from config import Config
from data_processor import DataProcessor


@pytest.fixture
def config():
    """Fixture for Config object."""
    return Config()


@pytest.fixture
def processor(config):
    """Fixture for DataProcessor object."""
    return DataProcessor(config)


def test_processor_initialization(processor):
    """Test processor initialization."""
    assert processor.processed_count == 0


def test_process_excellent_score(processor):
    """Test processing with excellent score."""
    data = [{"name": "Alice", "score": 95}]
    results = processor.process(data)
    
    assert len(results) == 1
    assert results[0]["status"] == "Excellent"
    assert results[0]["name"] == "Alice"


def test_process_good_score(processor):
    """Test processing with good score."""
    data = [{"name": "Bob", "score": 85}]
    results = processor.process(data)
    
    assert results[0]["status"] == "Good"


def test_process_needs_improvement(processor):
    """Test processing with low score."""
    data = [{"name": "Charlie", "score": 70}]
    results = processor.process(data)
    
    assert results[0]["status"] == "Needs Improvement"


def test_process_multiple_records(processor):
    """Test processing multiple records."""
    data = [
        {"name": "Alice", "score": 95},
        {"name": "Bob", "score": 85},
        {"name": "Charlie", "score": 70},
    ]
    results = processor.process(data)
    
    assert len(results) == 3
    assert processor.processed_count == 3
