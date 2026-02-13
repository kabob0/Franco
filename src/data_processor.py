"""Data processor module for handling data operations."""


class DataProcessor:
    """Process and transform data based on configuration."""
    
    def __init__(self, config):
        """Initialize processor with configuration.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.processed_count = 0
    
    def process(self, data):
        """Process a list of data records.
        
        Args:
            data: List of dictionaries to process
            
        Returns:
            List of processed records with status
        """
        results = []
        
        for record in data:
            processed = self._process_record(record)
            results.append(processed)
            self.processed_count += 1
        
        return results
    
    def _process_record(self, record):
        """Process a single record.
        
        Args:
            record: Individual data record
            
        Returns:
            Processed record with status
        """
        # Determine status based on score
        score = record.get("score", 0)
        
        if score >= self.config.HIGH_THRESHOLD:
            status = "Excellent"
        elif score >= self.config.MEDIUM_THRESHOLD:
            status = "Good"
        else:
            status = "Needs Improvement"
        
        return {
            **record,
            "status": status,
        }
