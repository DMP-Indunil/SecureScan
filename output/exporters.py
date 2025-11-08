"""
Result export functionality for JSON and CSV formats
"""

import json
import csv


class ResultExporter:
    """Export scan results to various formats"""
    
    @staticmethod
    def export_to_json(results, filename):
        """
        Export scan results to JSON file
        
        Args:
            results (list): List of scan results
            filename (str): Output filename
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            return True
        except Exception as e:
            print(f"❌ Error exporting to JSON: {e}")
            return False
    
    @staticmethod
    def export_to_csv(results, filename):
        """
        Export scan results to CSV file
        
        Args:
            results (list): List of scan results
            filename (str): Output filename
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filename, 'w', newline='') as f:
                if not results:
                    return True
                    
                fieldnames = results[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            return True
        except Exception as e:
            print(f"❌ Error exporting to CSV: {e}")
            return False
    
    @staticmethod
    def export_results(results, format_type, filename):
        """
        Export results to specified format
        
        Args:
            results (list): List of scan results
            format_type (str): Export format ('json' or 'csv')
            filename (str): Output filename
            
        Returns:
            bool: True if successful, False otherwise
        """
        if format_type.lower() == 'json':
            return ResultExporter.export_to_json(results, filename)
        elif format_type.lower() == 'csv':
            return ResultExporter.export_to_csv(results, filename)
        else:
            print(f"❌ Unsupported format: {format_type}")
            return False
