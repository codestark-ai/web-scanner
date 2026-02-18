import json
import csv
from datetime import datetime
from typing import List, Dict, Any
import os

class DataHandler:
    def __init__(self, output_dir: str = "data/output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def save_to_json(self, data: List[Dict[str, Any]], filename: str = None) -> str:
        """Save data to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawl_results_{timestamp}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def save_to_csv(self, data: List[Dict[str, Any]], filename: str = None) -> str:
        """Save data to CSV file"""
        if not data:
            return ""
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawl_results_{timestamp}.csv"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Extract all possible keys from data
        all_keys = set()
        for item in data:
            all_keys.update(item.keys())
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=list(all_keys))
            writer.writeheader()
            writer.writerows(data)
        
        return filepath
    
    def load_from_json(self, filename: str) -> List[Dict[str, Any]]:
        """Load data from JSON file"""
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
    
    def export_report(self, data: List[Dict[str, Any]]) -> str:
        """Generate a simple report"""
        if not data:
            return "No data to report"
        
        successful = sum(1 for item in data if 'error' not in item)
        errors = len(data) - successful
        
        report = f"""
        ===== CRAWLING REPORT =====
        Total Requests: {len(data)}
        Successful: {successful}
        Errors: {errors}
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        ===========================
        
        Details:
        """
        
        for i, item in enumerate(data, 1):
            report += f"\n{i}. URL: {item.get('url', 'N/A')}\n"
            report += f"   Status: {'Success' if 'error' not in item else 'Error'}\n"
            if 'error' in item:
                report += f"   Error: {item['error']}\n"
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_dir, f"report_{timestamp}.txt")
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        return report_file