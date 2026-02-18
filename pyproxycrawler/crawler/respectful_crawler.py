import time
import requests
from typing import Dict, List, Any
from urllib.parse import urlparse
from .proxy_manager import ProxyManager

class RespectfulCrawler:
    def __init__(self, proxy_manager: ProxyManager, delay: int = 2, max_pages: int = 10):
        self.proxy_manager = proxy_manager
        self.delay = delay
        self.max_pages = max_pages
        self.visited_urls = set()
        self.is_running = True
        
        # Headers to mimic a real browser
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    def crawl_demo(self, start_url: str) -> List[Dict[str, Any]]:
        """Demo crawler for educational purposes"""
        results = []
        
        # Simulate crawling a few pages
        for i in range(min(self.max_pages, 3)):  # Limit to 3 for demo
            if not self.is_running:
                break
            
            # Get a proxy
            proxy = self.proxy_manager.get_next_proxy()
            
            # Simulate request
            result = {
                'url': f"{start_url}?page={i+1}",
                'proxy': proxy or 'Direct',
                'timestamp': time.time(),
                'status': 'Success' if i < 2 else 'Blocked (Demo)'
            }
            
            # Simulate getting some data
            if i < 2:
                result['data'] = f"Demo content from page {i+1}. This is simulated data for educational purposes."
            
            results.append(result)
            
            # Add delay
            time.sleep(self.delay)
        
        return results
    
    def make_request(self, url: str, use_proxy: bool = True) -> Dict[str, Any]:
        """Make a respectful HTTP request"""
        proxies = None
        
        if use_proxy:
            proxy = self.proxy_manager.get_next_proxy()
            if proxy:
                proxies = {
                    'http': f'http://{proxy}',
                    'https': f'http://{proxy}'
                }
        
        try:
            response = requests.get(
                url,
                headers=self.headers,
                proxies=proxies,
                timeout=10,
                allow_redirects=True
            )
            
            return {
                'status_code': response.status_code,
                'content': response.text[:1000],  # Limit content for demo
                'headers': dict(response.headers),
                'url': response.url,
                'proxy_used': proxy if use_proxy and proxy else 'Direct'
            }
            
        except requests.RequestException as e:
            return {
                'error': str(e),
                'url': url,
                'proxy_used': proxy if use_proxy and proxy else 'Direct'
            }
    
    def stop(self):
        """Stop the crawler"""
        self.is_running = False
    
    def is_valid_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False