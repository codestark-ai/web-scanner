import random
from typing import List, Optional

class ProxyManager:
    def __init__(self):
        self.proxies: List[str] = []
        self.current_index = 0
    
    def add_proxy(self, proxy: str) -> None:
        """Add a proxy to the manager"""
        if proxy not in self.proxies:
            self.proxies.append(proxy)
    
    def remove_proxy(self, proxy: str) -> bool:
        """Remove a proxy from the manager"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
            return True
        return False
    
    def clear(self) -> None:
        """Clear all proxies"""
        self.proxies.clear()
        self.current_index = 0
    
    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy in rotation"""
        if not self.proxies:
            return None
        
        proxy = self.proxies[self.current_index]
        self.current_index = (self.current_index + 1) % len(self.proxies)
        return proxy
    
    def get_random_proxy(self) -> Optional[str]:
        """Get a random proxy"""
        if not self.proxies:
            return None
        return random.choice(self.proxies)
    
    def count(self) -> int:
        """Get number of proxies"""
        return len(self.proxies)
    
    def get_all(self) -> List[str]:
        """Get all proxies"""
        return self.proxies.copy()