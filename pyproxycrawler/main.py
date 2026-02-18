import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from crawler.respectful_crawler import RespectfulCrawler
from crawler.proxy_manager import ProxyManager
from crawler.data_handler import DataHandler
import threading
import json

class ProxyCrawlerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyProxyCrawler - Educational Tool")
        self.root.geometry("900x700")
        self.root.configure(bg="#2b2b2b")
        
        # Initialize components
        self.proxy_manager = ProxyManager()
        self.crawler = None
        self.data_handler = DataHandler()
        
        # Set style
        self.setup_styles()
        
        # Build UI
        self.create_widgets()
        
        # Load sample proxies (for demonstration)
        self.load_sample_proxies()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure("TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="#ffffff")
        style.configure("TButton", background="#4a4a4a", foreground="#ffffff")
        style.map("TButton", background=[("active", "#5a5a5a")])
        style.configure("TEntry", fieldbackground="#3a3a3a", foreground="#ffffff")
        style.configure("TCombobox", fieldbackground="#3a3a3a", foreground="#ffffff")
        style.configure("Treeview", background="#3a3a3a", foreground="#ffffff", fieldbackground="#3a3a3a")
        style.configure("Treeview.Heading", background="#4a4a4a", foreground="#ffffff")
    
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = tk.Label(main_frame, text="PyProxyCrawler", 
                               font=("Arial", 24, "bold"), 
                               bg="#2b2b2b", fg="#00ff88")
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Control Panel
        control_frame = ttk.LabelFrame(main_frame, text="Crawler Controls", padding="10")
        control_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # URL Input
        ttk.Label(control_frame, text="Target URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(control_frame, width=50)
        self.url_entry.grid(row=0, column=1, padx=5, pady=5)
        self.url_entry.insert(0, "https://httpbin.org/ip")  # Demo URL
        
        # Max Pages
        ttk.Label(control_frame, text="Max Pages:").grid(row=0, column=2, sticky=tk.W, pady=5, padx=(10,0))
        self.max_pages_spin = ttk.Spinbox(control_frame, from_=1, to=100, width=10)
        self.max_pages_spin.grid(row=0, column=3, padx=5, pady=5)
        self.max_pages_spin.set("5")
        
        # Delay
        ttk.Label(control_frame, text="Delay (sec):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.delay_spin = ttk.Spinbox(control_frame, from_=1, to=10, width=10)
        self.delay_spin.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.delay_spin.set("2")
        
        # Buttons
        self.start_btn = ttk.Button(control_frame, text="Start Crawling", command=self.start_crawling)
        self.start_btn.grid(row=1, column=2, padx=5, pady=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_crawling, state=tk.DISABLED)
        self.stop_btn.grid(row=1, column=3, padx=5, pady=5)
        
        # Proxy Management Frame
        proxy_frame = ttk.LabelFrame(main_frame, text="Proxy Management", padding="10")
        proxy_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Proxy List
        ttk.Label(proxy_frame, text="Available Proxies:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        self.proxy_listbox = tk.Listbox(proxy_frame, height=8, width=40, 
                                        bg="#3a3a3a", fg="#ffffff", 
                                        selectbackground="#00ff88")
        self.proxy_listbox.grid(row=1, column=0, rowspan=4, padx=5, pady=5)
        
        # Scrollbar for proxy list
        proxy_scrollbar = ttk.Scrollbar(proxy_frame, orient=tk.VERTICAL)
        proxy_scrollbar.grid(row=1, column=1, rowspan=4, sticky=(tk.N, tk.S))
        self.proxy_listbox.config(yscrollcommand=proxy_scrollbar.set)
        proxy_scrollbar.config(command=self.proxy_listbox.yview)
        
        # Proxy controls
        ttk.Button(proxy_frame, text="Add Proxy", 
                  command=self.add_proxy_dialog).grid(row=1, column=2, padx=5, pady=2, sticky=tk.W)
        ttk.Button(proxy_frame, text="Remove Selected", 
                  command=self.remove_proxy).grid(row=2, column=2, padx=5, pady=2, sticky=tk.W)
        ttk.Button(proxy_frame, text="Clear All", 
                  command=self.clear_proxies).grid(row=3, column=2, padx=5, pady=2, sticky=tk.W)
        ttk.Button(proxy_frame, text="Test Proxies", 
                  command=self.test_proxies).grid(row=4, column=2, padx=5, pady=2, sticky=tk.W)
        
        # Results Frame
        results_frame = ttk.LabelFrame(main_frame, text="Crawling Results", padding="10")
        results_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=15, 
                                                      bg="#3a3a3a", fg="#ffffff",
                                                      insertbackground="#ffffff")
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready to crawl")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                               relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
    
    def load_sample_proxies(self):
        """Load sample proxies for demonstration (not real proxies)"""
        sample_proxies = [
            "192.168.1.1:8080",
            "10.0.0.1:8888",
            "proxy.demo:3128"
        ]
        for proxy in sample_proxies:
            self.proxy_manager.add_proxy(proxy)
            self.proxy_listbox.insert(tk.END, proxy)
    
    def add_proxy_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Proxy")
        dialog.geometry("300x150")
        dialog.configure(bg="#2b2b2b")
        
        ttk.Label(dialog, text="Proxy (host:port):").pack(pady=10)
        proxy_entry = ttk.Entry(dialog, width=30)
        proxy_entry.pack(pady=5)
        
        def add_proxy():
            proxy = proxy_entry.get().strip()
            if proxy:
                if ":" in proxy:
                    self.proxy_manager.add_proxy(proxy)
                    self.proxy_listbox.insert(tk.END, proxy)
                    dialog.destroy()
                else:
                    messagebox.showwarning("Invalid Format", "Please use format: host:port")
        
        ttk.Button(dialog, text="Add", command=add_proxy).pack(pady=10)
        proxy_entry.focus()
    
    def remove_proxy(self):
        selection = self.proxy_listbox.curselection()
        if selection:
            proxy = self.proxy_listbox.get(selection[0])
            self.proxy_manager.remove_proxy(proxy)
            self.proxy_listbox.delete(selection[0])
    
    def clear_proxies(self):
        if messagebox.askyesno("Confirm", "Clear all proxies?"):
            self.proxy_manager.clear()
            self.proxy_listbox.delete(0, tk.END)
    
    def test_proxies(self):
        self.update_status("Testing proxies...")
        # This would test proxy connectivity in a real implementation
        self.update_status("Proxy test completed")
    
    def start_crawling(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a URL")
            return
        
        # Disable start button, enable stop button
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        
        # Clear results
        self.results_text.delete(1.0, tk.END)
        
        # Start crawling in separate thread
        self.crawler = RespectfulCrawler(
            proxy_manager=self.proxy_manager,
            delay=int(self.delay_spin.get()),
            max_pages=int(self.max_pages_spin.get())
        )
        
        self.crawler_thread = threading.Thread(
            target=self.run_crawler,
            args=(url,),
            daemon=True
        )
        self.crawler_thread.start()
    
    def run_crawler(self, start_url):
        try:
            self.update_status("Crawling started...")
            
            # For demonstration, we'll simulate crawling
            results = self.crawler.crawl_demo(start_url)
            
            # Display results
            self.display_results(results)
            
            self.update_status("Crawling completed successfully")
            
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            self.results_text.insert(tk.END, f"Error occurred: {str(e)}\n")
        finally:
            self.root.after(0, self.reset_buttons)
    
    def display_results(self, results):
        self.results_text.insert(tk.END, "="*60 + "\n")
        self.results_text.insert(tk.END, "CRAWLING RESULTS\n")
        self.results_text.insert(tk.END, "="*60 + "\n\n")
        
        for result in results:
            self.results_text.insert(tk.END, f"URL: {result['url']}\n")
            self.results_text.insert(tk.END, f"Status: {result['status']}\n")
            self.results_text.insert(tk.END, f"Proxy Used: {result.get('proxy', 'Direct')}\n")
            if 'data' in result:
                self.results_text.insert(tk.END, f"Data: {result['data'][:200]}...\n")
            self.results_text.insert(tk.END, "-"*40 + "\n")
    
    def stop_crawling(self):
        if self.crawler:
            self.crawler.stop()
            self.update_status("Crawling stopped by user")
            self.reset_buttons()
    
    def reset_buttons(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def update_status(self, message):
        self.root.after(0, lambda: self.status_var.set(message))
        print(f"Status: {message}")

def main():
    root = tk.Tk()
    app = ProxyCrawlerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()