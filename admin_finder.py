#!/usr/bin/env python3
"""
OmniAdminFinder - Admin Panel Discovery Tool

A comprehensive tool for discovering admin accounts and access points 
across web applications.
"""

import requests
import threading
import time
import argparse
import sys
from urllib.parse import urljoin
from typing import List, Dict, Optional
import logging

__version__ = '1.0.0'
__author__ = 'PN777'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AdminFinder:
    """Main class for discovering admin panels and access points."""
    
    DEFAULT_ENDPOINTS = [
        '/admin', '/admin/', '/administrator', '/admin/index.php',
        '/admin/login.php', '/admin.php', '/cp', '/wp-admin',
        '/user/admin', '/staff', '/manage', '/webadmin', '/adminpanel',
        '/admin-panel', '/administrator/', '/admin_area', '/panel',
        '/controlpanel', '/adminarea', '/admin-area', '/login',
        '/backend', '/dashboard', '/console', '/manager'
    ]
    
    DEFAULT_USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
    ]
    
    def __init__(
        self,
        target_url: str,
        threads: int = 10,
        timeout: int = 5,
        proxy: Optional[str] = None,
        wordlist: Optional[List[str]] = None,
        verify_ssl: bool = True
    ):
        """
        Initialize AdminFinder.
        
        Args:
            target_url: Target website URL
            threads: Number of threads for scanning
            timeout: Request timeout in seconds
            proxy: Proxy URL (e.g., http://proxy.example.com:8080)
            wordlist: Custom wordlist of endpoints to scan
            verify_ssl: Whether to verify SSL certificates
        """
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.results = []
        self.lock = threading.Lock()
        self.user_agent_index = 0
        
        # Set endpoints
        if wordlist:
            self.endpoints = wordlist
        else:
            self.endpoints = self.DEFAULT_ENDPOINTS
    
    def _get_user_agent(self) -> str:
        """Rotate and return next user agent."""
        agent = self.DEFAULT_USER_AGENTS[self.user_agent_index % len(self.DEFAULT_USER_AGENTS)]
        self.user_agent_index += 1
        return agent
    
    def _check_endpoint(self, endpoint: str) -> Dict:
        """
        Check if an endpoint exists on the target.
        
        Args:
            endpoint: Endpoint path to check
            
        Returns:
            Dictionary with endpoint details
        """
        url = urljoin(self.target_url, endpoint)
        headers = {'User-Agent': self._get_user_agent()}
        proxies = {}
        
        if self.proxy:
            proxies = {'http': self.proxy, 'https': self.proxy}
        
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                proxies=proxies,
                allow_redirects=True
            )
            
            # Consider 2xx, 3xx, 4xx as found (not 5xx)
            found = 200 <= response.status_code < 500
            
            return {
                'url': url,
                'endpoint': endpoint,
                'status_code': response.status_code,
                'found': found,
                'content_length': len(response.content),
                'headers': dict(response.headers)
            }
        
        except requests.Timeout:
            logger.warning(f"Timeout: {url}")
            return {
                'url': url,
                'endpoint': endpoint,
                'status_code': None,
                'found': False,
                'error': 'Timeout'
            }
        except requests.RequestException as e:
            logger.warning(f"Error checking {url}: {str(e)}")
            return {
                'url': url,
                'endpoint': endpoint,
                'status_code': None,
                'found': False,
                'error': str(e)
            }
    
    def _worker(self, endpoints_queue: List[str]):
        """Worker thread that processes endpoints."""
        for endpoint in endpoints_queue:
            result = self._check_endpoint(endpoint)
            with self.lock:
                self.results.append(result)
            
            if result['found']:
                logger.info(f"Found: {result['url']} (Status: {result['status_code']})")
    
    def scan(self) -> List[Dict]:
        """
        Scan the target for admin panels.
        
        Returns:
            List of results with endpoint information
        """
        logger.info(f"Starting scan on {self.target_url}")
        logger.info(f"Endpoints to check: {len(self.endpoints)}")
        
        self.results = []
        
        # Split endpoints among threads
        chunk_size = max(1, len(self.endpoints) // self.threads)
        threads = []
        
        for i in range(0, len(self.endpoints), chunk_size):
            chunk = self.endpoints[i:i + chunk_size]
            thread = threading.Thread(target=self._worker, args=(chunk,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        logger.info(f"Scan complete. Found {sum(1 for r in self.results if r.get('found'))} endpoints")
        
        return self.results
    
    def get_found_endpoints(self) -> List[Dict]:
        """Get only the found endpoints."""
        return [r for r in self.results if r.get('found')]
    
    def save_results(self, filename: str):
        """Save results to a file."""
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results saved to {filename}")


def main():
    """Command line interface."""
    parser = argparse.ArgumentParser(
        description='OmniAdminFinder - Discover admin panels and access points',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python admin_finder.py https://example.com
  python admin_finder.py https://example.com --threads 20 --timeout 10
  python admin_finder.py https://example.com --proxy http://proxy.com:8080
        '''
    )
    
    parser.add_argument('url', help='Target URL')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://proxy.com:8080)')
    parser.add_argument('--wordlist', help='Custom wordlist file (one endpoint per line)')
    parser.add_argument('--verify-ssl', action='store_true', default=True, help='Verify SSL certificates')
    parser.add_argument('--no-verify-ssl', dest='verify_ssl', action='store_false', help='Skip SSL verification')
    parser.add_argument('--output', help='Save results to JSON file')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    # Load custom wordlist if provided
    wordlist = None
    if args.wordlist:
        try:
            with open(args.wordlist, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            logger.info(f"Loaded {len(wordlist)} endpoints from {args.wordlist}")
        except FileNotFoundError:
            logger.error(f"Wordlist file not found: {args.wordlist}")
            sys.exit(1)
    
    # Create finder and run scan
    finder = AdminFinder(
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
        wordlist=wordlist,
        verify_ssl=args.verify_ssl
    )
    
    results = finder.scan()
    found = finder.get_found_endpoints()
    
    # Print results
    print("\n" + "="*60)
    print("SCAN RESULTS")
    print("="*60)
    
    if found:
        print(f"\nFound {len(found)} admin endpoints:\n")
        for result in found:
            print(f"[{result['status_code']}] {result['url']}")
    else:
        print("\nNo admin endpoints found.")
    
    print(f"\nTotal endpoints checked: {len(results)}")
    print("="*60 + "\n")
    
    # Save results if requested
    if args.output:
        finder.save_results(args.output)
    
    return 0 if found else 1


if __name__ == '__main__':
    sys.exit(main())
