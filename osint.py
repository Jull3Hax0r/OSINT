#!/usr/bin/env python3
"""
OSINT Tool - Multi-Source Open Source Intelligence Gatherer
Search for information from multiple sources based on name, email or alias
"""

import requests
import json
import time
import re
import argparse
from urllib.parse import quote, urljoin
from bs4 import BeautifulSoup
import concurrent.futures
from colorama import init, Fore, Back, Style
import sys
from typing import Dict, List, Any
import urllib3
import socket # For analyze_email_domain

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

class OSINTTool:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.results = {}
        
    def print_banner(self):
        text_above_banner = " v0.1 - https://jull3.se"
        
        # Content lines of the banner, without the frame.
        # Each line's content was originally 63 characters wide to fit inside the frame.
        banner_lines = [
            f"                      {Fore.YELLOW}OSINT INTELLIGENCE TOOL{Fore.CYAN}                    {Style.RESET_ALL}",
            f"                   {Fore.GREEN}Multi-Source Information Gatherer{Fore.CYAN}              {Style.RESET_ALL}",
            f"                                                               {Style.RESET_ALL}", # 63 spaces
            f"  {Fore.RED}█████{Fore.CYAN}  ███████ ██ ███    ██ ████████                        {Style.RESET_ALL}",
            f" {Fore.RED}██   ██{Fore.CYAN} ██      ██ ████   ██    ██                           {Style.RESET_ALL}",
            f" {Fore.RED}██   ██{Fore.CYAN} ███████ ██ ██ ██  ██    ██                           {Style.RESET_ALL}",
            f" {Fore.RED}██   ██{Fore.CYAN}      ██ ██ ██  ██ ██    ██                           {Style.RESET_ALL}",
            f"  {Fore.RED}█████{Fore.CYAN}  ███████ ██ ██   ████    ██                           {Style.RESET_ALL}"
        ]

        # Effective width of the banner content for centering the text_above_banner.
        # This is based on the 63-character width of the content lines.
        banner_content_width = 63
        
        text_above_len = len(text_above_banner)
        
        # Calculate padding to center the text_above_banner
        padding_total = banner_content_width - text_above_len
        left_padding_count = padding_total // 2
        
        # Ensure padding is not negative if text is too long
        if left_padding_count < 0:
            left_padding_count = 0
            
        left_padding = " " * left_padding_count
        
        version_info_line = f"{left_padding}{Fore.WHITE}{text_above_banner}{Style.RESET_ALL}"

        print(version_info_line)
        for line in banner_lines:
            print(line)
        print() # Add a blank line after banner for spacing
    
    def print_status(self, message: str, status: str = "info"):
        colors = {
            "info": Fore.BLUE,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED
        }
        icons = {
            "info": "ℹ",
            "success": "✓",
            "warning": "⚠",
            "error": "✗"
        }
        print(f"{colors.get(status, Fore.WHITE)}[{icons.get(status, '•')}] {message}{Style.RESET_ALL}")
    
    def search_github(self, query: str) -> Dict[str, Any]:
        """Search GitHub for users and repositories"""
        try:
            # Search users
            user_url = f"https://api.github.com/search/users?q={quote(query)}"
            user_response = self.session.get(user_url, timeout=10)
            
            # Search repositories
            repo_url = f"https://api.github.com/search/repositories?q={quote(query)}"
            repo_response = self.session.get(repo_url, timeout=10)
            
            results = {
                "users": [],
                "repositories": []
            }
            
            if user_response.status_code == 200:
                user_data = user_response.json()
                for user in user_data.get('items', [])[:5]: # Limiting to top 5 results
                    results["users"].append({
                        "username": user.get('login'),
                        "profile_url": user.get('html_url'),
                        "avatar": user.get('avatar_url'),
                        "followers_url": user.get('followers_url'), 
                        "repos_url": user.get('repos_url') 
                    })
            elif user_response.status_code == 403:
                self.print_status(f"GitHub user search rate limit hit or forbidden. {user_response.json().get('message', '')}", "warning")
            else:
                self.print_status(f"GitHub user search failed with status {user_response.status_code}", "warning")


            if repo_response.status_code == 200:
                repo_data = repo_response.json()
                for repo in repo_data.get('items', [])[:5]: # Limiting to top 5 results
                    results["repositories"].append({
                        "name": repo.get('name'),
                        "full_name": repo.get('full_name'),
                        "url": repo.get('html_url'),
                        "description": repo.get('description'),
                        "stars": repo.get('stargazers_count', 0),
                        "language": repo.get('language')
                    })
            elif repo_response.status_code == 403:
                self.print_status(f"GitHub repository search rate limit hit or forbidden. {repo_response.json().get('message', '')}", "warning")
            else:
                self.print_status(f"GitHub repository search failed with status {repo_response.status_code}", "warning")
            
            return results
        except requests.exceptions.RequestException as e:
            self.print_status(f"GitHub search request failed: {str(e)}", "error")
            return {"users": [], "repositories": [], "error": str(e)}
        except Exception as e:
            self.print_status(f"GitHub search failed with an unexpected error: {str(e)}", "error")
            return {"users": [], "repositories": [], "error": str(e)}
    
    def search_social_media(self, query: str) -> Dict[str, Any]:
        """Search social media platforms"""
        results = {
            "twitter": self.check_twitter_profile(query),
            "instagram": self.check_instagram_profile(query),
            "linkedin": self.check_linkedin_profile(query),
            "facebook": self.check_facebook_profile(query), 
            "reddit": {"search_url": f"https://www.reddit.com/search/?q={quote(query)}", "note": "Manual check required"},
            "github_profile_search": {"search_url": f"https://github.com/search?q={quote(query)}&type=users", "note": "Manual check for profiles"},
            "tiktok": {"search_url": f"https://www.tiktok.com/search/user?q={quote(query)}", "note": "Manual verification required"},
            "youtube_channel_search": {"search_url": f"https://www.youtube.com/results?search_query={quote(query)}&sp=EgIQAg%253D%253D", "note": "Channel search, manual check"}
        }
        return results
    
    def check_twitter_profile(self, username: str) -> Dict[str, Any]:
        """Check Twitter profile or perform search"""
        profile_url_twitter = f"https://twitter.com/{quote(username)}"
        search_url_twitter = f"https://twitter.com/search?q={quote(username)}"
        
        if " " in username: 
            return {
                "search_url": search_url_twitter,
                "note": "Name search performed. Manual verification needed."
            }
        
        try:
            response = self.session.head(profile_url_twitter, timeout=7, allow_redirects=True)
            if response.status_code == 200: 
                return {
                    "exists": True, 
                    "url": profile_url_twitter,
                    "status": "Profile URL seems valid (manual check highly recommended)"
                }
            elif response.status_code == 404:
                 return {"exists": False, "url": profile_url_twitter, "status": "Profile not found (404)"}
            else:
                return {
                    "search_url": search_url_twitter, 
                    "url_attempted": profile_url_twitter,
                    "status_code": response.status_code,
                    "note": f"Direct check inconclusive (status {response.status_code}). Use search. Manual verification needed."
                }
        except requests.exceptions.Timeout:
            self.print_status(f"Twitter check for {username} timed out.", "warning")
            return {"exists": False, "url": profile_url_twitter, "status": "Request timed out", "search_url": search_url_twitter}
        except requests.exceptions.RequestException as e:
            self.print_status(f"Twitter check failed for {username}: {e}", "warning")
            return {"exists": False, "url": profile_url_twitter, "status": f"Request error: {type(e).__name__}", "search_url": search_url_twitter}

    def check_instagram_profile(self, username: str) -> Dict[str, Any]:
        """Check Instagram profile or perform search. Highly likely to be blocked."""
        profile_url_instagram = f"https://www.instagram.com/{quote(username)}/"
        search_url_instagram = f"https://www.instagram.com/explore/search/keyword/?q={quote(username)}"

        if " " in username:
             return {
                "search_url": search_url_instagram,
                "note": "Name search performed. Manual verification needed (login likely required)."
            }
        
        return {
            "search_url": search_url_instagram,
            "url_attempted": profile_url_instagram,
            "note": "Direct Instagram profile checks are unreliable. Use search link. Manual verification needed (login likely required)."
        }
    
    def check_linkedin_profile(self, query: str) -> Dict[str, Any]:
        """Provide LinkedIn search URL."""
        search_url_linkedin = f"https://www.linkedin.com/search/results/people/?keywords={quote(query)}"
        
        return {
            "search_url": search_url_linkedin,
            "note": "Manual verification required. LinkedIn search (login usually required)."
        }
    
    def check_facebook_profile(self, query: str) -> Dict[str, Any]:
        """Provide Facebook search URL."""
        search_url_fb = f"https://www.facebook.com/search/people/?q={quote(query)}"
        return {
            "search_url": search_url_fb,
            "note": "Manual verification required. Facebook search can find profiles or pages (login usually required)."
        }
    
    def search_email_info(self, email: str) -> Dict[str, Any]:
        """Gather information about email address"""
        results = {
            "domain_info": self.analyze_email_domain(email),
            "breach_check_note": "Use haveibeenpwned.com manually for breach information.",
            "format_validation": self.validate_email(email)
        }
        return results
    
    def analyze_email_domain(self, email: str) -> Dict[str, Any]:
        """Analyze email domain"""
        try:
            domain = email.split('@')[1]
        except IndexError:
            return {"error": "Invalid email format, no domain found."}
            
        domain_active = False
        try:
            socket.gethostbyname(domain)
            domain_active = True
        except socket.gaierror: 
            domain_active = False
        except Exception as e: 
            self.print_status(f"Error checking host for domain {domain}: {e}", "warning")
            domain_active = False 
        
        return {
            "domain": domain,
            "host_resolves": domain_active,
            "common_provider": domain.lower() in ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com']
        }
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def search_pastebin(self, query: str) -> Dict[str, Any]:
        """Search for information on Pastebin (provides search link)."""
        return {
            "note": "Manual search recommended on pastebin.com and similar sites.",
            "search_url": f"https://pastebin.com/search?q={quote(query)}"
        }
    
    def search_general_web(self, query: str) -> Dict[str, Any]:
        """General web search using DuckDuckGo."""
        try:
            search_url = f"https://duckduckgo.com/html/?q={quote(query)}" 
            
            return {
                "search_performed": True,
                "search_engine": "DuckDuckGo",
                "search_url": search_url,
                "note": "General web search - manual review of results recommended."
            }
        except Exception as e:
            self.print_status(f"General web search query construction failed: {str(e)}", "error")
            return {"search_performed": False, "error": str(e)}
    
    def run_search(self, query: str, search_type: str = "all"):
        """Run the main search"""
        self.print_status(f"Starting OSINT search for: \"{query}\"", "info")
        
        if self.validate_email(query):
            detected_type = "email"
        elif " " in query or query.replace("-", "").replace(".", "").isalpha(): 
            detected_type = "name"
        else: 
            detected_type = "username/alias"
        
        self.print_status(f"Detected input type: {detected_type}", "info")
        
        search_functions: List[tuple[str, Any]] = []
        
        if search_type in ["all", "github"]:
            search_functions.append(("GitHub Repos/Users", lambda: self.search_github(query)))
        
        if search_type in ["all", "social"]:
            search_functions.append(("Social Media Presence", lambda: self.search_social_media(query)))
        
        if search_type in ["all", "email"] and detected_type == "email":
            search_functions.append(("Email Address Analysis", lambda: self.search_email_info(query)))
        elif search_type == "email" and detected_type != "email":
            self.print_status(f"'{query}' is not a valid email. Skipping email analysis.", "warning")

        if search_type in ["all", "pastebin"]:
            search_functions.append(("Pastebin & Similar Sites Search", lambda: self.search_pastebin(query)))
        
        if search_type in ["all", "web"]:
            search_functions.append(("General Web Search", lambda: self.search_general_web(query)))
        
        if not search_functions:
            self.print_status("No searches to perform for the given type and query.", "warning")
            return

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_source = {
                executor.submit(func): source 
                for source, func in search_functions
            }
            
            for future in concurrent.futures.as_completed(future_to_source):
                source = future_to_source[future]
                try:
                    result = future.result()
                    if result: 
                        self.results[source] = result
                        self.print_status(f"Completed search: {source}", "success")
                    else:
                        self.print_status(f"Search for {source} returned no data.", "info")
                except Exception as e:
                    self.print_status(f"Error during {source} search: {str(e)}", "error")
                    self.results[source] = {"error": f"Search failed: {str(e)}"}
    
    def display_results(self):
        """Display search results"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}                    SEARCH RESULTS")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if not self.results:
            print(f"{Fore.YELLOW}No results to display.{Style.RESET_ALL}")
            return

        for source, data in self.results.items():
            print(f"{Fore.GREEN}▓▓▓ {source.upper()} ▓▓▓{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'—'* (len(source) + 8)}{Style.RESET_ALL}") 
            
            if data is None: 
                print(f"  {Fore.YELLOW}No data returned for this source.{Style.RESET_ALL}")
                print()
                continue
            
            if "error" in data and len(data) == 1: 
                print(f"  {Fore.RED}Error: {data['error']}{Style.RESET_ALL}")
            elif source == "GitHub Repos/Users":
                self.display_github_results(data)
            elif source == "Social Media Presence":
                self.display_social_results(data)
            elif source == "Email Address Analysis":
                self.display_email_results(data)
            else: 
                self.display_generic_results(data)
            
            print() 
    
    def display_github_results(self, data: Dict[str, Any]):
        """Display GitHub results"""
        if data.get("error"):
            print(f"  {Fore.RED}Error in GitHub search: {data['error']}{Style.RESET_ALL}")
            return

        users = data.get("users", [])
        if users:
            print(f"  {Fore.YELLOW}👤 Users Found:{Style.RESET_ALL}")
            for user in users:
                print(f"    • {Fore.CYAN}{user.get('username', 'N/A')}{Style.RESET_ALL} - {user.get('profile_url', 'N/A')}")
        else:
            print(f"  {Fore.WHITE}No users found matching the query.{Style.RESET_ALL}")
        
        print() 
        repositories = data.get("repositories", [])
        if repositories:
            print(f"  {Fore.YELLOW}📁 Repositories Found:{Style.RESET_ALL}")
            for repo in repositories:
                print(f"    • {Fore.CYAN}{repo.get('full_name', repo.get('name', 'N/A'))}{Style.RESET_ALL} ({repo.get('language', 'N/A')})")
                print(f"      URL: {repo.get('url', 'N/A')}")
                print(f"      ⭐ Stars: {repo.get('stars', 'N/A')}")
                if repo.get('description'):
                    print(f"      Desc: {str(repo['description'])[:100]}...") 
        else:
            print(f"  {Fore.WHITE}No repositories found matching the query.{Style.RESET_ALL}")
    
    def display_social_results(self, data: Dict[str, Any]):
        """Display social media results"""
        if not data:
            print(f"  {Fore.WHITE}No social media checks performed or no data returned.{Style.RESET_ALL}")
            return

        for platform, info in data.items():
            if not isinstance(info, dict): 
                print(f"  {Fore.RED}✗ {platform.capitalize()}: Invalid data format received.{Style.RESET_ALL}")
                continue

            platform_name = platform.replace("_", " ").capitalize()
            if info.get("exists") is True: 
                print(f"  {Fore.GREEN}✓ {platform_name}:{Style.RESET_ALL} Profile potentially found at {Fore.CYAN}{info.get('url', 'N/A')}{Style.RESET_ALL}")
                if info.get("status"): print(f"    Status: {info['status']}")
            elif info.get("exists") is False: 
                print(f"  {Fore.RED}✗ {platform_name}:{Style.RESET_ALL} Profile likely not found or issue checking.")
                if info.get("url"): print(f"    Attempted URL: {Fore.CYAN}{info['url']}{Style.RESET_ALL}")
                if info.get("status"): print(f"    Status: {info['status']}")
                if info.get("search_url"): print(f"    Search instead: {Fore.YELLOW}{info['search_url']}{Style.RESET_ALL}")
            elif info.get("search_url"):
                print(f"  {Fore.YELLOW}? {platform_name}:{Style.RESET_ALL} Search at {Fore.CYAN}{info['search_url']}{Style.RESET_ALL}")
            else: 
                 print(f"  {Fore.WHITE}- {platform_name}:{Style.RESET_ALL} No specific finding or direct check not performed.")

            if info.get("note"):
                print(f"    {Fore.MAGENTA}Note: {info['note']}{Style.RESET_ALL}")
    
    def display_email_results(self, data: Dict[str, Any]):
        """Display email analysis results"""
        if not data:
            print(f"  {Fore.WHITE}No email analysis data returned.{Style.RESET_ALL}")
            return

        is_valid_format = data.get('format_validation', False)
        print(f"  {Fore.YELLOW}✉️ Email Format Validation: {Fore.GREEN if is_valid_format else Fore.RED}{'Valid' if is_valid_format else 'Invalid'}{Style.RESET_ALL}")

        domain_info = data.get("domain_info", {})
        if domain_info:
            if domain_info.get("error"):
                 print(f"  {Fore.RED}Domain Analysis Error: {domain_info['error']}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}Domain: {Fore.CYAN}{domain_info.get('domain', 'N/A')}{Style.RESET_ALL}")
                print(f"    Host Resolves (A/AAAA): {'✓ Yes' if domain_info.get('host_resolves') else '✗ No / Error'}")
                print(f"    Common Provider: {'✓ Yes' if domain_info.get('common_provider') else '✗ No'}")
        
        if data.get("breach_check_note"):
            print(f"  {Fore.YELLOW}🛡️ Data Breaches: {Fore.WHITE}{data['breach_check_note']}{Style.RESET_ALL}")
    
    def display_generic_results(self, data: Dict[str, Any]):
        """Display generic results (e.g., for Web search, Pastebin)"""
        if not data:
            print(f"  {Fore.WHITE}No data returned for this source.{Style.RESET_ALL}")
            return
            
        for key, value in data.items():
            if isinstance(value, dict): 
                print(f"  {Fore.YELLOW}{key.replace('_', ' ').capitalize()}:{Style.RESET_ALL}")
                for subkey, subvalue in value.items():
                    print(f"    {subkey.replace('_', ' ').capitalize()}: {Fore.CYAN}{subvalue}{Style.RESET_ALL}")
            elif isinstance(value, bool):
                print(f"  {Fore.YELLOW}{key.replace('_', ' ').capitalize()}: {Fore.GREEN if value else Fore.RED}{value}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}{key.replace('_', ' ').capitalize()}: {Fore.CYAN}{value}{Style.RESET_ALL}")
    
    def save_results(self, filename: str):
        """Save results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False) 
            self.print_status(f"Results saved to: {filename}", "success")
        except IOError as e: 
            self.print_status(f"Could not save file: {str(e)}", "error")
        except Exception as e:
            self.print_status(f"An unexpected error occurred while saving file: {str(e)}", "error")

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Tool - Multi-Source Intelligence Gatherer. Gathers open-source intelligence from various sources.",
        formatter_class=argparse.RawTextHelpFormatter, 
        epilog="""
Examples:
  python %(prog)s -q "john.doe@example.com"
  python %(prog)s -q "johndoe" -t social
  python %(prog)s -q "John Doe" -t all -o results.json
  python %(prog)s -q "projectXYZ" -t github -o project_xyz_github.json

Search Types:
  all       : Perform all available searches relevant to the query type.
  github    : Search GitHub for users and repositories.
  social    : Check various social media platforms.
  email     : Analyze an email address (if query is an email).
  pastebin  : Provide search links for Pastebin and similar sites.
  web       : Perform a general web search using DuckDuckGo.
        """
    )
    
    parser.add_argument('-q', '--query', required=True, 
                       help='Search term (e.g., name, email, username, keyword)')
    parser.add_argument('-t', '--type', choices=['all', 'github', 'social', 'email', 'pastebin', 'web'],
                       default='all', help='Type of search to perform (default: all)')
    parser.add_argument('-o', '--output', metavar="FILENAME",
                        help='Save results to a JSON file (e.g., results.json)')
    parser.add_argument('--no-banner', action='store_true', help='Suppress the startup banner display')
    
    args = parser.parse_args()
    
    osint_tool = OSINTTool()
    
    if not args.no_banner:
        osint_tool.print_banner()
    
    try:
        osint_tool.run_search(args.query, args.type)
        osint_tool.display_results()
        
        if args.output:
            osint_tool.save_results(args.output)
        
        print(f"\n{Fore.GREEN}✓ Search process completed!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠  False positives do occur - remember to manually verify all information found .{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠  Use this tool responsibly and ethically, respecting privacy and applicable laws.{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}✗ Search aborted by user.{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        osint_tool.print_status(f"An unexpected critical error occurred: {str(e)}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
