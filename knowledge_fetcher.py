#!/usr/bin/env python3
"""
Knowledge Fetcher for Rogue Security Scanner
Fetches and parses security knowledge from expert sources before scanning
"""

import requests
from bs4 import BeautifulSoup
import time
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
import logging

class SecurityKnowledgeBase:
    """
    Fetches and maintains a knowledge base of security testing techniques
    from expert sources like DevSec Blog and PortSwigger Web Security Academy
    """
    
    def __init__(self):
        self.knowledge = {
            "web_api_vulnerabilities": [],
            "portswigger_labs": [],
            "cisa_kev_web_vulns": []
        }
        
    def build_knowledge_base(self):
        """
        Build the complete security knowledge base by fetching from all sources
        """
        print("[Info] 🧠 Building security knowledge base...")
        
        # Fetch DevSec Blog articles
        print("[Info] 📚 Fetching Web API security knowledge from DevSec Blog...")
        try:
            self._fetch_devsec_articles()
            print(f"[Info] ✅ Fetched {len(self.knowledge['web_api_vulnerabilities'])} DevSec articles")
        except Exception as e:
            print(f"[Warning] Failed to fetch DevSec knowledge: {e}")
            
        # Fetch PortSwigger labs
        print("[Info] 🧪 Fetching lab knowledge from PortSwigger Web Security Academy...")
        try:
            self._fetch_portswigger_labs()
            print(f"[Info] ✅ Fetched {len(self.knowledge['portswigger_labs'])} lab categories")
        except Exception as e:
            print(f"[Warning] Failed to fetch PortSwigger knowledge: {e}")
            
        # Fetch CISA KEV vulnerabilities
        print("[Info] 🏛️ Fetching CISA KEV web vulnerabilities...")
        try:
            self._fetch_cisa_kev_web_vulns()
            print(f"[Info] ✅ Fetched {len(self.knowledge['cisa_kev_web_vulns'])} CISA KEV vulnerabilities")
        except Exception as e:
            print(f"[Warning] Failed to fetch CISA KEV knowledge: {e}")
            
        print(f"[Info] ✅ Knowledge base updated with {len(self.knowledge['web_api_vulnerabilities'])} API articles, {len(self.knowledge['portswigger_labs'])} lab categories, and {len(self.knowledge['cisa_kev_web_vulns'])} CISA KEV web vulnerabilities")
    
    def _fetch_devsec_articles(self):
        """Fetch security articles from DevSec Blog"""
        articles_data = [
            {
                "url": "https://blog.devsecurely.com/p/broken-function-level-authorization",
                "title": "Broken Function Level Authorization — Web API Security Champion Part V"
            },
            {
                "url": "https://blog.devsecurely.com/p/unrestricted-resource-consumption",
                "title": "Unrestricted Resource Consumption in a Password Reset — Web API Security Champion Part IV"
            },
            {
                "url": "https://blog.devsecurely.com/p/web-api-security-champion-part-iii",
                "title": "Web API Security Champion Part III: Broken Object Property Level Authorization (OWASP TOP 10)"
            },
            {
                "url": "https://blog.devsecurely.com/p/web-api-security-champion-part-ii",
                "title": "Web API Security Champion Part II: Broken Authentication (OWASP TOP 10)"
            },
            {
                "url": "https://blog.devsecurely.com/p/web-api-security-champion-broken",
                "title": "Web API Security Champion: Broken Object Level Authorization (OWASP TOP 10)"
            },
            {
                "url": "https://blog.devsecurely.com/p/security-code-challenge-for-developers",
                "title": "Security Code Challenge for Developers & Ethical Hackers – The Damn Vulnerable RESTaurant"
            }
        ]
        
        for article in articles_data:
            print(f"[Info] 📖 Reading: {article['title']}")
            try:
                content = self._fetch_article_content(article['url'])
                if content:
                    self.knowledge["web_api_vulnerabilities"].append({
                        "title": article['title'],
                        "url": article['url'],
                        "content": content
                    })
                time.sleep(1)  # Be respectful to the server
            except Exception as e:
                print(f"[Warning] Failed to fetch {article['title']}: {e}")
    
    def _fetch_article_content(self, url: str) -> str:
        """Fetch and extract main content from a DevSec blog article"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract main content from various possible containers
            content_selectors = [
                'article',
                '.post-content',
                '.entry-content', 
                '.content',
                'main',
                '[data-testid="post-content"]'
            ]
            
            content = ""
            for selector in content_selectors:
                element = soup.select_one(selector)
                if element:
                    content = element.get_text(strip=True)
                    break
            
            # Fallback: get all paragraphs if no main container found
            if not content:
                paragraphs = soup.find_all('p')
                content = ' '.join([p.get_text(strip=True) for p in paragraphs[:10]])
            
            return content[:2000]  # Limit content length
            
        except Exception as e:
            print(f"Error fetching article content: {e}")
            return ""
    
    def _fetch_portswigger_labs(self):
        """Fetch PortSwigger Web Security Academy lab information"""
        lab_categories = [
            "sql-injection", "cross-site-scripting", "authentication",
            "path-traversal", "command-injection", "business-logic",
            "access-control", "ssrf", "xxe", "nosql-injection", "api-testing"
        ]
        
        for category in lab_categories:
            print(f"[Info] 📚 Learning {category} techniques...")
            try:
                labs = self._fetch_category_labs(category)
                if labs:
                    self.knowledge["portswigger_labs"].append({
                        "category": category,
                        "labs": labs
                    })
                time.sleep(1)  # Be respectful
            except Exception as e:
                print(f"[Warning] Failed to fetch {category} labs: {e}")
    
    def _fetch_category_labs(self, category: str) -> List[Dict]:
        """Fetch labs for a specific category from PortSwigger"""
        try:
            url = f"https://portswigger.net/web-security/{category}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            labs = []
            # Look for lab links and descriptions
            lab_links = soup.find_all('a', href=re.compile(r'/web-security/.*?/lab-'))
            
            for link in lab_links[:5]:  # Limit to 5 labs per category
                title = link.get_text(strip=True)
                if title and len(title) > 10:  # Filter out empty or too short titles
                    labs.append({
                        "title": title,
                        "url": urljoin(url, link.get('href', '')),
                        "category": category
                    })
            
            return labs
            
        except Exception as e:
            print(f"Error fetching {category} labs: {e}")
            return []
    
    def _fetch_cisa_kev_web_vulns(self):
        """Fetch web-related vulnerabilities from CISA KEV catalog"""
        try:
            # CISA KEV catalog JSON endpoint
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            
            # Filter for web-related vulnerabilities
            web_keywords = [
                'web', 'http', 'sql injection', 'xss', 'cross-site', 'remote code execution',
                'directory traversal', 'file inclusion', 'upload', 'authentication bypass',
                'session', 'cookie', 'csrf', 'deserialization', 'template injection'
            ]
            
            web_vulns = []
            for vuln in data.get('vulnerabilities', []):
                description = vuln.get('vulnerabilityName', '').lower()
                if any(keyword in description for keyword in web_keywords):
                    web_vulns.append({
                        "cve_id": vuln.get('cveID'),
                        "name": vuln.get('vulnerabilityName'),
                        "description": vuln.get('shortDescription', ''),
                        "date_added": vuln.get('dateAdded'),
                        "required_action": vuln.get('requiredAction', '')
                    })
                    
                    if len(web_vulns) >= 20:  # Limit to 20 most relevant
                        break
            
            self.knowledge["cisa_kev_web_vulns"] = web_vulns
            
        except Exception as e:
            print(f"Error fetching CISA KEV data: {e}")
    
    def get_knowledge_summary(self) -> str:
        """
        Generate a comprehensive summary of the security knowledge base
        for use in LLM prompts
        """
        summary_parts = []
        
        # DevSec Blog API Security Knowledge
        if self.knowledge["web_api_vulnerabilities"]:
            summary_parts.append("## Web API Security Knowledge (DevSec Blog)")
            summary_parts.append("Advanced techniques for testing web APIs and modern applications:")
            
            for article in self.knowledge["web_api_vulnerabilities"]:
                summary_parts.append(f"- **{article['title']}**")
                if article.get('content'):
                    # Extract key points from content
                    content_preview = article['content'][:300] + "..."
                    summary_parts.append(f"  {content_preview}")
        
        # PortSwigger Lab Knowledge
        if self.knowledge["portswigger_labs"]:
            summary_parts.append("\n## PortSwigger Web Security Academy Techniques")
            summary_parts.append("Proven exploitation techniques from hands-on security labs:")
            
            for category_data in self.knowledge["portswigger_labs"]:
                category = category_data['category'].replace('-', ' ').title()
                labs = category_data.get('labs', [])
                summary_parts.append(f"- **{category}**: {len(labs)} advanced techniques")
                
                # Include specific lab examples
                for lab in labs[:2]:  # Show first 2 labs as examples
                    summary_parts.append(f"  • {lab['title']}")
        
        # CISA KEV Web Vulnerabilities
        if self.knowledge["cisa_kev_web_vulns"]:
            summary_parts.append("\n## Critical Web Vulnerabilities (CISA KEV)")
            summary_parts.append("Known exploited vulnerabilities actively being used by attackers:")
            
            for vuln in self.knowledge["cisa_kev_web_vulns"][:5]:  # Show top 5
                summary_parts.append(f"- **{vuln['cve_id']}**: {vuln['name']}")
                if vuln.get('description'):
                    summary_parts.append(f"  {vuln['description']}")
        
        # Usage guidance
        summary_parts.append("\n## Testing Guidance")
        summary_parts.append("When generating security test plans:")
        summary_parts.append("- Prioritize techniques proven successful in real-world exploitation")
        summary_parts.append("- Focus on vulnerabilities currently being exploited (CISA KEV)")
        summary_parts.append("- Use modern attack vectors for web APIs and complex applications")
        summary_parts.append("- Combine multiple techniques for comprehensive coverage")
        summary_parts.append("- Always verify exploitability with concrete proof-of-concept")
        
        return "\n".join(summary_parts)


def initialize_knowledge_base() -> SecurityKnowledgeBase:
    """
    Initialize and build the security knowledge base
    
    Returns:
        SecurityKnowledgeBase: Populated knowledge base instance
    """
    kb = SecurityKnowledgeBase()
    kb.build_knowledge_base()
    return kb 