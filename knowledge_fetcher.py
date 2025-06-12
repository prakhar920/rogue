#!/usr/bin/env python3
"""
Knowledge Fetcher for Rogue Security Scanner
Fetches and parses security knowledge from expert sources before scanning
"""

import requests
from bs4 import BeautifulSoup
import time
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
import logging

class SecurityKnowledgeBase:
    """
    Fetches and maintains a knowledge base of security testing techniques
    from expert sources like PentestMonkey, CAPEC, and OWASP WSTG
    """
    
    def __init__(self):
        self.knowledge = {
            "exploit_techniques": [],
            "payloads": [],
            "pentestmonkey_cheatsheets": [],
            "capec_attack_patterns": [],
            "owasp_wstg_techniques": [],
            "last_updated": None
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; RogueSecurityScanner/1.0; +https://github.com/rogue-scanner)'
        })
        
    def fetch_pentestmonkey_cheatsheets(self) -> List[Dict]:
        """Fetch cheat sheets from PentestMonkey"""
        print("[Info] 🐒 Fetching PentestMonkey cheat sheets...")
        base_url = "https://pentestmonkey.net/category/cheat-sheet"
        cheatsheets = []
        try:
            resp = self.session.get(base_url, timeout=15)
            soup = BeautifulSoup(resp.content, 'html.parser')
            for a in soup.select('div.post h2 a'):
                title = a.get_text(strip=True)
                url = a['href']
                if not url.startswith('http'):
                    url = urljoin(base_url, url)
                
                # Simplified the filter to be more robust
                if 'cheat-sheet' in url:
                    try:
                        art_resp = self.session.get(url, timeout=10)
                        art_soup = BeautifulSoup(art_resp.content, 'html.parser')
                        content = art_soup.find('div', class_='entryContent')
                        if content:
                            text = content.get_text("\n", strip=True)
                            cheatsheets.append({
                                'title': title,
                                'url': url,
                                'content': text[:3000]
                            })
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"[Warning] Failed to fetch cheat sheet {title}: {e}")
                        continue
            print(f"[Info] ✅ Fetched {len(cheatsheets)} PentestMonkey cheat sheets")
        except Exception as e:
            print(f"[Warning] Failed to fetch PentestMonkey cheat sheets: {e}")
        return cheatsheets

    def fetch_capec_patterns(self) -> List[Dict]:
        """Fetch attack patterns from CAPEC-513 and related patterns"""
        print("[Info] 🏛️ Fetching CAPEC-513 and related attack patterns...")
        base_url = "https://capec.mitre.org/data/definitions/513.html"
        patterns = []
        try:
            resp = self.session.get(base_url, timeout=15)
            soup = BeautifulSoup(resp.content, 'html.parser')
            title = soup.find('h2')
            desc = soup.find('div', class_='summary')
            patterns.append({
                'title': title.get_text(strip=True) if title else 'CAPEC-513',
                'url': base_url,
                'description': desc.get_text("\n", strip=True)[:2000] if desc else ''
            })
            # Find related patterns (HasMember links)
            for a in soup.find_all('a', href=True):
                if '/data/definitions/' in a['href'] and a['href'] != '/data/definitions/513.html':
                    rel_url = urljoin(base_url, a['href'])
                    rel_title = a.get_text(strip=True)
                    try:
                        rel_resp = self.session.get(rel_url, timeout=10)
                        rel_soup = BeautifulSoup(rel_resp.content, 'html.parser')
                        rel_desc = rel_soup.find('div', class_='summary')
                        patterns.append({
                            'title': rel_title,
                            'url': rel_url,
                            'description': rel_desc.get_text("\n", strip=True)[:2000] if rel_desc else ''
                        })
                        if len(patterns) >= 10:
                            break
                        time.sleep(0.5)
                    except Exception as e:
                        print(f"[Warning] Failed to fetch CAPEC pattern {rel_title}: {e}")
                        continue
            print(f"[Info] ✅ Fetched {len(patterns)} CAPEC attack patterns")
        except Exception as e:
            print(f"[Warning] Failed to fetch CAPEC-513: {e}")
        return patterns

    def fetch_owasp_wstg_techniques(self) -> List[Dict]:
        """Fetch testing techniques from OWASP WSTG and crawl subpages"""
        print("[Info] 🕸️ Fetching OWASP WSTG techniques...")
        base_url = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
        techniques = []
        try:
            resp = self.session.get(base_url, timeout=15)
            soup = BeautifulSoup(resp.content, 'html.parser')
            # Main page summary
            main_title = soup.find('h1')
            main_desc = soup.find('div', class_='content')
            techniques.append({
                'title': main_title.get_text(strip=True) if main_title else 'OWASP WSTG',
                'url': base_url,
                'description': main_desc.get_text("\n", strip=True)[:2000] if main_desc else ''
            })
            # Crawl subpages (subsection links)
            sub_links = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/') and a['href'] != '/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/']
            sub_links = list(dict.fromkeys(sub_links))  # Deduplicate
            for sub in sub_links[:15]:
                sub_url = urljoin('https://owasp.org', sub)
                try:
                    sub_resp = self.session.get(sub_url, timeout=10)
                    sub_soup = BeautifulSoup(sub_resp.content, 'html.parser')
                    sub_title = sub_soup.find('h1')
                    sub_desc = sub_soup.find('div', class_='content')
                    techniques.append({
                        'title': sub_title.get_text(strip=True) if sub_title else sub_url,
                        'url': sub_url,
                        'description': sub_desc.get_text("\n", strip=True)[:2000] if sub_desc else ''
                    })
                    time.sleep(0.5)
                except Exception as e:
                    print(f"[Warning] Failed to fetch OWASP WSTG subpage {sub_url}: {e}")
                    continue
            print(f"[Info] ✅ Fetched {len(techniques)} OWASP WSTG techniques")
        except Exception as e:
            print(f"[Warning] Failed to fetch OWASP WSTG: {e}")
        return techniques
    
    def fetch_all_knowledge(self):
        print("[Info] 🧠 Building security knowledge base...")
        self.knowledge["pentestmonkey_cheatsheets"] = self.fetch_pentestmonkey_cheatsheets()
        self.knowledge["capec_attack_patterns"] = self.fetch_capec_patterns()
        self.knowledge["owasp_wstg_techniques"] = self.fetch_owasp_wstg_techniques()
        self._compile_techniques_and_payloads()
        self.knowledge["last_updated"] = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[Info] ✅ Knowledge base updated with {len(self.knowledge['pentestmonkey_cheatsheets'])} PentestMonkey cheat sheets, {len(self.knowledge['capec_attack_patterns'])} CAPEC patterns, {len(self.knowledge['owasp_wstg_techniques'])} OWASP WSTG techniques")
    
    def _compile_techniques_and_payloads(self):
        """Compile techniques and payloads from all sources"""
        techniques = []
        payloads = []

        # From PentestMonkey cheat sheets
        for cheat in self.knowledge.get("pentestmonkey_cheatsheets", []):
            if 'content' in cheat:
                # Extract command lines and code blocks as payloads
                payloads.extend(re.findall(r'\b\w+ [^\n]+', cheat['content'])[:10])
        # From CAPEC attack patterns
        for pattern in self.knowledge.get("capec_attack_patterns", []):
            if 'techniques' in pattern:
                techniques.extend(pattern['techniques'])
            if 'example_instances' in pattern:
                payloads.extend(pattern['example_instances'])
        # From OWASP WSTG techniques
        for technique in self.knowledge.get("owasp_wstg_techniques", []):
            if 'test_steps' in technique:
                techniques.extend(technique['test_steps'])
            if 'example_payloads' in technique:
                payloads.extend(technique['example_payloads'])
        
        # Deduplicate
        techniques = list(set(techniques))
        payloads = list(set(payloads))
        
        self.knowledge["exploit_techniques"] = techniques
        self.knowledge["payloads"] = payloads
    
    def get_knowledge_summary(self) -> str:
        """Generate a concise summary of all gathered security knowledge"""
        summary = "🧠 Security Knowledge Summary\n\n"

        # PentestMonkey Cheat Sheets
        if self.knowledge.get("pentestmonkey_cheatsheets"):
            summary += "### 🐒 PentestMonkey Cheat Sheets:\n"
            for cheat in self.knowledge["pentestmonkey_cheatsheets"]:
                summary += f"- {cheat['title']}\n"
            summary += "\n"
        
        # CAPEC Attack Patterns
        if self.knowledge.get("capec_attack_patterns"):
            summary += "### 🎯 CAPEC Attack Patterns:\n"
            for pattern in self.knowledge["capec_attack_patterns"]:
                summary += f"- {pattern['title']}\n"
            summary += "\n"
        
        # OWASP WSTG Techniques
        if self.knowledge.get("owasp_wstg_techniques"):
            summary += "### 🔍 OWASP WSTG Techniques:\n"
            for technique in self.knowledge["owasp_wstg_techniques"]:
                summary += f"- {technique['title']}\n"
            summary += "\n"
        
        # Aggregated techniques and payloads
        summary += f"### 🛠️ Total Unique Techniques: {len(self.knowledge['exploit_techniques'])}\n"
        summary += f"### 🎯 Total Unique Payloads: {len(self.knowledge['payloads'])}\n"
        
        return summary

def initialize_knowledge_base() -> SecurityKnowledgeBase:
    """Initialize and populate the security knowledge base"""
    print("[Info] 🧠 Building security knowledge base...")
    
    kb = SecurityKnowledgeBase()
    kb.fetch_all_knowledge()
    
    return kb 