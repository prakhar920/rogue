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
            "cisa_kev_web_vulns": [],
            "exploit_techniques": [],
            "payloads": [],
            "last_updated": None
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; RogueSecurityScanner/1.0; +https://github.com/rogue-scanner)'
        })
        
    def fetch_devsec_api_knowledge(self) -> List[Dict]:
        """Fetch Web API Security Champion articles from DevSec Blog"""
        print("[Info] 📚 Fetching Web API security knowledge from DevSec Blog...")
        
        base_url = "https://devsec-blog.com/tag/web-api-security-champion/"
        api_knowledge = []
        
        try:
            response = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find article links
            article_links = []
            for article in soup.find_all('article'):
                title_elem = article.find('h3') or article.find('h2')
                if title_elem:
                    link_elem = title_elem.find('a')
                    if link_elem and link_elem.get('href'):
                        article_links.append({
                            'title': title_elem.get_text().strip(),
                            'url': urljoin(base_url, link_elem['href'])
                        })
            
            # Fetch each article's content
            for article in article_links[:6]:  # Limit to avoid overwhelming
                print(f"[Info] 📖 Reading: {article['title']}")
                try:
                    article_response = self.session.get(article['url'], timeout=10)
                    article_soup = BeautifulSoup(article_response.content, 'html.parser')
                    
                    # Extract main content
                    content_elem = article_soup.find('div', class_='post-content') or article_soup.find('article')
                    if content_elem:
                        content = content_elem.get_text().strip()
                        
                        api_knowledge.append({
                            'title': article['title'],
                            'url': article['url'],
                            'content': content[:3000],  # Limit content length
                            'vulnerability_type': self._extract_vulnerability_type(article['title']),
                            'key_techniques': self._extract_techniques(content)
                        })
                        
                    time.sleep(1)  # Be respectful to the server
                    
                except Exception as e:
                    print(f"[Warning] Failed to fetch article {article['title']}: {e}")
                    continue
                    
        except Exception as e:
            print(f"[Warning] Failed to fetch DevSec knowledge: {e}")
            
        return api_knowledge
    
    def fetch_portswigger_lab_knowledge(self) -> List[Dict]:
        """Fetch lab techniques from PortSwigger Web Security Academy"""
        print("[Info] 🧪 Fetching lab knowledge from PortSwigger Web Security Academy...")
        
        base_url = "https://portswigger.net/web-security"
        lab_knowledge = []
        
        # Key vulnerability categories to focus on
        vuln_categories = [
            'sql-injection',
            'cross-site-scripting',
            'authentication',
            'path-traversal', 
            'command-injection',
            'business-logic',
            'access-control',
            'ssrf',
            'xxe',
            'nosql-injection',
            'api-testing'
        ]
        
        for category in vuln_categories:
            try:
                category_url = f"{base_url}/{category}"
                print(f"[Info] 📚 Learning {category} techniques...")
                
                response = self.session.get(category_url, timeout=10)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Extract key techniques and payloads
                techniques = []
                payloads = []
                
                # Look for code blocks, examples, and technique descriptions
                for code_block in soup.find_all(['code', 'pre']):
                    code_text = code_block.get_text().strip()
                    if len(code_text) > 10 and len(code_text) < 200:
                        if any(keyword in code_text.lower() for keyword in ['select', 'union', 'script', 'alert', 'payload', 'exploit']):
                            payloads.append(code_text)
                
                # Extract technique descriptions
                for p in soup.find_all('p'):
                    text = p.get_text().strip()
                    if len(text) > 50 and any(keyword in text.lower() for keyword in ['vulnerability', 'exploit', 'attack', 'injection']):
                        techniques.append(text[:300])
                
                lab_knowledge.append({
                    'category': category,
                    'url': category_url,
                    'techniques': techniques[:5],  # Top 5 techniques
                    'payloads': payloads[:10],     # Top 10 payloads
                    'description': f"Security testing techniques for {category.replace('-', ' ')}"
                })
                
                time.sleep(1)  # Be respectful to the server
                
            except Exception as e:
                print(f"[Warning] Failed to fetch {category} knowledge: {e}")
                continue
                
        return lab_knowledge
    
    def fetch_cisa_kev_web_vulnerabilities(self) -> List[Dict]:
        """Fetch web-related vulnerabilities from CISA Known Exploited Vulnerabilities catalog"""
        print("[Info] 🏛️ Fetching CISA KEV web vulnerabilities...")
        
        # Use the provided web search results data instead of scraping
        # This contains the real CISA KEV data
        kev_web_vulns = []
        
        # Web-focused CVEs from CISA KEV with detailed analysis
        web_cves = [
            {
                'cve_id': 'CVE-2025-35939',
                'title': 'Craft CMS Session File Arbitrary Content Storage RCE',
                'description': 'Craft CMS stores arbitrary content provided by unauthenticated users in session files. This content could be accessed and executed, possibly using an independent vulnerability.',
                'cvss_score': 6.9,
                'exploit_techniques': [
                    'Session file poisoning with PHP code injection',
                    'Leveraging unauthenticated access to store malicious content',
                    'Exploiting session file locations at /var/lib/php/sessions',
                    'Manipulating return URLs to inject PHP payloads'
                ],
                'affected_components': [
                    'Session management system',
                    'Login redirect functionality', 
                    'Return URL parameter handling'
                ],
                'payload_patterns': [
                    'PHP code injection in session files',
                    'Malicious return URL crafting',
                    'Session file naming exploitation: sess_[session_value]'
                ],
                'vulnerability_type': 'code_injection'
            },
            {
                'cve_id': 'CVE-2025-3935', 
                'title': 'ScreenConnect ViewState Code Injection',
                'description': 'ScreenConnect versions 25.2.3 and earlier may be susceptible to a ViewState code injection attack when machine keys are compromised.',
                'cvss_score': 8.1,
                'exploit_techniques': [
                    'ViewState deserialization attack',
                    'Machine key exploitation for payload signing',
                    'ASP.NET ViewState manipulation',
                    'Base64 encoded malicious ViewState creation'
                ],
                'affected_components': [
                    'ASP.NET ViewState mechanism',
                    'Web Forms state management',
                    'Machine key validation system'
                ],
                'payload_patterns': [
                    'Malicious ViewState Base64 payloads',
                    'Deserialization gadget chains',
                    'Signed ViewState with compromised machine keys'
                ],
                'vulnerability_type': 'deserialization'
            },
            {
                'cve_id': 'CVE-2024-56145',
                'title': 'Craft CMS Remote Code Execution via register_argc_argv',
                'description': 'Craft CMS remote code execution vector when php.ini has register_argc_argv enabled.',
                'cvss_score': 9.8,
                'exploit_techniques': [
                    'PHP configuration exploitation (register_argc_argv)',
                    'Argument vector manipulation for RCE',
                    'Command line argument injection',
                    'Unauthenticated remote code execution'
                ],
                'affected_components': [
                    'PHP runtime configuration',
                    'Command line argument processing',
                    'CMS core request handling'
                ],
                'payload_patterns': [
                    'Malicious argv parameter injection',
                    'Command execution via argument manipulation',
                    'PHP register_argc_argv exploitation'
                ],
                'vulnerability_type': 'code_injection'
            },
            {
                'cve_id': 'CVE-2023-39780',
                'title': 'ASUS Router OS Command Injection via HTTP Parameter',
                'description': 'ASUS RT-AX55 devices allow authenticated OS command injection via the /start_apply.htm qos_bw_rulelist parameter.',
                'cvss_score': 8.8,
                'exploit_techniques': [
                    'HTTP parameter injection for OS command execution',
                    'QoS configuration parameter abuse',
                    'Router web interface exploitation',
                    'Authenticated command injection attacks'
                ],
                'affected_components': [
                    '/start_apply.htm endpoint',
                    'qos_bw_rulelist parameter',
                    'QoS bandwidth rule configuration'
                ],
                'payload_patterns': [
                    'OS command injection in qos_bw_rulelist',
                    'Parameter pollution for command execution',
                    'Router configuration bypass techniques'
                ],
                'vulnerability_type': 'command_injection'
            },
            {
                'cve_id': 'CVE-2021-32030',
                'title': 'ASUS Router Authentication Bypass via Null Byte',
                'description': 'ASUS router authentication bypass when processing remote input from unauthenticated user. Attacker-supplied \\0 matches device default \\0.',
                'cvss_score': 9.8,
                'exploit_techniques': [
                    'Null byte injection for authentication bypass',
                    'Default value matching exploitation',
                    'Remote unauthenticated access techniques',
                    'HTTP request manipulation for bypass'
                ],
                'affected_components': [
                    'Router authentication system',
                    'Remote access features',
                    'Administrator interface access controls'
                ],
                'payload_patterns': [
                    'Null byte (\\0) injection in auth parameters',
                    'Default value matching attacks',
                    'Authentication bypass via parameter manipulation'
                ],
                'vulnerability_type': 'authentication_bypass'
            },
            {
                'cve_id': 'CVE-2024-27443',
                'title': 'Zimbra Collaboration XSS in CalendarInvite',
                'description': 'Cross-Site Scripting vulnerability in CalendarInvite feature due to improper input validation in calendar header handling.',
                'cvss_score': 6.1,
                'exploit_techniques': [
                    'Calendar header XSS injection',
                    'Email-based XSS payload delivery',
                    'Webmail interface exploitation',
                    'Calendar invitation abuse for script execution'
                ],
                'affected_components': [
                    'CalendarInvite feature',
                    'Calendar header processing',
                    'Zimbra webmail classic interface'
                ],
                'payload_patterns': [
                    'XSS payloads in calendar headers',
                    'JavaScript injection via email calendar invites',
                    'HTML email-based XSS vectors'
                ],
                'vulnerability_type': 'xss'
            },
            {
                'cve_id': 'CVE-2023-38950',
                'title': 'ZKTeco BioTime Path Traversal in iclock API',
                'description': 'Path traversal vulnerability in the iclock API allows unauthenticated attackers to read arbitrary files.',
                'cvss_score': 7.5,
                'exploit_techniques': [
                    'API path traversal for file disclosure',
                    'Unauthenticated file system access',
                    'Directory traversal via crafted API requests',
                    'Arbitrary file reading techniques'
                ],
                'affected_components': [
                    'iclock API endpoint',
                    'File access controls',
                    'API authentication mechanisms'
                ],
                'payload_patterns': [
                    '../../../etc/passwd traversal sequences',
                    'Null byte injection with path traversal',
                    'API parameter manipulation for file access'
                ],
                'vulnerability_type': 'path_traversal'
            }
        ]
        
        # Filter and enhance the web CVEs
        web_keywords = ['http', 'web', 'xss', 'sql', 'ssrf', 'csrf', 'injection', 'authentication', 'session', 'cookie', 'parameter', 'api', 'endpoint']
        ignore_keywords = ['kernel', 'system', 'linux', 'memory corruption', 'driver', 'windows dwm', 'gpu', 'chrome v8']
        
        for cve in web_cves:
            # Check if it's web-related and not system-level
            description_lower = cve['description'].lower()
            title_lower = cve['title'].lower()
            
            is_web_related = any(keyword in description_lower or keyword in title_lower for keyword in web_keywords)
            is_system_level = any(keyword in description_lower or keyword in title_lower for keyword in ignore_keywords)
            
            if is_web_related and not is_system_level:
                kev_web_vulns.append(cve)
        
        return kev_web_vulns
    
    def _extract_vulnerability_type(self, title: str) -> str:
        """Extract vulnerability type from article title"""
        title_lower = title.lower()
        
        if 'authorization' in title_lower:
            return 'authorization'
        elif 'authentication' in title_lower:
            return 'authentication'
        elif 'consumption' in title_lower:
            return 'resource_consumption'
        elif 'object' in title_lower:
            return 'object_level_access'
        else:
            return 'general_api_security'
    
    def _extract_techniques(self, content: str) -> List[str]:
        """Extract key security testing techniques from content"""
        techniques = []
        
        # Look for common security testing patterns
        patterns = [
            r'(?:exploit|attack|vulnerability|injection|bypass)[\w\s]{20,100}',
            r'(?:payload|script|query|request)[\w\s]{20,100}',
            r'(?:test|check|verify|validate)[\w\s]{20,100}'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            techniques.extend([match.strip() for match in matches[:3]])
        
        return techniques[:5]  # Return top 5 techniques
    
    def fetch_all_knowledge(self) -> Dict:
        """Fetch knowledge from all sources and compile into knowledge base"""
        print("[Info] 🧠 Building security knowledge base...")
        
        # Fetch from DevSec Blog
        self.knowledge["web_api_vulnerabilities"] = self.fetch_devsec_api_knowledge()
        
        # Fetch from PortSwigger
        self.knowledge["portswigger_labs"] = self.fetch_portswigger_lab_knowledge()
        
        # Fetch CISA KEV web vulnerabilities
        self.knowledge["cisa_kev_web_vulns"] = self.fetch_cisa_kev_web_vulnerabilities()
        
        # Compile exploit techniques and payloads
        self._compile_techniques_and_payloads()
        
        self.knowledge["last_updated"] = time.time()
        
        print(f"[Info] ✅ Knowledge base updated with {len(self.knowledge['web_api_vulnerabilities'])} API articles, {len(self.knowledge['portswigger_labs'])} lab categories, and {len(self.knowledge['cisa_kev_web_vulns'])} CISA KEV web vulnerabilities")
        
        return self.knowledge
    
    def _compile_techniques_and_payloads(self):
        """Compile techniques and payloads from all sources"""
        techniques = []
        payloads = []
        
        # From DevSec articles
        for article in self.knowledge["web_api_vulnerabilities"]:
            techniques.extend(article.get('key_techniques', []))
        
        # From PortSwigger labs
        for lab in self.knowledge["portswigger_labs"]:
            techniques.extend(lab.get('techniques', []))
            payloads.extend(lab.get('payloads', []))
        
        # From CISA KEV web vulnerabilities
        for cve in self.knowledge["cisa_kev_web_vulns"]:
            techniques.extend(cve['exploit_techniques'])
            payloads.extend(cve['payload_patterns'])
        
        self.knowledge["exploit_techniques"] = list(set(techniques))[:20]  # Top 20 unique techniques
        self.knowledge["payloads"] = list(set(payloads))[:30]  # Top 30 unique payloads
    
    def get_knowledge_summary(self) -> str:
        """Get a formatted summary of the knowledge base for LLM consumption"""
        summary = "## 🧠 ADVANCED SECURITY KNOWLEDGE BASE\n\n"
        
        # CISA KEV Web Vulnerabilities (Highest Priority - Known Exploited)
        summary += "### 🚨 CISA KEV Known Exploited Web Vulnerabilities:\n"
        for cve in self.knowledge["cisa_kev_web_vulns"][:4]:  # Top 4 most critical
            summary += f"**{cve['cve_id']}: {cve['title']}** (CVSS: {cve['cvss_score']})\n"
            summary += f"- Type: {cve['vulnerability_type']}\n"
            summary += f"- Affected: {', '.join(cve['affected_components'][:2])}\n"
            summary += f"- Key exploit: {cve['exploit_techniques'][0]}\n"
            summary += f"- Payload pattern: {cve['payload_patterns'][0]}\n\n"
        
        # Web API Vulnerabilities
        summary += "### 🔐 Web API Security Knowledge:\n"
        for article in self.knowledge["web_api_vulnerabilities"][:3]:  # Top 3 articles
            summary += f"**{article['title']}**\n"
            summary += f"- Type: {article['vulnerability_type']}\n"
            summary += f"- Key techniques: {', '.join(article['key_techniques'][:3])}\n\n"
        
        # PortSwigger Lab Techniques  
        summary += "### 🧪 Lab-Proven Techniques:\n"
        for lab in self.knowledge["portswigger_labs"][:5]:  # Top 5 categories
            summary += f"**{lab['category'].replace('-', ' ').title()}**\n"
            if lab['techniques']:
                summary += f"- Techniques: {lab['techniques'][0][:100]}...\n"
            if lab['payloads']:
                summary += f"- Example payload: {lab['payloads'][0]}\n\n"
        
        # Context-Aware Testing Guidance
        summary += "### 🎯 Context-Aware Web Application Testing:\n"
        summary += "**For ASP.NET Applications (like testasp.vulnweb.com):**\n"
        summary += "- Test ViewState manipulation and deserialization attacks\n"
        summary += "- Check for ASP.NET-specific injection vectors (.asp/.aspx endpoints)\n"
        summary += "- Examine RetURL parameters for open redirect vulnerabilities\n"
        summary += "- Test authentication bypasses with null byte injection\n"
        summary += "- Look for path traversal in file handling parameters\n\n"
        
        summary += "**For PHP Applications:**\n"
        summary += "- Test for PHP code injection in session files\n"
        summary += "- Check register_argc_argv exploitation vectors\n"
        summary += "- Examine file inclusion and path traversal vulnerabilities\n"
        summary += "- Test for null byte injection bypasses\n\n"
        
        summary += "**For API Endpoints:**\n"
        summary += "- Test unauthenticated file access via path traversal\n"
        summary += "- Check for command injection in configuration parameters\n"
        summary += "- Examine object-level authorization bypasses\n\n"
        
        # Advanced Exploit Techniques from CISA KEV
        summary += "### ⚡ Advanced Exploit Techniques (CISA KEV):\n"
        unique_techniques = []
        for cve in self.knowledge["cisa_kev_web_vulns"]:
            unique_techniques.extend(cve['exploit_techniques'])
        unique_techniques = list(set(unique_techniques))[:8]
        
        for i, technique in enumerate(unique_techniques, 1):
            summary += f"{i}. {technique}\n"
        
        summary += "\n### 💡 Current Threat Intelligence:\n"
        summary += "- Session poisoning attacks are actively exploited (CVE-2025-35939)\n"
        summary += "- ViewState deserialization is a critical ASP.NET attack vector\n"
        summary += "- Null byte injection remains effective for authentication bypass\n"
        summary += "- Parameter injection in configuration endpoints leads to RCE\n"
        summary += "- Path traversal in APIs often allows unauthenticated file access\n"
        summary += "- XSS via email/calendar features bypasses traditional input filters\n"
        
        return summary

def initialize_knowledge_base() -> SecurityKnowledgeBase:
    """Initialize and fetch the security knowledge base"""
    kb = SecurityKnowledgeBase()
    kb.fetch_all_knowledge()
    return kb 