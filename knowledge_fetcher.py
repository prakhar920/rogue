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
    from expert sources like DevSec Blog and PortSwigger Web Security Academy
    """
    
    def __init__(self):
        self.knowledge = {
            "web_api_vulnerabilities": [],
            "portswigger_labs": [],
            "cisa_kev_web_vulns": [],
            "technology_specific_cves": {},  # New: stores CVEs by technology
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
        
        # Web vulnerability keywords for filtering
        web_vuln_keywords = [
            # Core web vulnerability types
            'sql injection', 'cross-site scripting', 'xss', 'cross-site request forgery', 'csrf',
            'server-side request forgery', 'ssrf', 'remote code execution', 'rce', 'local file inclusion',
            'lfi', 'remote file inclusion', 'rfi', 'path traversal', 'directory traversal',
            'command injection', 'ldap injection', 'xml injection', 'xxe', 'xml external entity',
            'template injection', 'deserialization', 'file upload', 'authentication bypass',
            'authorization bypass', 'privilege escalation', 'session hijacking', 'clickjacking',
            'open redirect', 'information disclosure', 'insecure direct object reference', 'idor',
            
            # Web technologies and components
            'http', 'https', 'web', 'website', 'webapp', 'web application', 'browser', 'javascript',
            'html', 'css', 'ajax', 'json', 'xml', 'rest', 'api', 'soap', 'graphql', 'websocket',
            'cookie', 'session', 'header', 'parameter', 'form', 'input', 'upload', 'download',
            'login', 'authentication', 'authorization', 'oauth', 'jwt', 'token', 'csrf token',
            
            # Web servers and frameworks
            'apache', 'nginx', 'iis', 'tomcat', 'jetty', 'django', 'flask', 'express', 'spring',
            'laravel', 'symfony', 'rails', 'asp.net', 'php', 'jsp', 'servlets', 'cgi',
            'wordpress', 'drupal', 'joomla', 'magento', 'sharepoint', 'confluence', 'jira',
            
            # Network protocols commonly used in web contexts
            'http header', 'url', 'uri', 'endpoint', 'redirect', 'referer', 'user-agent',
            'content-type', 'accept', 'origin', 'host header', 'x-forwarded', 'proxy',
            
            # Common web vulnerability indicators
            'injection', 'bypass', 'traversal', 'execution', 'disclosure', 'exposure',
            'manipulation', 'tampering', 'spoofing', 'forgery', 'hijacking', 'fixation',
            'pollution', 'confusion', 'smuggling', 'splitting', 'poisoning'
        ]
        
        try:
            # Fetch the CISA KEV page
            response = requests.get(
                "https://www.cvedetails.com/cisa-known-exploited-vulnerabilities/kev-1.html",
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                },
                timeout=30
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            vulnerabilities = []
            
            # Find vulnerability entries in the table
            # The page typically has a table with CVE details
            table = soup.find('table', {'class': 'searchresults'}) or soup.find('table')
            
            if not table:
                print("[Warning] Could not find vulnerability table on CISA KEV page")
                return []
            
            rows = table.find_all('tr')[1:]  # Skip header row
            
            for row in rows:
                cells = row.find_all('td')
                if len(cells) < 4:
                    continue
                
                try:
                    # Extract basic CVE information
                    cve_id = cells[0].get_text(strip=True) if cells[0] else ""
                    vendor = cells[1].get_text(strip=True) if len(cells) > 1 else ""
                    product = cells[2].get_text(strip=True) if len(cells) > 2 else ""
                    description = cells[3].get_text(strip=True) if len(cells) > 3 else ""
                    
                    # Check if this is a web-related vulnerability
                    text_to_check = f"{description} {vendor} {product}".lower()
                    is_web_related = any(keyword in text_to_check for keyword in web_vuln_keywords)
                    
                    if not is_web_related or not cve_id.startswith('CVE-'):
                        continue
                    
                    # Extract additional details if available
                    cvss_score = ""
                    if len(cells) > 4:
                        cvss_text = cells[4].get_text(strip=True)
                        # Extract numeric CVSS score
                        import re
                        cvss_match = re.search(r'(\d+\.?\d*)', cvss_text)
                        if cvss_match:
                            cvss_score = cvss_match.group(1)
                    
                    # Determine vulnerability type based on description
                    vuln_type = "Unknown"
                    desc_lower = description.lower()
                    
                    if any(term in desc_lower for term in ['sql injection', 'sqli']):
                        vuln_type = "SQL Injection"
                    elif any(term in desc_lower for term in ['cross-site scripting', 'xss']):
                        vuln_type = "Cross-Site Scripting"
                    elif any(term in desc_lower for term in ['path traversal', 'directory traversal', 'lfi', 'rfi']):
                        vuln_type = "Path Traversal"
                    elif any(term in desc_lower for term in ['command injection', 'code execution', 'rce']):
                        vuln_type = "Remote Code Execution"
                    elif any(term in desc_lower for term in ['csrf', 'cross-site request forgery']):
                        vuln_type = "Cross-Site Request Forgery"
                    elif any(term in desc_lower for term in ['ssrf', 'server-side request forgery']):
                        vuln_type = "Server-Side Request Forgery"
                    elif any(term in desc_lower for term in ['authentication bypass', 'auth bypass']):
                        vuln_type = "Authentication Bypass"
                    elif any(term in desc_lower for term in ['file upload', 'upload']):
                        vuln_type = "File Upload"
                    elif any(term in desc_lower for term in ['information disclosure', 'data exposure']):
                        vuln_type = "Information Disclosure"
                    
                    # Generate basic exploit techniques based on vulnerability type
                    exploit_techniques = []
                    if vuln_type == "SQL Injection":
                        exploit_techniques = [
                            "Test with single quote (') to trigger SQL errors",
                            "Use UNION SELECT statements for data extraction",
                            "Try boolean-based blind injection with OR/AND conditions",
                            "Test time-based blind injection with WAITFOR DELAY",
                            "Look for error-based injection opportunities"
                        ]
                    elif vuln_type == "Cross-Site Scripting":
                        exploit_techniques = [
                            "Test with <script>alert(1)</script> payload",
                            "Try event handlers like onload, onerror, onclick",
                            "Test with HTML entity encoding and URL encoding",
                            "Look for DOM-based XSS in client-side JavaScript",
                            "Test stored XSS in user input fields"
                        ]
                    elif vuln_type == "Path Traversal":
                        exploit_techniques = [
                            "Use ../ sequences to traverse directories",
                            "Try null byte injection (%00) to bypass filters",
                            "Test with URL encoding (%2e%2e%2f)",
                            "Attempt to access /etc/passwd or C:\\windows\\win.ini",
                            "Test different path separators (/, \\)"
                        ]
                    elif vuln_type == "Remote Code Execution":
                        exploit_techniques = [
                            "Identify injection points in user input",
                            "Test command chaining with ;, &&, ||",
                            "Try system commands like whoami, id, dir",
                            "Look for file upload functionality",
                            "Test template injection payloads"
                        ]
                    
                    vulnerability = {
                        "cve_id": cve_id,
                        "description": description,
                        "vendor": vendor,
                        "product": product,
                        "vulnerability_type": vuln_type,
                        "cvss_score": cvss_score,
                        "exploit_techniques": exploit_techniques,
                        "affected_components": [product] if product else [],
                        "payload_patterns": self._generate_payload_patterns(vuln_type),
                        "testing_guidance": f"Focus on {vuln_type.lower()} testing in {product} applications"
                    }
                    
                    vulnerabilities.append(vulnerability)
                    
                    # Limit to prevent overwhelming the knowledge base
                    if len(vulnerabilities) >= 20:
                        break
                        
                except Exception as e:
                    print(f"[Warning] Error parsing CVE row: {e}")
                    continue
            
            print(f"[Info] Successfully parsed {len(vulnerabilities)} web-related CVEs from CISA KEV")
            return vulnerabilities
            
        except requests.RequestException as e:
            print(f"[Warning] Failed to fetch CISA KEV data: {e}")
            print("[Info] Using fallback web vulnerability patterns...")
            
            # Fallback: return some common web vulnerability patterns for testing
            return [
                {
                    "cve_id": "FALLBACK-001",
                    "description": "Common SQL injection vulnerability pattern",
                    "vendor": "Various",
                    "product": "Web Applications",
                    "vulnerability_type": "SQL Injection",
                    "cvss_score": "7.5",
                    "exploit_techniques": [
                        "Test with single quote (') to trigger SQL errors",
                        "Use UNION SELECT statements for data extraction",
                        "Try boolean-based blind injection with OR/AND conditions"
                    ],
                    "affected_components": ["Database queries", "Login forms", "Search functionality"],
                    "payload_patterns": ["'", "' OR 1=1--", "' UNION SELECT NULL--"],
                    "testing_guidance": "Focus on input parameters that interact with databases"
                },
                {
                    "cve_id": "FALLBACK-002", 
                    "description": "Cross-site scripting vulnerability pattern",
                    "vendor": "Various",
                    "product": "Web Applications",
                    "vulnerability_type": "Cross-Site Scripting",
                    "cvss_score": "6.1",
                    "exploit_techniques": [
                        "Test with <script>alert(1)</script> payload",
                        "Try event handlers like onload, onerror",
                        "Test with HTML entity encoding"
                    ],
                    "affected_components": ["User input forms", "URL parameters", "Comment sections"],
                    "payload_patterns": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                    "testing_guidance": "Focus on any user-controllable output in HTML context"
                }
            ]
        
        except Exception as e:
            print(f"[Error] Unexpected error fetching CISA KEV data: {e}")
            return []
    
    def _generate_payload_patterns(self, vuln_type: str) -> List[str]:
        """Generate common payload patterns for a vulnerability type"""
        patterns = {
            "SQL Injection": [
                "'", "\"", "' OR 1=1--", "' UNION SELECT NULL--", 
                "'; DROP TABLE users--", "' AND 1=2--", "1' OR '1'='1"
            ],
            "Cross-Site Scripting": [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "javascript:alert(1)", "<svg onload=alert(1)>", 
                "'-alert(1)-'", "\"><script>alert(1)</script>"
            ],
            "Path Traversal": [
                "../", "..\\", "....//", "..%2f", "%2e%2e%2f",
                "../../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                "%00../", "....\\\\", "..%c0%af"
            ],
            "Remote Code Execution": [
                "; ls", "| whoami", "&& dir", "$(id)", "`whoami`",
                "; cat /etc/passwd", "| type C:\\windows\\win.ini",
                "${@print(system('id'))}", "<%- system('whoami') %>"
            ],
            "Cross-Site Request Forgery": [
                "<form method=post action=target><input type=submit value=Click></form>",
                "<img src=target?action=delete>", "<script>fetch('/admin/delete')</script>"
            ],
            "Server-Side Request Forgery": [
                "http://localhost", "http://127.0.0.1", "http://169.254.169.254",
                "file:///etc/passwd", "gopher://127.0.0.1:25", "dict://localhost:11211"
            ]
        }
        return patterns.get(vuln_type, ["test", "' OR 1=1", "<script>alert(1)</script>"])
    
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

    def query_technology_specific_cves(self, technologies: List[str]) -> Dict[str, List[Dict]]:
        """
        Query CVEs specific to discovered technologies.
        
        Args:
            technologies: List of technology identifiers (e.g., ['php', 'wordpress', 'apache'])
            
        Returns:
            Dict mapping technology to list of relevant CVEs
        """
        print(f"[Info] 🔍 Querying CVEs for discovered technologies: {', '.join(technologies)}")
        
        tech_cves = {}
        
        for tech in technologies:
            print(f"[Info] 📡 Searching CVEs for {tech}...")
            cves = self._fetch_technology_cves(tech)
            if cves:
                tech_cves[tech] = cves
                print(f"[Info] ✅ Found {len(cves)} CVEs for {tech}")
            else:
                print(f"[Info] ⚠️ No CVEs found for {tech}")
                
            time.sleep(0.5)  # Rate limiting
            
        # Cache results
        self.knowledge["technology_specific_cves"].update(tech_cves)
        
        return tech_cves

    def _fetch_technology_cves(self, technology: str) -> List[Dict]:
        """
        Fetch CVEs for a specific technology from multiple sources.
        
        Args:
            technology: Technology name (e.g., 'php', 'wordpress', 'apache')
            
        Returns:
            List of CVE dictionaries with vulnerability details
        """
        cves = []
        
        # Try multiple CVE sources
        sources = [
            self._query_cve_details,
            self._query_nvd_nist,
            self._query_cisa_kev_tech_specific
        ]
        
        for source_func in sources:
            try:
                source_cves = source_func(technology)
                cves.extend(source_cves)
                if len(cves) >= 10:  # Limit to prevent overwhelming
                    break
            except Exception as e:
                print(f"[Warning] CVE source failed for {technology}: {e}")
                continue
                
        return cves[:10]  # Return top 10 most relevant

    def _query_cve_details(self, technology: str) -> List[Dict]:
        """Query CVE Details for technology-specific vulnerabilities"""
        cves = []
        
        try:
            # Search for recent high-severity CVEs
            search_url = f"https://www.cvedetails.com/vulnerability-search.php"
            params = {
                'f': 1,
                'vendor': '',
                'product': technology,
                'cvssscoremin': 7.0,  # High severity only
                'cvssscoremax': '',
                'publishdatefrom': '2020-01-01',  # Recent vulnerabilities
                'publishdateto': '',
                'order': 3,  # Order by CVSS score
                'trc': 50,
                'sha': 'ba3f4b7bb1cd86d47bcaba1a0f929fc65fb1e2e1'
            }
            
            response = self.session.get(search_url, params=params, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Parse CVE results table
                for row in soup.find_all('tr')[1:6]:  # First 5 results
                    cells = row.find_all('td')
                    if len(cells) >= 3:
                        cve_link = cells[1].find('a')
                        if cve_link:
                            cve_id = cve_link.text.strip()
                            cve_desc = cells[2].text.strip()
                            cvss_score = cells[3].text.strip() if len(cells) > 3 else 'N/A'
                            
                            cves.append({
                                'id': cve_id,
                                'description': cve_desc[:300],
                                'cvss_score': cvss_score,
                                'technology': technology,
                                'source': 'CVE Details'
                            })
                            
        except Exception as e:
            print(f"[Warning] CVE Details query failed: {e}")
            
        return cves

    def _query_nvd_nist(self, technology: str) -> List[Dict]:
        """Query NVD NIST API for technology-specific CVEs"""
        cves = []
        
        try:
            # Use NVD REST API v2
            api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                'keywordSearch': technology,
                'cvssV3Severity': 'HIGH,CRITICAL',
                'resultsPerPage': 5,
                'startIndex': 0
            }
            
            response = self.session.get(api_url, params=params, timeout=15)
            if response.status_code == 200:
                data = response.json()
                
                for vulnerability in data.get('vulnerabilities', []):
                    cve_item = vulnerability.get('cve', {})
                    cve_id = cve_item.get('id', 'Unknown')
                    
                    # Get description
                    descriptions = cve_item.get('descriptions', [])
                    description = 'No description available'
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')[:300]
                            break
                    
                    # Get CVSS score
                    cvss_score = 'N/A'
                    metrics = cve_item.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 'N/A')
                    
                    cves.append({
                        'id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'technology': technology,
                        'source': 'NVD NIST'
                    })
                    
        except Exception as e:
            print(f"[Warning] NVD NIST query failed: {e}")
            
        return cves

    def _query_cisa_kev_tech_specific(self, technology: str) -> List[Dict]:
        """Query CISA KEV for technology-specific vulnerabilities"""
        cves = []
        
        try:
            # Download CISA KEV catalog
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            response = self.session.get(kev_url, timeout=30)
            
            if response.status_code == 200:
                kev_data = response.json()
                
                for vuln in kev_data.get('vulnerabilities', []):
                    vendor = vuln.get('vendorProject', '').lower()
                    product = vuln.get('product', '').lower()
                    vuln_name = vuln.get('vulnerabilityName', '').lower()
                    
                    # Check if technology matches vendor, product, or vulnerability name
                    tech_lower = technology.lower()
                    if (tech_lower in vendor or tech_lower in product or 
                        tech_lower in vuln_name or vendor in tech_lower):
                        
                        cves.append({
                            'id': vuln.get('cveID', 'Unknown'),
                            'description': f"{vuln.get('vulnerabilityName', '')}: {vuln.get('shortDescription', '')}",
                            'cvss_score': 'CISA KEV',
                            'technology': technology,
                            'source': 'CISA KEV',
                            'vendor': vuln.get('vendorProject', ''),
                            'product': vuln.get('product', ''),
                            'due_date': vuln.get('dueDate', '')
                        })
                        
                        if len(cves) >= 5:  # Limit CISA results
                            break
                            
        except Exception as e:
            print(f"[Warning] CISA KEV query failed: {e}")
            
        return cves

    def extract_technologies_from_page_data(self, page_data: str) -> List[str]:
        """
        Extract technology identifiers from scanner page data.
        
        Args:
            page_data: Scanner data containing page information
            
        Returns:
            List of detected technologies
        """
        technologies = set()
        page_lower = page_data.lower()
        
        # Web frameworks and languages
        tech_patterns = {
            'php': ['php', '.php', 'x-powered-by: php'],
            'asp.net': ['asp.net', '.aspx', '.asp', 'viewstate', 'x-aspnet-version'],
            'java': ['java', '.jsp', '.do', 'jsessionid', 'tomcat', 'jetty'],
            'python': ['python', 'django', 'flask', '.py'],
            'ruby': ['ruby', 'rails', '.rb'],
            'nodejs': ['node.js', 'express', 'x-powered-by: express'],
            'go': ['golang', ' go '],
            
            # CMS and Applications
            'wordpress': ['wordpress', 'wp-content', 'wp-admin', '/wp/'],
            'drupal': ['drupal', '/sites/default/', 'drupal.org'],
            'joomla': ['joomla', '/administrator/', 'joomla.org'],
            'magento': ['magento', '/magento/', 'mage'],
            'shopify': ['shopify', 'myshopify.com'],
            'sharepoint': ['sharepoint', '_layouts', 'microsoftsharepointteamservices'],
            'confluence': ['confluence', '/confluence/', 'atlassian'],
            'jira': ['jira', '/jira/', 'atlassian'],
            
            # Web servers
            'apache': ['apache', 'server: apache'],
            'nginx': ['nginx', 'server: nginx'],
            'iis': ['iis', 'server: microsoft-iis', 'x-aspnet-version'],
            'lighttpd': ['lighttpd', 'server: lighttpd'],
            
            # Databases (from error messages, headers)
            'mysql': ['mysql', 'mysqli', 'sql syntax', 'mysql_'],
            'postgresql': ['postgresql', 'postgres', 'psql'],
            'oracle': ['oracle', 'ora-', 'plsql'],
            'mongodb': ['mongodb', 'mongo', 'nosql'],
            'mssql': ['mssql', 'microsoft sql server', 'sql server'],
            
            # JavaScript frameworks
            'react': ['react', 'reactjs', '_react'],
            'angular': ['angular', 'angularjs', 'ng-'],
            'vue': ['vue.js', 'vuejs', '__vue'],
            'jquery': ['jquery', '$(', 'jquery.min.js'],
            
            # Cloud platforms
            'aws': ['amazonaws.com', 'aws', 'cloudfront'],
            'azure': ['azure', 'azurewebsites.net', 'microsoftonline'],
            'gcp': ['googleapis.com', 'google cloud', 'appspot.com'],
            
            # Other technologies
            'elasticsearch': ['elasticsearch', 'elastic.co'],
            'redis': ['redis', 'redis-server'],
            'docker': ['docker', 'container'],
            'kubernetes': ['kubernetes', 'k8s'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in page_lower:
                    technologies.add(tech)
                    break
        
        # Also check for version numbers in common headers
        version_patterns = {
            'apache': r'server:\s*apache[/\s]([\d.]+)',
            'nginx': r'server:\s*nginx[/\s]([\d.]+)',
            'php': r'x-powered-by:\s*php[/\s]([\d.]+)',
        }
        
        for tech, pattern in version_patterns.items():
            matches = re.findall(pattern, page_lower)
            if matches and tech not in technologies:
                technologies.add(f"{tech} {matches[0]}")
        
        return list(technologies)

    def get_technology_specific_knowledge(self, page_data: str) -> str:
        """
        Get knowledge summary including technology-specific CVEs.
        
        Args:
            page_data: Scanner data to extract technologies from
            
        Returns:
            Knowledge summary including technology-specific vulnerabilities
        """
        # Extract technologies from page data
        technologies = self.extract_technologies_from_page_data(page_data)
        
        if not technologies:
            return self.get_knowledge_summary()  # Return general knowledge if no tech detected
        
        # Query CVEs for discovered technologies
        tech_cves = self.query_technology_specific_cves(technologies)
        
        # Build enhanced knowledge summary
        knowledge_parts = [
            "## Security Knowledge Base",
            "",
            "### Discovered Technologies",
            f"Detected: {', '.join(technologies)}",
            ""
        ]
        
        # Add technology-specific CVEs
        if tech_cves:
            knowledge_parts.extend([
                "### Technology-Specific Vulnerabilities",
                ""
            ])
            
            for tech, cves in tech_cves.items():
                knowledge_parts.append(f"**{tech.upper()} Vulnerabilities:**")
                for cve in cves[:3]:  # Top 3 per technology
                    knowledge_parts.append(f"- {cve['id']}: {cve['description'][:150]}... (CVSS: {cve['cvss_score']})")
                knowledge_parts.append("")
        
        # Add general knowledge
        knowledge_parts.extend([
            "### General Security Testing Knowledge",
            "- **DevSec Blog Web API Security Champion Series**: Authorization bypasses, authentication flaws, object-level access control",
            "- **PortSwigger Web Security Academy Labs**: SQL injection, XSS, CSRF, authentication bypasses, access control flaws, SSRF, XXE",
            "- **Expert Penetration Testing Techniques**: Advanced payload crafting, polyglot attacks, chained exploits",
            "",
            "**Testing Strategy**: Prioritize technology-specific vulnerabilities above, then apply general OWASP Top 10 testing."
        ])
        
        return "\n".join(knowledge_parts)

def initialize_knowledge_base() -> SecurityKnowledgeBase:
    """Initialize and fetch the security knowledge base"""
    kb = SecurityKnowledgeBase()
    kb.fetch_all_knowledge()
    return kb 