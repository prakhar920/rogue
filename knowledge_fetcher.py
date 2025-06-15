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
    from expert sources (PentestMonkey, CAPEC, OWASP WSTG) and CISA KEV (using shared memory context).
    """
    
    def __init__(self):
        self.knowledge = {
            "pentestmonkey_cheatsheets": [],
            "capec_attack_patterns": [],
            "owasp_wstg_techniques": [],
            "cisa_kev_web_vulns": []
        }
        
    def build_knowledge_base(self, shared_memory_context: Optional[Dict] = None):
        """
        Build the complete security knowledge base by fetching from all sources
        """
        print("[Info] 📥 Fetching security knowledge from expert sources...")
        
        # Fetch from all sources
        self.knowledge["pentestmonkey_cheatsheets"] = self.fetch_pentestmonkey_cheatsheets()
        print(f"[Info] ✅ Fetched {len(self.knowledge['pentestmonkey_cheatsheets'])} PentestMonkey cheat sheets")
        
        self.knowledge["capec_attack_patterns"] = self.fetch_capec_patterns()
        print(f"[Info] ✅ Fetched {len(self.knowledge['capec_attack_patterns'])} CAPEC attack patterns")
        
        self.knowledge["owasp_wstg_techniques"] = self.fetch_owasp_wstg_techniques()
        print(f"[Info] ✅ Fetched {len(self.knowledge['owasp_wstg_techniques'])} OWASP WSTG techniques")
        
        # Compile techniques and payloads
        self._compile_techniques_and_payloads()
        
        # Note: CISA KEV vulnerabilities will be fetched later based on scanner context
        print("[Info] ℹ️  CISA KEV vulnerabilities will be fetched based on application context")
        
        self.knowledge["last_updated"] = time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"[Info] ✅ Knowledge base updated at {self.knowledge['last_updated']}")
    
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
    
    def fetch_contextual_cves(self, scanner_context: Dict) -> List[Dict]:
        """
        Fetch CVEs from CISA KEV catalog based on actual scanner context
        
        Args:
            scanner_context: Dictionary containing scanner findings like:
                - technologies: List of detected technologies/frameworks
                - services: List of detected services
                - endpoints: List of discovered endpoints
                - forms: List of forms found
                - headers: HTTP headers observed
                - cookies: Cookies observed
                - javascript_libraries: JS libraries detected
                - cms_info: CMS information if detected
        
        Returns:
            List of relevant CVEs based on the actual application context
        """
        print("[Info] 🎯 Fetching contextual CVEs based on scanner findings...")
        
        try:
            # CISA KEV catalog JSON endpoint
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json()
            
            # Build context-specific keywords from scanner findings
            context_keywords = self._build_context_keywords(scanner_context)
            print(f"[Info] 🔍 Searching CVEs for: {', '.join(context_keywords[:10])}{'...' if len(context_keywords) > 10 else ''}")
            
            relevant_cves = []
            for vuln in data.get('vulnerabilities', []):
                vuln_name = vuln.get('vulnerabilityName', '').lower()
                vuln_desc = vuln.get('shortDescription', '').lower()
                vendor_project = vuln.get('vendorProject', '').lower()
                product = vuln.get('product', '').lower()
                
                # Check if vulnerability matches our application context
                search_text = f"{vuln_name} {vuln_desc} {vendor_project} {product}"
                
                if any(keyword.lower() in search_text for keyword in context_keywords):
                    relevance_score = self._calculate_cve_relevance(vuln, context_keywords)
                    
                    relevant_cves.append({
                        "cve_id": vuln.get('cveID'),
                        "name": vuln.get('vulnerabilityName'),
                        "description": vuln.get('shortDescription', ''),
                        "vendor_project": vuln.get('vendorProject', ''),
                        "product": vuln.get('product', ''),
                        "date_added": vuln.get('dateAdded'),
                        "required_action": vuln.get('requiredAction', ''),
                        "relevance_score": relevance_score,
                        "matching_keywords": [kw for kw in context_keywords if kw.lower() in search_text]
                    })
            
            # Sort by relevance score and limit results
            relevant_cves.sort(key=lambda x: x['relevance_score'], reverse=True)
            relevant_cves = relevant_cves[:25]  # Top 25 most relevant
            
            # Update knowledge base
            self.knowledge["cisa_kev_web_vulns"] = relevant_cves
            print(f"[Info] ✅ Fetched {len(relevant_cves)} contextually relevant CVEs")
            
            return relevant_cves
            
        except Exception as e:
            print(f"[Error] Failed to fetch contextual CVEs: {e}")
            return []
    
    def _build_context_keywords(self, scanner_context: Dict) -> List[str]:
        """Build a list of keywords based on scanner context for CVE filtering"""
        keywords = set()
        
        # Add detected technologies and frameworks
        if 'technologies' in scanner_context:
            for tech in scanner_context['technologies']:
                keywords.add(tech.lower())
                # Add common variations
                if 'wordpress' in tech.lower():
                    keywords.update(['wordpress', 'wp', 'cms'])
                elif 'drupal' in tech.lower():
                    keywords.update(['drupal', 'cms'])
                elif 'joomla' in tech.lower():
                    keywords.update(['joomla', 'cms'])
                elif 'apache' in tech.lower():
                    keywords.update(['apache', 'httpd'])
                elif 'nginx' in tech.lower():
                    keywords.update(['nginx', 'web server'])
                elif 'php' in tech.lower():
                    keywords.update(['php', 'scripting'])
                elif 'mysql' in tech.lower():
                    keywords.update(['mysql', 'database', 'sql'])
                elif 'postgresql' in tech.lower():
                    keywords.update(['postgresql', 'postgres', 'database', 'sql'])
        
        # Add detected services
        if 'services' in scanner_context:
            keywords.update([service.lower() for service in scanner_context['services']])
        
        # Add JavaScript libraries
        if 'javascript_libraries' in scanner_context:
            for lib in scanner_context['javascript_libraries']:
                keywords.add(lib.lower())
                # Add common JS framework variations
                if 'jquery' in lib.lower():
                    keywords.add('jquery')
                elif 'react' in lib.lower():
                    keywords.update(['react', 'reactjs'])
                elif 'angular' in lib.lower():
                    keywords.update(['angular', 'angularjs'])
                elif 'vue' in lib.lower():
                    keywords.update(['vue', 'vuejs'])
        
        # Add CMS information
        if 'cms_info' in scanner_context and scanner_context['cms_info']:
            cms_info = scanner_context['cms_info']
            if 'name' in cms_info:
                keywords.add(cms_info['name'].lower())
            if 'version' in cms_info:
                keywords.add(f"{cms_info['name'].lower()} {cms_info['version']}")
        
        # Add server information from headers
        if 'headers' in scanner_context:
            headers = scanner_context['headers']
            if 'server' in headers:
                server_info = headers['server'].lower()
                keywords.add(server_info)
                # Extract server name and version
                if '/' in server_info:
                    server_name = server_info.split('/')[0]
                    keywords.add(server_name)
        
        # Add endpoint-based keywords
        if 'endpoints' in scanner_context:
            for endpoint in scanner_context['endpoints']:
                endpoint_lower = endpoint.lower()
                # Look for common vulnerable endpoints
                if 'admin' in endpoint_lower:
                    keywords.add('admin panel')
                elif 'api' in endpoint_lower:
                    keywords.add('api')
                elif 'upload' in endpoint_lower:
                    keywords.add('file upload')
                elif 'login' in endpoint_lower:
                    keywords.add('authentication')
        
        # Add form-based keywords
        if 'forms' in scanner_context:
            for form in scanner_context['forms']:
                if 'action' in form:
                    action = form['action'].lower()
                    if 'search' in action:
                        keywords.add('search')
                    elif 'login' in action:
                        keywords.add('authentication')
                    elif 'upload' in action:
                        keywords.add('file upload')
        
        # Always include basic web vulnerability keywords
        keywords.update([
            'web application', 'http', 'web server', 'remote code execution',
            'sql injection', 'cross-site scripting', 'authentication bypass',
            'directory traversal', 'file inclusion', 'deserialization'
        ])
        
        return list(keywords)
    
    def _calculate_cve_relevance(self, vuln: Dict, context_keywords: List[str]) -> float:
        """Calculate relevance score for a CVE based on context match"""
        score = 0.0
        
        vuln_name = vuln.get('vulnerabilityName', '').lower()
        vuln_desc = vuln.get('shortDescription', '').lower()
        vendor_project = vuln.get('vendorProject', '').lower()
        product = vuln.get('product', '').lower()
        
        search_text = f"{vuln_name} {vuln_desc} {vendor_project} {product}"
        
        # Higher score for exact technology matches
        for keyword in context_keywords:
            keyword_lower = keyword.lower()
            if keyword_lower in vendor_project or keyword_lower in product:
                score += 3.0  # High relevance for vendor/product match
            elif keyword_lower in vuln_name:
                score += 2.0  # Medium relevance for name match
            elif keyword_lower in vuln_desc:
                score += 1.0  # Lower relevance for description match
        
        # Bonus for recent vulnerabilities (more likely to be relevant)
        try:
            date_added = vuln.get('dateAdded', '')
            if date_added:
                from datetime import datetime
                vuln_date = datetime.strptime(date_added, '%Y-%m-%d')
                days_old = (datetime.now() - vuln_date).days
                if days_old < 365:  # Less than 1 year old
                    score += 1.0
                elif days_old < 730:  # Less than 2 years old
                    score += 0.5
        except:
            pass
        
        return score

    def fetch_pentestmonkey_cheatsheets(self) -> List[Dict]:
        """Fetch security testing cheat sheets from PentestMonkey"""
        print("[Info] 🐒 Fetching PentestMonkey cheat sheets...")
        cheatsheets = []
        try:
            # PentestMonkey cheat sheets - using working URLs only
            urls = [
                "https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet",
                "https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet",
                "https://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet",
                "https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html'
            }
            
            for url in urls:
                try:
                    response = requests.get(url, headers=headers, timeout=10)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract title and content
                    title = soup.find('h1')
                    if title:
                        title = title.get_text(strip=True)
                        
                        # Look for content in various possible containers
                        content_div = soup.find('div', class_='entry-content')
                        if not content_div:
                            content_div = soup.find('div', class_='entryContent')
                        if not content_div:
                            content_div = soup.find('div', class_='post-content')
                        if not content_div:
                            content_div = soup.find('article')
                        if not content_div:
                            content_div = soup.find('main')
                        
                        if content_div:
                            # Extract code blocks and tables
                            code_blocks = content_div.find_all('pre')
                            tables = content_div.find_all('table')
                            
                            cheatsheet = {
                                "title": title,
                                "url": url,
                                "code_blocks": [block.get_text(strip=True) for block in code_blocks],
                                "tables": [
                                    [[cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])] 
                                     for row in table.find_all('tr')]
                                    for table in tables
                                ]
                            }
                            cheatsheets.append(cheatsheet)
                            print(f"[Info] ✅ Fetched: {title}")
                    time.sleep(1)  # Be respectful to the server
                except Exception as e:
                    print(f"[Warning] Failed to fetch {url}: {e}")
                    
        except Exception as e:
            print(f"[Error] Failed to fetch PentestMonkey cheat sheets: {e}")
        
        return cheatsheets

    def fetch_capec_patterns(self) -> List[Dict]:
        """Fetch attack patterns from CAPEC starting from CAPEC-513"""
        print("[Info] 🎯 Fetching CAPEC attack patterns...")
        patterns = []
        visited_urls = set()
        
        try:
            # Start with CAPEC-513 and follow related patterns
            base_url = "https://capec.mitre.org/data/definitions/513.html"
            urls_to_visit = [base_url]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html'
            }
            
            while urls_to_visit and len(patterns) < 50:  # Limit to 50 patterns
                url = urls_to_visit.pop(0)
                if url in visited_urls:
                    continue
                    
                try:
                    response = requests.get(url, headers=headers, timeout=15)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract pattern details from the CAPEC definition div
                    capec_def = soup.find('div', id='CAPECDefinition')
                    if capec_def:
                        # Extract title from h2 anywhere on the page
                        title_elem = soup.find('h2')
                        if title_elem:
                            title = title_elem.get_text(strip=True)
                            
                            # Extract CAPEC ID - try multiple methods
                            capec_id = None
                            # Method 1: Look for CAPEC-XXX in title
                            capec_match = re.search(r'CAPEC[- ](\d+)', title)
                            if capec_match:
                                capec_id = capec_match.group(1)
                            
                            # Method 2: Look for Category ID or Attack Pattern ID in the status div
                            if not capec_id:
                                status_div = capec_def.find('div', class_='status')
                                if status_div:
                                    status_text = status_div.get_text()
                                    id_match = re.search(r'(?:Category ID|Attack Pattern ID):\s*(\d+)', status_text)
                                    if id_match:
                                        capec_id = id_match.group(1)
                            
                            # Method 3: Extract from URL as fallback
                            if not capec_id:
                                url_match = re.search(r'(\d+)\.html', url)
                                if url_match:
                                    capec_id = url_match.group(1)
                            
                            if capec_id:
                                # Extract description from Summary div (for categories) or Description div (for patterns)
                                description = ""
                                desc_div = soup.find('div', id='Summary')
                                if not desc_div:
                                    desc_div = soup.find('div', id='Description')
                                if desc_div:
                                    detail_div = desc_div.find('div', class_='detail')
                                    if detail_div:
                                        description = detail_div.get_text(strip=True)
                                
                                # Extract related patterns from Membership div (for categories) or Relationships div (for patterns)
                                related_patterns = []
                                membership_div = soup.find('div', id='Membership')
                                if not membership_div:
                                    membership_div = soup.find('div', id='Relationships')
                                
                                if membership_div:
                                    # Find the table with related patterns
                                    table = membership_div.find('table', id='Detail')
                                    if table:
                                        for link in table.find_all('a', href=re.compile(r'/data/definitions/\d+\.html')):
                                            related_url = urljoin('https://capec.mitre.org', link['href'])
                                            if related_url not in visited_urls and related_url not in urls_to_visit:
                                                urls_to_visit.append(related_url)
                                                related_patterns.append(link.get_text(strip=True))
                                
                                pattern = {
                                    "title": title,
                                    "id": f"CAPEC-{capec_id}",
                                    "description": description,
                                    "url": url,
                                    "related_patterns": related_patterns
                                }
                                patterns.append(pattern)
                                print(f"[Info] ✅ Fetched: {title}")
                                visited_urls.add(url)
                    
                    time.sleep(1)  # Be respectful to the server
                    
                except Exception as e:
                    print(f"[Warning] Failed to fetch {url}: {e}")
                    
        except Exception as e:
            print(f"[Error] Failed to fetch CAPEC patterns: {e}")
        
        return patterns

    def fetch_owasp_wstg_techniques(self) -> List[Dict]:
        """Fetch testing techniques from OWASP Web Security Testing Guide"""
        print("[Info] 🔍 Fetching OWASP WSTG techniques...")
        techniques = []
        visited_urls = set()
        
        try:
            # Start with the main WSTG page
            base_url = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            urls_to_visit = [base_url]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html'
            }
            
            while urls_to_visit and len(techniques) < 100:  # Limit to 100 techniques
                url = urls_to_visit.pop(0)
                if url in visited_urls:
                    continue
                    
                try:
                    response = requests.get(url, headers=headers, timeout=15)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract main content from the page-body section
                    main_content = soup.find('section', id='div-main')
                    if not main_content:
                        main_content = soup.find('section', class_='page-body')
                    
                    if main_content:
                        # Extract technique title
                        title = None
                        title_elem = main_content.find('h1')
                        if not title_elem:
                            title_elem = main_content.find('h2')
                        if title_elem:
                            title = title_elem.get_text(strip=True)
                            
                            # Extract technique content
                            content = []
                            # Get all content elements
                            for elem in main_content.find_all(['p', 'pre', 'ul', 'ol', 'h2', 'h3', 'h4', 'table']):
                                if elem.name == 'pre':
                                    content.append(f"```\n{elem.get_text()}\n```")
                                elif elem.name == 'table':
                                    # Convert table to markdown
                                    rows = []
                                    for row in elem.find_all('tr'):
                                        cells = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                                        if cells:  # Only add non-empty rows
                                            rows.append('|' + '|'.join(cells) + '|')
                                    if rows:
                                        content.append('\n'.join(rows))
                                else:
                                    text = elem.get_text(strip=True)
                                    if text and len(text) > 10:  # Only add meaningful content
                                        if elem.name.startswith('h'):
                                            content.append(f"\n### {text}\n")
                                        else:
                                            content.append(text)
                            
                            # Find sub-techniques and add their URLs to visit
                            for link in main_content.find_all('a', href=re.compile(r'4-Web_Application_Security_Testing/.*')):
                                href = link.get('href')
                                if href:
                                    # Convert relative URLs to absolute
                                    if href.startswith('/'):
                                        sub_url = f"https://owasp.org{href}"
                                    else:
                                        sub_url = urljoin(base_url, href)
                                    
                                    if sub_url not in visited_urls and sub_url not in urls_to_visit:
                                        # Only add README pages and specific technique pages
                                        if 'README' in sub_url or re.search(r'/\d+-', sub_url):
                                            urls_to_visit.append(sub_url)
                            
                            technique = {
                                "title": title,
                                "url": url,
                                "content": "\n".join(content[:20]),  # Limit content to first 20 elements
                                "section": url.split('/')[-2].replace('-', ' ').replace('_', ' ') if '/' in url else "Main"
                            }
                            techniques.append(technique)
                            print(f"[Info] ✅ Fetched: {title}")
                            visited_urls.add(url)
                    
                    time.sleep(1)  # Be respectful to the server
                    
                except Exception as e:
                    print(f"[Warning] Failed to fetch {url}: {e}")
                    
        except Exception as e:
            print(f"[Error] Failed to fetch OWASP WSTG techniques: {e}")
        
        return techniques

    def _compile_techniques_and_payloads(self):
        """Compile and organize security testing techniques and payloads from all sources"""
        print("[Info] 📚 Compiling security techniques and payloads...")
        self.techniques = {
            "injection": [],
            "xss": [],
            "auth": [],
            "access_control": [],
            "business_logic": []
        }
        
        # Compile from PentestMonkey cheatsheets
        for cheat in self.knowledge["pentestmonkey_cheatsheets"]:
            if "sql" in cheat.get("title", "").lower():
                self.techniques["injection"].append(cheat)
            elif "xss" in cheat.get("title", "").lower():
                self.techniques["xss"].append(cheat)
            elif "auth" in cheat.get("title", "").lower():
                self.techniques["auth"].append(cheat)
        
        # Compile from CAPEC patterns
        for pattern in self.knowledge["capec_attack_patterns"]:
            if "injection" in pattern.get("title", "").lower():
                self.techniques["injection"].append(pattern)
            elif "access control" in pattern.get("title", "").lower():
                self.techniques["access_control"].append(pattern)
            elif "business logic" in pattern.get("title", "").lower():
                self.techniques["business_logic"].append(pattern)
        
        # Compile from OWASP WSTG techniques
        for technique in self.knowledge["owasp_wstg_techniques"]:
            if "injection" in technique.get("title", "").lower():
                self.techniques["injection"].append(technique)
            elif "xss" in technique.get("title", "").lower():
                self.techniques["xss"].append(technique)
            elif "auth" in technique.get("title", "").lower():
                self.techniques["auth"].append(technique)
            elif "access control" in technique.get("title", "").lower():
                self.techniques["access_control"].append(technique)
            elif "business logic" in technique.get("title", "").lower():
                self.techniques["business_logic"].append(technique)
        
        print(f"[Info] ✅ Compiled {sum(len(v) for v in self.techniques.values())} security techniques and payloads")
    
    def get_knowledge_summary(self) -> str:
        """
        Generate a comprehensive summary of the security knowledge base
        for use in LLM prompts
        """
        summary_parts = []
        # PentestMonkey Cheat Sheets
        if self.knowledge.get("pentestmonkey_cheatsheets"):
            summary_parts.append("## 🐒 PentestMonkey Cheat Sheets")
            for cheat in self.knowledge["pentestmonkey_cheatsheets"]:
                summary_parts.append(f"- {cheat['title']}")
        # CAPEC Attack Patterns
        if self.knowledge.get("capec_attack_patterns"):
            summary_parts.append("\n## 🎯 CAPEC Attack Patterns")
            for pattern in self.knowledge["capec_attack_patterns"]:
                summary_parts.append(f"- {pattern['title']}")
        # OWASP WSTG Techniques
        if self.knowledge.get("owasp_wstg_techniques"):
            summary_parts.append("\n## 🔍 OWASP WSTG Techniques")
            for technique in self.knowledge["owasp_wstg_techniques"]:
                summary_parts.append(f"- {technique['title']}")
        # CISA KEV Web Vulnerabilities (if available)
        if self.knowledge.get("cisa_kev_web_vulns"):
            summary_parts.append("\n## 🎯 Critical Vulnerabilities (CISA KEV)")
            summary_parts.append("Known exploited vulnerabilities relevant to this application:")
            for vuln in self.knowledge["cisa_kev_web_vulns"][:5]:
                summary_parts.append(f"- **{vuln['cve_id']}**: {vuln['name']}")
                if vuln.get('description'):
                    summary_parts.append(f"  {vuln['description']}")
                if vuln.get('matching_keywords'):
                    summary_parts.append(f"  Relevant to: {', '.join(vuln['matching_keywords'][:3])}")
        # Usage guidance
        summary_parts.append("\n## Testing Guidance")
        summary_parts.append("When generating security test plans:")
        summary_parts.append("- Prioritize techniques proven successful in real-world exploitation")
        summary_parts.append("- Focus on vulnerabilities currently being exploited (CISA KEV)")
        summary_parts.append("- Use modern attack vectors for web APIs and complex applications")
        summary_parts.append("- Combine multiple techniques for comprehensive coverage")
        summary_parts.append("- Always verify exploitability with concrete proof-of-concept")
        return "\n".join(summary_parts)

    def get_contextual_knowledge_summary(self, scanner_context: Dict) -> str:
        """
        Generate a knowledge summary enhanced with contextual CVEs
        
        Args:
            scanner_context: Scanner findings to use for CVE filtering
            
        Returns:
            Enhanced knowledge summary with relevant CVEs
        """
        # Fetch contextual CVEs first
        self.fetch_contextual_cves(scanner_context)
        
        # Return updated summary
        return self.get_knowledge_summary()

def initialize_knowledge_base() -> SecurityKnowledgeBase:
    """
    Initialize and build the security knowledge base
    
    Returns:
        SecurityKnowledgeBase: Populated knowledge base instance
    """
    kb = SecurityKnowledgeBase()
    print("[Info] 🧠 Building security knowledge base...")
    kb.build_knowledge_base()
    return kb 