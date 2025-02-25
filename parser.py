from bs4 import BeautifulSoup
import math
import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urljoin, urlparse
import re

class HTMLParser:
    def __init__(self):
        """
        Initialize the HTML parser with a base URL for resolving relative URLs
        
        Args:
            base_url (str): The base URL of the page being parsed
        """
        self.base_url = None
        
    def pretty_print(self, data: Dict[str, Any]) -> str:
        """
        Pretty print the parsed data as a nicely formatted string
        
        Args:
            data (Dict[str, Any]): The parsed data to format
            
        Returns:
            str: A nicely formatted string representation of the data
        """
        output = []
        output.append("Parsed HTML Data:")
        output.append("================")
        
        if data.get('urls'):
            output.append("\nURLs Found:")
            for url in data['urls']:
                output.append(f"  • {url['text']}: {url['href']}")
                
        if data.get('forms'):
            output.append("\nForms Found:")
            for i, form in enumerate(data['forms'], 1):
                output.append(f"\n  Form #{i}:")
                output.append(f"    Action: {form['action']}")
                output.append(f"    Method: {form['method']}")
                if form['inputs']:
                    output.append("    Inputs:")
                    for input_field in form['inputs']:
                        output.append(f"      - {input_field['name']} ({input_field['type']})")
                        
  
        return "\n".join(output)
        
    def parse(self, html_content: str, url: str) -> Dict[str, Any]:
        """
        Parse HTML content and extract relevant information
        
        Args:
            html_content (str): Raw HTML content to parse
            url (str): The URL of the page being parsed
            
        Returns:
            dict: Dictionary containing extracted information
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        self.base_url = url
        data = {
            'urls': self._extract_urls(soup),
            'forms': self._extract_forms(soup),
            'scripts': self._extract_scripts(soup),

        }
        return data

    def _extract_urls(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract all unique URLs from anchor tags with their text content that belong to the same domain"""
        from urllib.parse import urlparse
        
        seen_urls = set()
        urls = []
        base_domain = urlparse(self.base_url).netloc.split('.')[-2:]  # Get main domain without subdomains
        
        for a_tag in soup.find_all('a', href=True):
            full_url = urljoin(self.base_url, a_tag['href'])
            
            # Skip if we've seen this URL before
            if full_url in seen_urls:
                continue
                
            parsed_url = urlparse(full_url)
            url_domain = parsed_url.netloc.split('.')[-2:]
            
            # Only include URLs from same domain (including subdomains)
            if url_domain == base_domain:
                url = {
                    'href': full_url,
                    'text': a_tag.get_text(strip=True),
                }
                urls.append(url)
                seen_urls.add(full_url)
                
        return urls
        
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Extract all unique forms with their full HTML and input fields"""
        seen_forms = set()
        forms = []
        for form in soup.find_all('form'):
            form_html = str(form)
            
            # Skip if we've seen this exact form HTML before
            if form_html in seen_forms:
                continue
                
            form_data = {
                'action': urljoin(self.base_url, form.get('action', '')),
                'method': form.get('method', 'get'),
                'outer_html': form_html,
                'inputs': []
            }
            
            # Extract input fields
            for input_field in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_field.get('type', 'text'),
                    'name': input_field.get('name', ''),
                    'id': input_field.get('id', ''),
                    'required': input_field.has_attr('required'),
                    'outer_html': str(input_field)
                }
                form_data['inputs'].append(input_data)
                
            forms.append(form_data)
            seen_forms.add(form_html)
            
        return forms
        
    def _extract_scripts(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Extract all unique script tags and their sources"""
        seen_scripts = set()
        scripts = []
        base_domain = urlparse(self.base_url).netloc.split('.')[-2:]  # Get main domain without subdomains
        
        for script in soup.find_all('script'):
            src = script.get('src', '')
            if src:
                full_src = urljoin(self.base_url, src)
                parsed_url = urlparse(full_src)
                script_domain = parsed_url.netloc.split('.')[-2:]
                
                # Skip if not from same domain or already seen
                if script_domain != base_domain or full_src in seen_scripts:
                    continue
                    
                script_data = {
                    'src': full_src,
                    'type': script.get('type', 'text/javascript'),
                }
                scripts.append(script_data)
                seen_scripts.add(full_src)
            else:
                # For inline scripts, use content hash to detect duplicates
                content = script.string or ''
                if content in seen_scripts:
                    continue
                script_data = {
                    'src': content,
                    'type': script.get('type', 'text/javascript'),
                }
                scripts.append(script_data)
                seen_scripts.add(content)
                
        return scripts
        
   