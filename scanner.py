import os
import requests
import json
from parser import HTMLParser

class Scanner:
    def __init__(self, playwright_page):
        self.page = playwright_page
        self.parser = HTMLParser()

    def scan(self, url_to_scan: str) -> dict:
        """
        Scans a URL by visiting it, waiting for the page to load, and parsing its content.

        Args:
            url_to_scan (str): The URL to scan and analyze

        Returns:
            dict: Dictionary containing:
                - parsed_data: Structured data extracted from the page
                - url: The scanned URL
                - html_content: Raw HTML content of the page
        """
        # visit url
        self.page.goto(url_to_scan)
        try:
            self.page.wait_for_load_state("networkidle")
        except Exception as e:
            _ = 1

        # get the page source
        page_source = self.page.content()

        # parse the page source
        parsed_data = self.parser.parse(page_source, url_to_scan)

        # return the parsed data
        return {"parsed_data": parsed_data, "url": url_to_scan, "html_content": page_source}