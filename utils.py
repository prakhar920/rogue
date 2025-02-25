import os
import requests
import pathlib
import time
import base64
from urllib.parse import urlparse
import tiktoken

def check_hostname(url_start: str, url_to_check: str) -> bool:
    """
    Check if two URLs have the same hostname.
    
    Args:
        url_start: First URL to compare
        url_to_check: Second URL to compare
        
    Returns:
        bool: True if hostnames match, False otherwise
    """
    url_start_hostname = urlparse(url_start).netloc
    url_to_check_hostname = urlparse(url_to_check).netloc
    return url_start_hostname == url_to_check_hostname

def enumerate_subdomains(url: str) -> list:
    """
    Find valid subdomains for a given domain by testing common subdomain names.
    
    Args:
        url: Base URL to check subdomains for
        
    Returns:
        list: List of valid subdomain URLs that returned HTTP 200
    """
    # Extract the root domain from the URL
    parsed = urlparse(url)
    hostname = parsed.netloc
    # Remove any www. prefix if present
    if hostname.startswith('www.'):
        hostname = hostname[4:]
    # Split on dots and take last two parts to get root domain
    parts = hostname.split('.')
    if len(parts) > 2:
        hostname = '.'.join(parts[-2:])

    subdomains_path = pathlib.Path(__file__).parent / "lists" / "subdomains.txt"
    with open(subdomains_path, "r") as f:
        subdomains = f.read().splitlines()

    valid_domains = []
    for subdomain in subdomains:
        url = f"https://{subdomain}.{hostname}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                print(f"[Info] Found a valid subdomain: {url}")
                valid_domains.append(url)
        except:
            continue

    return valid_domains

def get_base64_image(page) -> str:
    """
    Take a screenshot of the page and return it as a base64 encoded string.
    
    Args:
        page: Playwright page object
        
    Returns:
        str: Base64 encoded screenshot image
    """
    screenshot_path = "temp/temp_screenshot.png"
    page.screenshot(path=screenshot_path)
    with open(screenshot_path, "rb") as image_file:
        base64_image = base64.b64encode(image_file.read()).decode("utf-8")
    return base64_image

def wait_for_network_idle(page, timeout: int = 4000) -> None:
    """
    Wait for network activity to become idle.
    
    Args:
        page: Playwright page object
        timeout: Maximum time to wait in milliseconds (default: 4000)
    """
    try:
        page.wait_for_load_state('networkidle', timeout=timeout)
    except Exception as e:
        # If timeout occurs, give a small delay anyway
        time.sleep(1)  # Fallback delay

def count_tokens(text, model: str = "gpt-4o") -> int:
    """
    Count the number of tokens in a text string using OpenAI's tokenizer.
    
    Args:
        text: The text to tokenize (string or list of dicts with content key)
        model: The model to use for tokenization (default: gpt-4o)
        
    Returns:
        int: The number of tokens in the text
    """
    if isinstance(text, list):
        text = " ".join(str(item.get("content", "")) for item in text)
    
    encoder = tiktoken.encoding_for_model("gpt-4o")
    tokens = encoder.encode(text)
    return len(tokens)