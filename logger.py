import logging
# from colorama import Fore, Style, init # REMOVED

# Initialize colorama
# init() # REMOVED

class Logger:
    # colors = { ... } # REMOVED

    def __init__(self, name='app'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        self.logger.addHandler(handler)

    def info(self, message, color='white'):
        # color_code = self.colors.get(color, Fore.WHITE) # REMOVED
        # self.logger.info(f"[Info] {color_code}{message}{Style.RESET_ALL}") # REPLACED
        self.logger.info(f"[Info] {message}") # CLEAN VERSION
        
    def warning(self, message):
        # self.logger.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}") # REPLACED
        self.logger.warning(f"[Warning] {message}") # CLEAN VERSION
        
    def error(self, message):
        # self.logger.error(f"{Fore.RED}{message}{Style.RESET_ALL}") # REPLACED
        self.logger.error(f"[Error] {message}") # CLEAN VERSION
        
    def debug(self, message):
        # self.logger.debug(f"{Fore.CYAN}{message}{Style.RESET_ALL}") # REPLACED
        self.logger.debug(f"[Debug] {message}") # CLEAN VERSION