class ScanContext:
    def __init__(self,url):
        self.url = url

        self.parsed = None
        self.params = None

        self.base_response = None
        self.base_text = None
        self.base_len = 0

        self.results = []

