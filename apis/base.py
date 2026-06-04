from abc import ABC, abstractmethod


class BaseAPI(ABC):

    def __init__(self, api_key: str):
        self.api_key = api_key

    @abstractmethod
    def query(self, ip: str) -> dict:
        """
        Makes the API call and returns a flat dict of results.
        Keys must match exactly what headers() returns.
        Raise exceptions freely — safe_query() handles them.
        """
        pass

    @abstractmethod
    def headers(self) -> list:
        """Returns the list of column names this API contributes."""
        pass

    def safe_query(self, ip: str) -> dict:
        """
        Wraps query() so a failed API call never crashes the run.
        On any error, fills all columns with ERROR and prints a warning.
        """
        try:
            return self.query(ip)
        except Exception as e:
            print(f"    [!] {self.__class__.__name__} failed for {ip}: {e}")
            return {h: "ERROR" for h in self.headers()}
