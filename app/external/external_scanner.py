from abc import ABC, abstractmethod


class ExternalScanner(ABC):
    """
    All external tooling will be wrapped in specific classes that will provide this method as part of the public API.
    """

    @abstractmethod
    def call(self):
        pass
