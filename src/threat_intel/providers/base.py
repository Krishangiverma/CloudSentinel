"""
CloudSentinel Threat Intelligence Provider Abstraction.

Defines the common interface that every threat-intelligence
provider must implement.
"""

from abc import ABC, abstractmethod

from src.threat_intel.ioc_model import IOC


class RateLimitError(RuntimeError):
    """
    Raised when a threat-intelligence provider reports
    that the request has been rate limited.
    """

    def __init__(
        self,
        message="Provider rate limit exceeded.",
        retry_after=None,
    ):
        super().__init__(
            message
        )

        self.retry_after = retry_after


class ThreatIntelProvider(ABC):
    """
    Abstract interface for threat-intelligence providers.

    Providers receive a canonical IOC and return a normalized
    threat-intelligence result.
    """

    @property
    @abstractmethod
    def name(self):
        """Return the provider name."""
        raise NotImplementedError

    @abstractmethod
    def lookup(
        self,
        ioc,
    ):
        """
        Look up one IOC.

        Args:
            ioc: CloudSentinel IOC instance.

        Returns:
            JSON-serializable provider result.
        """
        raise NotImplementedError
