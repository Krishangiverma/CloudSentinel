"""
CloudSentinel Threat Intelligence Provider Abstraction.

Defines the common interface that every threat-intelligence
provider must implement.
"""

from abc import ABC, abstractmethod

from src.threat_intel.ioc_model import IOC


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
    def lookup(self, ioc):
        """
        Look up one IOC.

        Args:
            ioc: CloudSentinel IOC instance.

        Returns:
            JSON-serializable provider result.
        """
        raise NotImplementedError
