"""
CloudSentinel Normalized IOC Model.

Defines the canonical representation of an Indicator of
Compromise (IOC) used by threat-intelligence components.

Supported IOC types:

    ip
    domain
    url
    md5
    sha1
    sha256
"""

from dataclasses import asdict, dataclass


SUPPORTED_IOC_TYPES = {
    "ip",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
}


@dataclass(frozen=True)
class IOC:
    """
    Canonical representation of one IOC.

    Attributes:
        ioc_type: Normalized IOC type.
        value: Normalized IOC value.
    """

    ioc_type: str
    value: str

    def __post_init__(self):
        ioc_type = str(
            self.ioc_type
        ).strip().lower()

        value = str(
            self.value
        ).strip()

        if ioc_type not in SUPPORTED_IOC_TYPES:
            raise ValueError(
                f"Unsupported IOC type: {ioc_type}"
            )

        if not value:
            raise ValueError(
                "IOC value cannot be empty."
            )

        object.__setattr__(
            self,
            "ioc_type",
            ioc_type,
        )

        object.__setattr__(
            self,
            "value",
            value,
        )

    def to_dict(self):
        """
        Convert the IOC into a JSON-friendly dictionary.
        """

        return asdict(self)
