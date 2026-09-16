"""
CloudSentinel AlienVault OTX Threat Intelligence Provider.

This adapter communicates with AlienVault OTX using its HTTP API.

The API key is read from the OTX_API_KEY environment variable.
No API key is stored in source code.
"""

import json
import os
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from src.threat_intel.ioc_model import IOC
from src.threat_intel.providers.base import ThreatIntelProvider


class OTXProvider(ThreatIntelProvider):
    """
    AlienVault OTX provider adapter.
    """

    DEFAULT_BASE_URL = (
        "https://otx.alienvault.com"
    )

    def __init__(
        self,
        api_key=None,
        base_url=None,
        request_timeout=10,
        opener=None,
    ):
        self.api_key = (
            api_key
            if api_key is not None
            else os.getenv("OTX_API_KEY")
        )

        self.base_url = (
            base_url
            if base_url is not None
            else os.getenv(
                "OTX_BASE_URL",
                self.DEFAULT_BASE_URL,
            )
        ).rstrip("/")

        self.request_timeout = float(
            request_timeout
        )

        if self.request_timeout <= 0:
            raise ValueError(
                "OTX request timeout must be greater than zero."
            )

        self._opener = (
            opener
            if opener is not None
            else urlopen
        )

    @property
    def name(self):
        return "otx"

    def _indicator_path(self, ioc):
        encoded_value = quote(
            ioc.value,
            safe="",
        )

        if ioc.ioc_type == "ip":
            indicator_type = "IPv4"

        elif ioc.ioc_type == "domain":
            indicator_type = "domain"

        elif ioc.ioc_type == "url":
            indicator_type = "url"

        elif ioc.ioc_type in {
            "md5",
            "sha1",
            "sha256",
        }:
            indicator_type = "file"

        else:
            raise ValueError(
                f"Unsupported IOC type for OTX: "
                f"{ioc.ioc_type}"
            )

        return (
            f"/api/v1/indicators/"
            f"{indicator_type}/"
            f"{encoded_value}/general"
        )

    @staticmethod
    def _extract_seen_times(pulses):
        """
        Extract first/last observed timestamps from
        OTX pulse metadata.

        Returns:
            tuple(first_seen, last_seen)
        """

        timestamps = []

        for pulse in pulses:
            if not isinstance(
                pulse,
                dict,
            ):
                continue

            created = pulse.get(
                "created"
            )

            modified = pulse.get(
                "modified"
            )

            if created:
                timestamps.append(
                    str(created)
                )

            if modified:
                timestamps.append(
                    str(modified)
                )

        if not timestamps:
            return None, None

        return (
            min(timestamps),
            max(timestamps),
        )

    def lookup(self, ioc):
        """
        Query OTX for one IOC.

        Returns normalized threat-intelligence fields:

            reputation
            confidence
            first_seen
            last_seen
            source
        """

        if not isinstance(ioc, IOC):
            raise TypeError(
                "OTX lookup() requires an IOC instance."
            )

        if not self.api_key:
            raise RuntimeError(
                "OTX_API_KEY environment variable is not configured."
            )

        endpoint = (
            self.base_url
            + self._indicator_path(ioc)
        )

        request = Request(
            endpoint,
            method="GET",
            headers={
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json",
                "User-Agent": "CloudSentinel/1.0",
            },
        )

        try:
            with self._opener(
                request,
                timeout=self.request_timeout,
            ) as response:

                raw_body = response.read()

        except HTTPError as exc:
            raise RuntimeError(
                f"OTX HTTP error: {exc.code}"
            ) from exc

        except URLError as exc:
            raise RuntimeError(
                f"OTX connection error: {exc.reason}"
            ) from exc

        try:
            data = json.loads(
                raw_body.decode("utf-8")
            )

        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as exc:

            raise RuntimeError(
                "OTX returned invalid JSON."
            ) from exc

        pulse_info = data.get(
            "pulse_info"
        ) or {}

        pulses = pulse_info.get(
            "pulses"
        ) or []

        pulse_count = pulse_info.get(
            "count",
            len(pulses),
        )

        pulse_names = []

        for pulse in pulses:
            if not isinstance(
                pulse,
                dict,
            ):
                continue

            name = pulse.get("name")

            if name:
                pulse_names.append(
                    str(name)
                )

        first_seen, last_seen = (
            self._extract_seen_times(
                pulses
            )
        )

        return {
            "status": "success",
            "provider": self.name,
            "source": self.name,
            "ioc": ioc.to_dict(),

            "found": bool(
                pulse_count
            ),

            "pulse_count": pulse_count,

            "reputation": data.get(
                "reputation"
            ),

            "confidence": data.get(
                "confidence"
            ),

            "first_seen": first_seen,
            "last_seen": last_seen,

            "pulse_names": pulse_names,

            "raw": data,
        }
