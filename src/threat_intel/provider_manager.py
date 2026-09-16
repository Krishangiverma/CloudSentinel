"""
CloudSentinel Threat Intelligence Provider Manager.

Coordinates provider lookup, caching, timeout protection,
rate-limit handling and graceful provider failure.
"""

from concurrent.futures import (
    ThreadPoolExecutor,
    TimeoutError as FuturesTimeoutError,
)

from src.threat_intel.cache import ThreatIntelCache
from src.threat_intel.ioc_model import IOC
from src.threat_intel.providers.base import RateLimitError


class ThreatIntelProviderManager:
    """
    Manage threat-intelligence provider lookups.

    The manager keeps provider-specific logic outside the rest
    of CloudSentinel.
    """

    def __init__(
        self,
        providers=None,
        cache=None,
        timeout_seconds=5,
    ):
        if timeout_seconds <= 0:
            raise ValueError(
                "Provider timeout must be greater than zero."
            )

        self.timeout_seconds = float(
            timeout_seconds
        )

        self.providers = {}

        for provider in providers or []:
            self.register(
                provider
            )

        self.cache = (
            cache
            if cache is not None
            else ThreatIntelCache()
        )

    def register(
        self,
        provider,
    ):
        """
        Register a threat-intelligence provider.
        """

        if not hasattr(
            provider,
            "name",
        ):
            raise TypeError(
                "Provider must define a name."
            )

        if not callable(
            getattr(
                provider,
                "lookup",
                None,
            )
        ):
            raise TypeError(
                "Provider must define lookup()."
            )

        name = str(
            provider.name
        ).strip()

        if not name:
            raise ValueError(
                "Provider name cannot be empty."
            )

        self.providers[name] = provider

    def _cache_key(
        self,
        provider_name,
        ioc,
    ):
        """
        Build a deterministic cache key.
        """

        return (
            f"{provider_name}:"
            f"{ioc.ioc_type}:"
            f"{ioc.value}"
        )

    def lookup(
        self,
        ioc,
        provider_name=None,
    ):
        """
        Look up an IOC using a registered provider.

        Cached results are returned without invoking
        the provider.

        Timeout, rate-limit and provider errors are
        returned as structured results instead of
        crashing the caller.
        """

        if not isinstance(
            ioc,
            IOC,
        ):
            raise TypeError(
                "lookup() requires an IOC instance."
            )

        # ----------------------------------------------------
        # No providers
        # ----------------------------------------------------

        if not self.providers:
            return {
                "status": "no_provider",
                "provider": None,
                "ioc": ioc.to_dict(),
                "cached": False,
            }

        # ----------------------------------------------------
        # Default provider
        # ----------------------------------------------------

        if provider_name is None:
            provider_name = next(
                iter(
                    self.providers
                )
            )

        provider = self.providers.get(
            provider_name
        )

        # ----------------------------------------------------
        # Unknown provider
        # ----------------------------------------------------

        if provider is None:
            return {
                "status": "provider_not_found",
                "provider": provider_name,
                "ioc": ioc.to_dict(),
                "cached": False,
            }

        # ----------------------------------------------------
        # Cache lookup
        # ----------------------------------------------------

        cache_key = self._cache_key(
            provider_name,
            ioc,
        )

        cached = self.cache.get(
            cache_key
        )

        if cached is not None:

            result = dict(
                cached
            )

            result["cached"] = True

            return result

        # ----------------------------------------------------
        # Provider execution
        # ----------------------------------------------------

        executor = ThreadPoolExecutor(
            max_workers=1
        )

        future = executor.submit(
            provider.lookup,
            ioc,
        )

        try:

            result = future.result(
                timeout=self.timeout_seconds
            )

            # ------------------------------------------------
            # Invalid provider result
            # ------------------------------------------------

            if not isinstance(
                result,
                dict,
            ):

                return {
                    "status": "invalid_provider_result",
                    "provider": provider_name,
                    "ioc": ioc.to_dict(),
                    "cached": False,
                }

            # ------------------------------------------------
            # Normalize provider result
            # ------------------------------------------------

            result = dict(
                result
            )

            result.setdefault(
                "status",
                "success",
            )

            result.setdefault(
                "provider",
                provider_name,
            )

            result.setdefault(
                "ioc",
                ioc.to_dict(),
            )

            result["cached"] = False

            # ------------------------------------------------
            # Cache ONLY successful results
            # ------------------------------------------------

            if result.get(
                "status"
            ) == "success":

                self.cache.set(
                    cache_key,
                    result,
                )

            return result

        # ----------------------------------------------------
        # Manager-level timeout
        # ----------------------------------------------------

        except FuturesTimeoutError:

            future.cancel()

            return {
                "status": "timeout",
                "provider": provider_name,
                "ioc": ioc.to_dict(),
                "timeout_seconds": (
                    self.timeout_seconds
                ),
                "cached": False,
            }

        # ----------------------------------------------------
        # Provider-raised timeout
        # ----------------------------------------------------

        except TimeoutError as exc:

            return {
                "status": "timeout",
                "provider": provider_name,
                "ioc": ioc.to_dict(),
                "error": str(exc),
                "timeout_seconds": (
                    self.timeout_seconds
                ),
                "cached": False,
            }

        # ----------------------------------------------------
        # Provider rate limit
        # ----------------------------------------------------

        except RateLimitError as exc:

            result = {
                "status": "rate_limited",
                "provider": provider_name,
                "ioc": ioc.to_dict(),
                "error": str(exc),
                "cached": False,
            }

            if exc.retry_after is not None:
                result["retry_after"] = (
                    exc.retry_after
                )

            return result

        # ----------------------------------------------------
        # Generic provider failure
        # ----------------------------------------------------

        except Exception as exc:

            return {
                "status": "error",
                "provider": provider_name,
                "ioc": ioc.to_dict(),
                "error": str(exc),
                "cached": False,
            }

        finally:

            executor.shutdown(
                wait=False,
                cancel_futures=True,
            )
