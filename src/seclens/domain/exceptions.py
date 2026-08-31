class SeclensError(Exception):
    """Base exception for all seclens domain errors."""


class ProductNotFoundError(SeclensError):
    def __init__(self, query: str):
        self.query = query
        super().__init__(f"No product found for: {query}")


class InvalidCPEError(SeclensError):
    def __init__(self, cpe_uri: str):
        self.cpe_uri = cpe_uri
        super().__init__(f"Invalid CPE URI: {cpe_uri}")


class DataSyncError(SeclensError):
    def __init__(self, source: str, reason: str):
        self.source = source
        self.reason = reason
        super().__init__(f"Sync failed for {source}: {reason}")


class InsufficientDataError(SeclensError):
    """Raised when there's not enough data to compute a meaningful score."""

    def __init__(self, product: str):
        self.product = product
        super().__init__(f"Insufficient vulnerability data for: {product}")
