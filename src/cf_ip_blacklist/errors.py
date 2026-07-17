class BlacklistError(Exception):
    """Base error for expected application failures."""


class ConfigurationError(BlacklistError):
    pass


class CloudflareError(BlacklistError):
    pass


class SafetyError(BlacklistError):
    pass
