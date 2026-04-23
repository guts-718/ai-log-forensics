import json
import re
def parse_log(raw):
    """
    Supports both:
    - dict input (preferred)
    - raw string (fallback)
    """

     # already structured (preferred)
    if isinstance(raw, dict):
        return raw

    # fallback string parsing
    log = {}

    parts = raw.split()

    for part in parts:
        if "=" in part:
            k, v = part.split("=")
            log[k] = v

    return log