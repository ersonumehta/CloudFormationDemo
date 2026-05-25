import json
import logging
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context) -> Any:
    """
    Expects event with key: lambdaResult (Any/usually bool)
    Logs the message and returns the same value unchanged so the state machine can continue.
    """
    value = event.get("lambdaResult")
    logger.info("Logger Lambda: lambda returned: %s", json.dumps(value))
    return value