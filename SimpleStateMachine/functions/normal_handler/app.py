import json
import logging
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context) -> bool:
    """
    Expects event with keys: userId (str), userType (str), Name (str)
    Logs details and returns False for Normal.
    """
    user_id = event.get("userId")
    user_type = event.get("userType")
    name = event.get("Name")

    if not isinstance(user_id, str) or not isinstance(user_type, str) or not isinstance(name, str):
        logger.error(
            "Invalid input. Expected strings for userId, userType, and Name. Received: %s",
            json.dumps(event),
        )
        raise ValueError("Invalid input: userId, userType, and Name must be strings")

    logger.info("Normal Lambda invoked with userId=%s, userType=%s, Name=%s", user_id, user_type, name)
    return False