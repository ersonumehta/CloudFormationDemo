import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _extract_results(event: Any) -> Optional[List[Any]]:
    """
    Extracts parallel branch results from the Step Functions event.
    Preferred shape: { "results": [<admin_result>, <normal_result>] }
    Fallbacks supported for robustness:
      - event is already a list (parallel output passed directly)
      - event has keys: adminResult/normalResult
      - event has a single key 'lambdaResult' (legacy, single value)
    Returns a list or None if nothing meaningful found.
    """
    # If the event is already a list, treat it as parallel results
    if isinstance(event, list):
        return event

    if isinstance(event, dict):
        if "results" in event:
            return event.get("results")
        if "adminResult" in event or "normalResult" in event:
            return [event.get("adminResult"), event.get("normalResult")]
        if "lambdaResult" in event:
            # Legacy single result; normalize to list for unified logging
            return [event.get("lambdaResult")]

    return None


def lambda_handler(event: Dict[str, Any], context) -> Any:
    """
    Logger lambda for Step Functions.
    - Prints results from both Admin and Normal lambdas when invoked after a Parallel state.
    - Is tolerant of alternate shapes and legacy single-result payloads.
    - Returns the input event unchanged so the state machine can end with original data.
    """
    results = _extract_results(event)

    if isinstance(results, list):
        logger.info("Logger Lambda: parallel results count=%d", len(results))
        # By convention: branch[0] -> Admin, branch[1] -> Normal (based on Parallel branch order)
        if len(results) > 0:
            logger.info("Admin lambda result: %s", json.dumps(results[0]))
        if len(results) > 1:
            logger.info("Normal lambda result: %s", json.dumps(results[1]))
        # Log any extra results if present
        for idx in range(2, len(results)):
            logger.info("Extra branch %d result: %s", idx, json.dumps(results[idx]))
    else:
        # Fallback: log the entire incoming payload for visibility
        logger.info("Logger Lambda: received non-standard payload: %s", json.dumps(event))

    # Return the input unchanged so the state machine output reflects both results payload
    return event
