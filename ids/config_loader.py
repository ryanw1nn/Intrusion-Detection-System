"""
Configuration loader for the IDS.

Loads configuration from YAML file with validation and defaults.
"""

import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List
import os

logger = logging.getLogger(__name__)