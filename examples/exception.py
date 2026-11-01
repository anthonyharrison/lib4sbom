from loguru import logger

from lib4sbom.exception import SBOMParserException
from lib4sbom.parser import SBOMParser

parser = SBOMParser()
try:
    parser.parse_file("empty.json")
except FileNotFoundError as err:
    # logger.opt(exception=err).debug("Traceback for SBOM parsing error")
    logger.error(f"{err}: {err.__cause__}")
except SBOMParserException as err:
    logger.opt(exception=err).debug("Traceback for SBOM parsing error")
    logger.error(f"{err}: {err.__cause__}")
