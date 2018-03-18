import logging

logger = logging.getLogger('main')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('log/xray.log')
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
