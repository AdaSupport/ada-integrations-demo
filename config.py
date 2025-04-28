import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    ADA_INTEGRATION_ID = os.getenv("ADA_INTEGRATION_ID")
    """The ID for the integration you created"""

    ADA_INTEGRATION_SECRET = os.getenv("ADA_INTEGRATION_SECRET")
    """The OAuth client secret for the integration you created"""

    ADA_CREATOR_BOT_HANDLE = os.getenv("ADA_CREATOR_BOT_HANDLE")
    """The handle for the bot that the integration was created under"""

    APP_HOST = os.getenv("APP_HOST")
    """The host to run the demo app on"""

    APP_PORT = os.getenv("APP_PORT")
    """The port to run the demo app on"""
