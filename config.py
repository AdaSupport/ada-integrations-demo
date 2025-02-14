import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    integration_id = os.getenv("ADA_INTEGRATION_ID")
    """The ID for the integration you created"""

    integration_secret = os.getenv("ADA_INTEGRATION_SECRET")
    """The OAuth client secret for the integration you created"""

    creator_bot_handle = os.getenv("ADA_CREATOR_BOT_HANDLE")
    """The handle for the bot that the integration was created under"""
