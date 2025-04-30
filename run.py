from kb_integration_demo import app
from config import Config

if __name__ == "__main__":
    app.run(host=Config.APP_HOST, port=int(Config.APP_PORT))
