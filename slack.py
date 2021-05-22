from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import os


def send_alert(msg):
    slack_token = os.environ["SLACK_BOT_TOKEN"]
    client = WebClient(token=slack_token)
    response = client.chat_postMessage(channel="#alerts",text=msg)
        
if __name__ == '__main__':
    send_alert('Testing testing 123')
