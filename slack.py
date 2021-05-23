from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import config

def send_alert(msg):
    slack_token = config.get('slack.token')
    client = WebClient(token=slack_token)
    response = client.chat_postMessage(channel=config.get('slack.channel'),text=msg)

if __name__ == '__main__':
    send_alert('Testing testing 123')
