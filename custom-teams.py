#!/usr/bin/env python3

import sys
import json
import logging
import os
import urllib3
import ssl
from datetime import datetime

class TeamsWebhookException(Exception):
    pass

class ConnectorCard:
    def __init__(self, hookurl, payload, http_timeout=60):
        cert_reqs = ssl.CERT_NONE
        self.http = urllib3.PoolManager(cert_reqs = cert_reqs)
        self.payload = payload
        self.hookurl = hookurl
        self.http_timeout = http_timeout

    def send(self):
        logging.debug(self.payload)
        headers = {"Content-Type":"application/json"}
        r = self.http.request(
                'POST',
                f'{self.hookurl}',
                body=json.dumps(self.payload).encode('utf-8'),
                headers=headers, timeout=self.http_timeout)
        if r.status == 200:
            now = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            logging.info("Sent Alert at %s", now)
            return True
        else:
            logging.fatal(r.reason)
            raise TeamsWebhookException(r.reason)

DEBUG = False
for i in sys.argv:
    if i == "DEBUG":
        DEBUG = True

# Setup logging
logLocation = "/var/ossec/logs/microsoft-teams.log"

if DEBUG:
    logging.basicConfig(
            handlers=[
                logging.StreamHandler()
            ],
            level = logging.DEBUG
    )
else:
    if not os.path.exists(logLocation):
        open(logLocation, "w+").close()
    logging.basicConfig(
            filename = logLocation,
            level = logging.INFO
    )

#Get the alert json
logging.debug("Executing Microsoft Teams Plugin")

#Open the alert file
alertFile = open(sys.argv[1])

#load json into a python object
alert = json.loads(alertFile.read())
logging.debug(alert)

webhook = sys.argv[3]
logging.debug(webhook)

payload = {
        "type": "message",
        "attachments":[
        {
            "contentType":"application/vnd.microsoft.card.adaptive",
            "contentUrl": "",
            "content": {
                "type": "AdaptiveCard",
                "body": [
                    {
                        "type": "TextBlock",
                        "size": "Large",
                        "weight": "Bolder",
                        "text": "Wazuh Alert"
                    },
                    {
                        "type": "TextBlock",
                        "text": alert["rule"]["description"],
                        "wrap": True
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "Alert ID",
                                "value": alert["id"]
                            },
                            {
                                "title": "Timestamp",
                                "value": alert["timestamp"]
                            },
                            {
                                "title": "Agent ID",
                                "value": alert["agent"]["id"]
                            },
                            {
                                "title": "Agent Name",
                                "value": alert["agent"]["name"]
                            }
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": "Rule",
                        "wrap": True,
                        "size": "Large",
                        "weight": "Bolder"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "ID",
                                "value": alert["rule"]["id"]
                            },
                            {
                                "title": "Level",
                                "value": alert["rule"]["level"]
                            },
                            {
                                "title": "Groups",
                                "value": ' '.join(alert["rule"]["groups"])
                            }
                        ]
                    }
                ],
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.5",
            }
        }
    ]
}

myTeamsMessage = ConnectorCard(webhook, payload)
myTeamsMessage.send()
