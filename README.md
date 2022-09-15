# Wazuh Teams Integration

## Setup Teams

Setup the webhook connector in Teams for the channel where you want alerts posted.

## Testing

Edit the webhookUrl in run&#46;sh to test your webhook to Teams. 

## ossec.conf Configuration

Add the following integration configuration to ossec.conf via the web UI or
direct. Replace WEBHOOK URL with the URL you generated from Teams. You can have
multiple integration blocks in your ossec.conf. You can configure multiple
options in the integration such as levels and rules. Refer to the following
link for all options. It is important the integration name starts with
"custom-" otherwise Wazuh will reject the integration.

[Integrator Daemon Configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html#reference-ossec-integration)

```
<integration>
  <name>custom-teams</name>
  <level>3</level>
  <hook_url>WEBHOOK URL</hook_url> 
  <alert_format>json</alert_format> 
</integration>
```

Make sure you save the configuration and use the Restart Manager button.

## Alert Script

Copy the custom-teams and custom-teams&#46;py file to /var/ossec/integrations/
Use the following commands to allow Wazuh to execute the file.
```
chmod 750 /var/ossec/integrations/custom-teams
chown root:wazuh /var/ossec/integrations/custom-teams
chmod 750 /var/ossec/integrations/custom-teams.py
chown root:wazuh /var/ossec/integrations/custom-teams.py
```

## Verify
Trigger an alert in Wazuh and validate you're receiving them in Teams.

## Troubleshooting
Use a combination of the ossec.log and microsoft-teams.log files located in the
following directory:

```
/var/ossec/logs
```

## Customize - Advanced
Browse to the following location to customize the card in custom-teams&#46;py.

[Card Designer](https://adaptivecards.io/designer/)

Be sure to follow the correct formatting when replacing content in the script.
