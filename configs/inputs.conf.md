[splunktcp://9997]
connection_host = <SPLUNK_HOST_IP>

[monitor:///var/log/snort/snort.alert.fast]
disabled = false
index = main
sourcetype = snort_alert_full
source = snort

[monitor:///var/log/auth.log]
disabled = false
index = main
sourcetype = linux_secure

[monitor:///home/splunkufw/suricatatest/logs/eve.json]
disabled = false
index = suricata
sourcetype = suricata

[monitor:///opt/shopsecure/app.log]
disabled = false
index = main
sourcetype = shopsecure:app

