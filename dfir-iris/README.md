# DFIR-IRIS — forensic investigation

`case-template.json` defines two forensic case templates (exfiltration,
malware) with task lists, evidence types, and a mandatory chain-of-custody log.

## Role in the flow
- TheHive cases that need forensic depth escalate to DFIR-IRIS (PB4 creates one
  directly for exfiltration).
- Timeline reconstruction merges Wazuh FIM + Zeek conn.log + Sysmon + Arkime
  sessions. Evidence (PCAP, memory dumps, disk images) is attached with custody
  tracking.

## Deploy
DFIR-IRIS ships its own compose (`dfir-iris/iris-web`). Deploy it standalone,
then load these templates via the IRIS API (`/manage/case-templates/add`). Bind
the TheHive→IRIS escalation with the IRIS API key (`$IRIS_API_KEY`).

> Status: templates defined; live instance + API binding is a follow-up. See
> `STATUS.md`.
