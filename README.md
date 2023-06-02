# reversinglabs-siem-rules

This repository contains SIEM rules to aid in detecting the tactics, techniques, and procedures (TTPs) used by various threat actors.

## Categories

### [Ransomware](./Ransomware/)

### [Malware](./Malware/)

## Contents
Each group will have the following subdirectories containing detection rules and other useful resources:

### Sigma
This folder contains [Sigma](https://github.com/SigmaHQ/sigma) rules that can be used to detect threat actor TTPs.

### KQL
This folder contains KQL queries that can be used to identify threat actor TTPs in Microsoft Sentinel and Microsoft Defender for Endpoint. Use these queries to hunt for threats, or create analytic rules to generate alerts and incidents.

### YARA
This optional folder contains related YARA rules that can be used to identify malware.

# License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.