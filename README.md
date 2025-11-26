# sky-log-analyzer

Sama Valiyeva​ SecureLog Analyzer (Log Analysis & CTI Project) - Developed a Python-based tool to automate web server log analysis and threat intelligence correlation. 

Parsed access.log files to extract key fields (IP, Timestamp, Status Code) and performed automated threat intelligence enrichment for each unique IP. Integrated with external CTI sources, including AbuseIPDB, Cisco Talos, and the VirusTotal API, to gather reputation data. Implemented statistical analysis to f lag high-risk IPs based on malicious reports and 4xx error rates. Utilized a generative AI o translate raw technical threat data into simple, actionable explanations for final report generation