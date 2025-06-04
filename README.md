# IP Guardian (Golang)

## Middleware

- flow
  ```mermaid
  flowchart TD
  A["Request Received"] --> V1{"Check IP Format & Headers"}
  V1 -->|"Invalid IP"| Y["Reject Request"]:::danger
  V1 -->|"Missing Headers"| Y
  V1 -->|"Valid Format & Headers"| L{"Check IP Category"}
  L -->|"In Block List"| BT["Check Block Records"]
  L -->|"Internal IP No Flag"| R["Apply Default Risk Score"]
  L -->|"External IP No Flag"| T{"Check AbuseIPDB Token"}
  BT --> BD{"Evaluate Request Frequency"}
  BD -->|"Below Threshold"| BF["Extend Block Duration (Exponential)"] --> Y
  BD -->|"Above Threshold"| BM["Add to Permanent Blacklist (Local JSON)"]
  BM --> W{"Check Email Config"}
  W -->|"Email Set"| U["Send Email Notification"] --> Y
  W -->|"No Email Set"| Y
  T -->|"No Token"| R
  T -->|"Token Set"| D{"Check AbuseIPDB Cache"}
  D -->|"Cache Exists"| E{"Verify IP Reputation"}
  D -->|"No Cache"| F["Query AbuseIPDB & Cache (24h)"]
  F --> M{"API Request Status"}
  M -->|"Request Failed"| R
  M -->|"Request Success"| E
  
  E -->|"Normal Reputation"| G1["Check Device Fingerprint"]
  G1 --> G4{"Compare Fingerprint Anomalies"}
  G4 --> G5{"Analyze IP Pattern Changes"}
  G5 --> H["Calculate Time Decay Factor"]
  H --> N["Calculate Combined Risk Score"]
  N --> I{"Assess Geo & Device Risk"}
  I -->|"High Risk +20pts"| J{"Check Risk Threshold"}
  I -->|"Normal Risk"| J
  
  J -->|"Acceptable Risk"| Q1{"Check Requests per Minute"}
  Q1 -->|"Exceeds Limit"| Q2{"Check Block Threshold"}
  
  J -->|"Exceeds Threshold"| Y
  Q2 -->|"Exceeded"| BM
  L -->|"In Whitelist"| Z["Allow Access"]:::success
  L -->|"In Blacklist"| Y
  Q1 -->|"Within Limit"| Z
  Q2 -->|"Not Exceeded"| Y
  E -->|"Malicious Confirmed"| Y
  R --> I
  
  classDef success fill:#2ecc71,stroke:#27ae60,color:#ffffff
  classDef danger fill:#e74c3c,stroke:#c0392b,color:#ffffff
  ```
