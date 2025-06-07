# IP Guardian

## Main Flow

```mermaid
flowchart TD
  A["HTTP Request Reception"] --> V1{"IP Format & Header Validation"}
  V1 -->|"Invalid Format"| Y["Request Rejected"]:::danger
  V1 -->|"Missing Headers"| Y
  V1 -->|"Validation Passed"| DEVICE_INFO["Device Fingerprint & Session Management"]:::module
  
  DEVICE_INFO --> L{"IP Category Classification"}
  L -->|"Block List Match"| BT["Block Status Check"]
  L -->|"Internal Network Unlabeled"| DYNAMIC_SCORE
  L -->|"External Network Unlabeled"| ABUSE_CHECK["AbuseIPDB Threat Intelligence Check"]:::module
  L -->|"Whitelist Match"| Z_ALLOW["Request Allowed"]:::success
  L -->|"Blacklist Match"| Y
  
  BT --> BD{"Request Frequency Evaluation"}
  BD -->|"Normal Frequency"| BF["Block Time Extension (Exponential)"] --> Y
  BD -->|"Abnormal Frequency"| Y
  
  ABUSE_CHECK -->|"Malicious IP Confirmed"| Y
  ABUSE_CHECK -->|"Normal Reputation"| DYNAMIC_SCORE
  ABUSE_CHECK -->|"Check Failed/No Token"| DYNAMIC_SCORE
  
  DYNAMIC_SCORE["Multi-dimensional Suspicious Activity Detection"]:::module --> SECURE_RESULT["Comprehensive Security Assessment & Risk Determination"]:::module
  
  SECURE_RESULT -->|"Security Check Passed"| Z_ALLOW
  SECURE_RESULT -->|"Risk Exceeds Threshold"| Y
  
  classDef success fill:#2ecc71,stroke:#27ae60,color:#ffffff
  classDef danger fill:#e74c3c,stroke:#c0392b,color:#ffffff
  classDef module fill:#3498db,stroke:#2980b9,color:#ffffff
  
  class A,V1,L main
```

## Device Fingerprint & Session Management

```mermaid
graph TD
    A[HTTP Request Reception] --> E{Proxy Header Detection}
    E -->|CF-Connecting-IP| F[Extract Real IP from Headers]
    E -->|X-Forwarded-For| F
    E -->|X-Real-IP| F
    E -->|Other Proxy Headers| F
    E -->|No Headers| G[Use RemoteAddr]
    
    F --> H[IP Address Parse]
    G --> H
    H --> I[Internal IP Check]
    
    I --> J{Proxy Headers Present?}
    J -->|Yes| K[Proxy Chain Integrity Check]
    J -->|No| L[Direct Connection IP Check]
    
    K --> M{All Proxy Chain Internal?}
    L --> N{Direct IP Internal?}
    
    M -->|Yes| O[IsPrivate=true, Level=1]
    M -->|No| P[IsPrivate=false, Level=0]
    N -->|Yes| O
    N -->|No| P
    
    O --> Q[User-Agent Header Parse]
    P --> Q
    
    Q --> R[Platform Info Extract]
    Q --> S[Browser Info Extract]
    Q --> T[Device Type Identify]
    Q --> U[OS Identify]
    
    R --> V[Device Base Info Structure]
    S --> V
    T --> V
    U --> V
    
    V --> X{Session Cookie Exists?}
    
    X -->|Yes| Y[Session ID Signature Parse]
    Y --> Z{HMAC-SHA256 Valid?}
    Z -->|Yes| AA[Extend Session Cookie 30 days]
    AA --> BB[Return Existing Session ID]
    
    Z -->|No| CC[Generate New Session ID Signature]
    X -->|No| CC
    
    CC --> DD[Generate 32-char Session ID]
    DD --> EE[Calculate HMAC-SHA256]
    EE --> FF[Combine s:sessionID.signature]
    FF --> GG[Set Session Cookie 30d Sliding]
    GG --> HH[Return New Session ID]
    
    BB --> JJ{Device Cookie Exists?}
    HH --> JJ
    
    JJ -->|Yes| KK[Read Existing Device Key]
    KK --> LL[Extend Device Cookie 365d]
    
    JJ -->|No| MM[Generate UUID Device Key]
    MM --> NN[Set Device Cookie 365d Sliding]
    
    LL --> OO[Complete Device Info]
    NN --> OO
    OO --> PP[Platform+Browser+Type+OS+Key]
    PP --> QQ[SHA256 Device Fingerprint]
    QQ --> TT[Return Device Fingerprint & Session]
    
    subgraph "IP Detection & Proxy Validation"
        E
        F
        G
        H
        I
        J
        K
        L
        M
        N
    end
    
    subgraph "User-Agent Parse Engine"
        R
        S
        T
        U
    end
    
    subgraph "Session Management (30d Sliding)"
        X
        Y
        Z
        AA
        CC
        DD
        EE
        FF
        GG
    end
    
    subgraph "Device Fingerprint Tracking (365d Sliding)"
        JJ
        KK
        LL
        MM
        NN
        OO
        PP
        QQ
    end
```

### AbuseIPDB Check

```mermaid
flowchart TD
  START["External IP"] --> TOKEN{"AbuseIPDB Token Check"}
  
  TOKEN -->|"Token Not Found"| NO_TOKEN["Skip Threat Intelligence Check"]
  TOKEN -->|"Token Found"| CACHE{"AbuseIPDB Cache Check"}
  
  CACHE -->|"Cache Hit"| REPUTATION{"IP Reputation Validation"}
  CACHE -->|"Cache Miss"| API_QUERY["AbuseIPDB API Query & Cache Update (24h)"]
  
  API_QUERY --> API_STATUS{"API Response Status"}
  API_STATUS -->|"Query Failed"| API_FAIL["API Query Failed"]
  API_STATUS -->|"Query Successful"| REPUTATION
  
  REPUTATION -->|"Malicious IP Confirmed"| MALICIOUS["Mark as Threat IP"]
  REPUTATION -->|"Normal Reputation"| CLEAN["Mark as Clean IP"]
  
  NO_TOKEN --> SKIP["Skip Check Result"]
  API_FAIL --> SKIP
  MALICIOUS --> RESULT["Return Check Result"]
  CLEAN --> RESULT
  SKIP --> RESULT
```

## Dynamic Score

```mermaid
graph TD
    A[Start Suspicious Activity Detection] --> B[Build Request Data Structure]
    B --> C[Initialize Anomaly Flags & Risk Score]
    
    C --> D[Basic Correlation Pattern Detection]
    D --> E[Execute Redis Pipeline Batch]
    E --> F[Session-IP Correlation Check]
    E --> G[IP-Device Correlation Check]
    E --> H[Device-IP Correlation Check]
    
    F --> I{Session Associated IPs > 4?}
    G --> J{IP Associated Devices > 8?}
    H --> K{Device Associated IPs > 8?}
    
    I -->|Yes| L[+25pts Multi-IP Session Anomaly]
    J -->|Yes| M[+20pts Multi-Device IP Anomaly]
    K -->|Yes| N[+15pts Multi-IP Device Anomaly]
    
    I -->|No| O[Geographic Behavior Detection]
    J -->|No| O
    K -->|No| O
    L --> O
    M --> O
    N --> O
    
    O --> P{GeoIP Detector Available?}
    P -->|No| Q[Skip Geo Detection]
    P -->|Yes| R[Get IP Geolocation Data]
    
    R --> S[Write Location History to Redis]
    S --> T[Analyze 1h Location Changes]
    
    T --> U{More than 4 Countries in 1h?}
    T --> V{Frequent Country Switching?}
    T --> W{Abnormal Quick Location Changes?}
    
    U -->|Yes| X[+15pts Geographic Jump Anomaly]
    V -->|Yes| Y[+20pts Frequent Country Switch]
    W -->|Yes| Z[+25pts Rapid Geo Change Anomaly]
    
    Q --> AA[Time Pattern Detection]
    U -->|No| AA
    V -->|No| AA
    W -->|No| AA
    X --> AA
    Y --> AA
    Z --> AA
    
    AA --> BB[Get Last Request Timestamp]
    BB --> CC[Calculate Request Interval]
    CC --> DD[Analyze Interval Patterns]
    
    DD --> EE{Too Regular Intervals?}
    DD --> FF{Session Duration > 2h?}
    
    EE -->|Yes| GG[+25pts Regular Bot Pattern]
    FF -->|Yes| HH[+15pts Long Session Anomaly]
    
    EE -->|No| II[Device Fingerprint Correlation]
    FF -->|No| II
    GG --> II
    HH --> II
    
    II --> JJ[Check Multi-Session Same Fingerprint]
    JJ --> KK{Fingerprint Sessions > 2?}
    KK -->|Yes| LL[+25pts Multi-Session Fingerprint]
    KK -->|No| MM[Calculate Total Risk Score]
    LL --> MM
    
    MM --> NN{Anomaly Types > 4?}
    NN -->|Yes| OO[+25pts Multi-Anomaly Weight]
    NN -->|No| PP[Cap Risk Score at 100]
    OO --> PP
    
    PP --> QQ[Write Results to Redis]
    QQ --> RR{Anomalies OR Risk Score > 50?}
    
    RR -->|Yes| SS[IsSuspicious = true]
    RR -->|No| TT[IsSuspicious = false]
    
    SS --> UU[Return DetectionResult]
    TT --> UU
    
    subgraph "Basic Correlation Pattern Detection (Redis Pipeline)"
        E
        F
        G
        H
        I
        J
        K
    end
    
    subgraph "Geographic Behavior Detection (GeoIP)"
        R
        S
        T
        U
        V
        W
    end
    
    subgraph "Time Pattern Detection (Interval Analysis)"
        BB
        CC
        DD
        EE
        FF
    end
    
    subgraph "Device Fingerprint Correlation (Session Track)"
        JJ
        KK
    end
    
    subgraph "Risk Assessment & Result"
        MM
        NN
        QQ
        RR
    end
```

## Risk Determination

```mermaid
flowchart TD
    A[Start Security Check] --> B[Get Risk Score & Device Info]
    B --> C{Check Risk Threshold}
    
    C -->|"Risk Score > 50"| REJECT[Reject Request - Risk Score Exceeds Threshold]:::danger
    C -->|"Risk Score ≤ 50"| D[Check Requests Per Minute]
    
    D --> E{Requests Per Minute Check}
    E -->|"≤ 60 req/min"| ALLOW[Pass Security Check]:::success
    E -->|"> 60 req/min"| F[Check Block Threshold]
    
    F --> G{Block Count Check}
    G -->|"< ? times/1min"| H[Set Temporary Block]
    G -->|"≥ ? times/1min"| I[Add to Permanent Blacklist]
    
    H --> J[Check Existing Block Records]
    J --> K{Already Blocked?}
    K -->|"Yes"| L[Extend Block Time - Exponential Growth]
    K -->|"No"| M[First Block - 1 Hour]
    
    L --> N[Calculate New Block Time]
    N --> O{New Time > 30 Days?}
    O -->|"Yes"| P[Set Maximum 30-Day Block]
    O -->|"No"| Q[Set Double Block Time]
    
    P --> TEMP_BLOCK[Temporary Block Complete]:::warning
    Q --> TEMP_BLOCK
    M --> TEMP_BLOCK
    
    I --> R[Add to Redis Blacklist]
    R --> T[Add to Local JSON Blacklist - Persistent]
    T --> U{Check Email Configuration}
    
    U -->|"Email Configured"| V[Send Email Notification]
    U -->|"No Email Config"| BLACKLIST_DONE[Permanent Blacklist Complete]:::danger
    
    V --> X[Send Alert Email]
    X --> Y{Email Send Status}
    Y -->|"Success"| BLACKLIST_DONE
    Y -->|"Failed"| Z[Log Error but Continue]
    Z --> BLACKLIST_DONE
```