# Email Detection Signals - Complete Data Generation Documentation

## Overview

This document provides comprehensive guidance for generating realistic malicious and not-malicious email detection signal data. The dataset contains 68 detection signals used to classify emails as either "Malicious" or "Not Malicious".

---

## Table of Contents

1. [Signal Inventory (All 68 Signals)](#1-signal-inventory-all-68-signals)
2. [Signal Semantics (1=Good vs 1=Bad)](#2-signal-semantics)
3. [Signal Group Correlations](#3-signal-group-correlations)
4. [Cross-Group Correlations](#4-cross-group-correlations)
5. [Hard Dependency Rules](#5-hard-dependency-rules)
6. [Malicious Scenarios](#6-malicious-scenarios)
7. [Not-Malicious Scenarios](#7-not-malicious-scenarios)
8. [Realistic Value Ranges](#8-realistic-value-ranges)
9. [Data Generation Rules](#9-data-generation-rules)
10. [Validation Checklist](#10-validation-checklist)

---

## 1. Signal Inventory (All 68 Signals)

### 1.1 Sender Detection (5 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 0 | sender_known_malicious | bool | Sender in threat intelligence (1=malicious) |
| 1 | sender_domain_reputation_score | float | Domain reputation (1=good, 0=bad) |
| 2 | sender_spoof_detected | bool | Spoofing detected (1=spoofed) |
| 3 | sender_temp_email_likelihood | float | Temporary email probability (1=temp) |
| 41 | sender_name_similarity_to_vip | float | VIP impersonation score (1=impersonation) |

### 1.2 Authentication & Identity (6 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 4 | dmarc_enforced | bool | DMARC policy enforced (1=enforced) |
| 51 | spf_result | enum | SPF check result |
| 52 | dkim_result | enum | DKIM check result |
| 53 | dmarc_result | enum | DMARC check result |
| 54 | reverse_dns_valid | bool | Reverse DNS valid (1=valid) |
| 55 | tls_version | categorical | TLS version used |

### 1.3 File Analysis (7 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 5 | packer_detected | bool | Packer/obfuscator detected (1=detected) |
| 6 | any_file_hash_malicious | bool | Known malicious hash (1=malicious) |
| 7 | max_metadata_suspicious_score | float | Metadata suspicion (1=suspicious) |
| 8 | malicious_attachment_count | int | Count of malicious attachments |
| 9 | has_executable_attachment | bool | Executable present (1=yes) |
| 10 | unscannable_attachment_present | bool | Encrypted/unscannable (1=yes) |
| 67 | qrcode_analysis | int | QR code malicious (1=malicious, 0=safe) |

### 1.4 Sandbox Detection (15 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 11 | total_components_detected_malicious | int | Malicious components count |
| 12 | total_yara_match_count | int | YARA rule matches |
| 13 | total_ioc_count | int | IOC matches count |
| 14 | max_behavioral_sandbox_score | float | Behavior score (1=worst) |
| 15 | max_amsi_suspicion_score | float | AMSI score (1=worst) |
| 16 | any_macro_enabled_document | bool | Macros present (1=yes) |
| 17 | any_vbscript_javascript_detected | bool | Scripts detected (1=yes) |
| 18 | any_active_x_objects_detected | bool | ActiveX present (1=yes) |
| 19 | any_network_call_on_open | bool | Network call on open (1=yes) |
| 20 | max_exfiltration_behavior_score | float | Exfiltration score (1=worst) |
| 21 | any_exploit_pattern_detected | bool | Exploit detected (1=yes) |
| 22 | total_embedded_file_count | int | Embedded files count |
| 23 | max_suspicious_string_entropy_score | float | Entropy score (1=suspicious) |
| 24 | max_sandbox_execution_time | float | Execution time (seconds) |
| 25 | unique_parent_process_names | categorical | Process chain (JSON array) |

### 1.5 Return/Reply Path (6 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 26 | return_path_mismatch_with_from | bool | Return path mismatch (1=mismatch) |
| 27 | return_path_known_malicious | bool | Return path malicious (1=yes) |
| 28 | return_path_reputation_score | float | Return path reputation (1=good) |
| 29 | reply_path_known_malicious | bool | Reply path malicious (1=yes) |
| 30 | reply_path_diff_from_sender | bool | Reply differs from sender (1=yes) |
| 31 | reply_path_reputation_score | float | Reply path reputation (1=good) |

### 1.6 IP Address Detection (4 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 32 | smtp_ip_known_malicious | bool | IP in threat intel (1=malicious) |
| 33 | smtp_ip_geo | float | Geographic risk score (1=high risk) |
| 34 | smtp_ip_asn | float | ASN risk score (1=high risk) |
| 35 | smtp_ip_reputation_score | float | IP reputation (1=good) |

### 1.7 DNS/URL Detection (9 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 36 | domain_known_malicious | bool | Domain in threat intel (1=malicious) |
| 37 | url_count | int | Number of URLs in email |
| 38 | dns_morphing_detected | bool | Homograph attack (1=detected) |
| 39 | domain_tech_stack_match_score | float | Tech stack match (1=matched/good) |
| 57 | url_shortener_detected | bool | URL shortener used (1=yes) |
| 58 | url_redirect_chain_length | int | Redirect hops count |
| 60 | url_decoded_spoof_detected | bool | URL spoof detected (1=yes) |
| 61 | url_reputation_score | float | URL reputation (1=safe) |
| 64 | url_rendering_behavior_score | float | Render behavior (1=suspicious) |

### 1.8 BEC/VIP Impersonation (4 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 40 | is_high_risk_role_targeted | bool | High-value target (1=targeted) |
| 42 | urgency_keywords_present | bool | Urgency language (1=present) |
| 43 | request_type | categorical | Type of request |

### 1.9 Spam/Graymail Filtering (7 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 44 | content_spam_score | float | Spam likelihood (1=spam) |
| 45 | user_marked_as_spam_before | bool | Previously marked spam (1=yes) |
| 46 | bulk_message_indicator | bool | Bulk message (1=bulk) |
| 47 | unsubscribe_link_present | bool | Unsubscribe link (1=present) |
| 48 | marketing_keywords_detected | float | Marketing content (1=marketing) |
| 49 | html_text_ratio | float | Text to HTML ratio (1=normal/good) |
| 50 | image_only_email | bool | Image-only email (1=yes) |

### 1.10 Real-Time Link Scanning (6 signals)

| # | Signal Name | Type | Description |
|---|-------------|------|-------------|
| 56 | total_links_detected | int | Total hyperlinks count |
| 59 | final_url_known_malicious | bool | Final URL malicious (1=yes) |
| 62 | ssl_validity_status | enum | SSL certificate status |
| 63 | site_visual_similarity_to_known_brand | float | Brand similarity (1=phishing) |
| 65 | link_rewritten_through_redirector | bool | Security rewrite (1=yes) |
| 66 | token_validation_success | bool | Token valid (1=valid) |

---

## 2. Signal Semantics

### 2.1 TYPE A: 1 = BAD / MALICIOUS / RISKY (38 signals)

These signals indicate risk when value is 1 or high:

```
sender_known_malicious          → 1 = malicious sender
sender_spoof_detected           → 1 = spoofed
sender_temp_email_likelihood    → 1.0 = temporary email
sender_name_similarity_to_vip   → 1.0 = impersonation
packer_detected                 → 1 = obfuscated
any_file_hash_malicious         → 1 = known malware
max_metadata_suspicious_score   → 1.0 = most suspicious
has_executable_attachment       → 1 = executable present
unscannable_attachment_present  → 1 = can't scan
max_behavioral_sandbox_score    → 1.0 = worst behavior
max_amsi_suspicion_score        → 1.0 = most suspicious
any_macro_enabled_document      → 1 = macros present
any_vbscript_javascript_detected → 1 = scripts present
any_active_x_objects_detected   → 1 = ActiveX present
any_network_call_on_open        → 1 = network activity
max_exfiltration_behavior_score → 1.0 = exfiltration
any_exploit_pattern_detected    → 1 = exploit found
max_suspicious_string_entropy_score → 1.0 = high entropy
return_path_mismatch_with_from  → 1 = mismatch
return_path_known_malicious     → 1 = malicious
reply_path_known_malicious      → 1 = malicious
reply_path_diff_from_sender     → 1 = different (BEC indicator)
smtp_ip_known_malicious         → 1 = malicious IP
smtp_ip_geo                     → 1.0 = high risk region
smtp_ip_asn                     → 1.0 = high risk ASN
domain_known_malicious          → 1 = malicious domain
dns_morphing_detected           → 1 = homograph attack
is_high_risk_role_targeted      → 1 = VIP targeted
urgency_keywords_present        → 1 = urgency language
content_spam_score              → 1.0 = spam
user_marked_as_spam_before      → 1 = marked spam
bulk_message_indicator          → 1 = bulk email
image_only_email                → 1 = image only (evasion)
url_shortener_detected          → 1 = shortener used
final_url_known_malicious       → 1 = malicious URL
url_decoded_spoof_detected      → 1 = URL spoofing
site_visual_similarity_to_known_brand → 1.0 = phishing page
url_rendering_behavior_score    → 1.0 = suspicious behavior
qrcode_analysis                 → 1 = malicious QR code
```

### 2.2 TYPE B: 1 = GOOD / SAFE / TRUSTWORTHY (11 signals)

These signals indicate safety when value is 1 or high:

```
sender_domain_reputation_score  → 1.0 = good reputation
dmarc_enforced                  → 1 = policy enforced
return_path_reputation_score    → 1.0 = trustworthy
reply_path_reputation_score     → 1.0 = trustworthy
smtp_ip_reputation_score        → 1.0 = trustworthy
domain_tech_stack_match_score   → 1.0 = legitimate site
html_text_ratio                 → 1.0 = normal text ratio
reverse_dns_valid               → 1 = valid DNS
url_reputation_score            → 1.0 = safe URL
link_rewritten_through_redirector → 1 = security feature active
token_validation_success        → 1 = valid token
```

### 2.3 TYPE C: COUNTS (9 signals)

Higher values indicate more risk:

```
malicious_attachment_count      → higher = more malicious files
total_components_detected_malicious → higher = more malicious
total_yara_match_count          → higher = more matches
total_ioc_count                 → higher = more IOCs
total_embedded_file_count       → higher = more suspicious
max_sandbox_execution_time      → higher = possible evasion
url_count                       → higher = more risk
total_links_detected            → higher = more risk
url_redirect_chain_length       → higher = more evasion
```

### 2.4 TYPE D: CATEGORICAL (10 signals)

#### spf_result, dkim_result Values:
- `pass` - GOOD
- `fail` - BAD
- `softfail` - SUSPICIOUS
- `neutral` - NEUTRAL
- `none` - NO RECORD
- `temperror` - TEMPORARY ERROR
- `permerror` - PERMANENT ERROR

#### dmarc_result Values:
- `pass` - GOOD
- `fail` - BAD
- `none` - NO POLICY
- `temperror` - TEMPORARY ERROR
- `permerror` - PERMANENT ERROR

#### ssl_validity_status Values:
- `valid` - GOOD
- `expired` - BAD
- `self_signed` - BAD
- `mismatch` - BAD
- `revoked` - BAD
- `invalid_chain` - BAD
- `no_ssl` - BAD
- `error` - BAD

#### tls_version Values:
- `TLS 1.3` - BEST
- `TLS 1.2` - GOOD
- `TLS 1.1` - OUTDATED
- `TLS 1.0` - RISKY
- `SSL 3.0` - VERY RISKY
- `None` - NO ENCRYPTION

#### request_type Values:
- `none` - NEUTRAL (often legitimate)
- `meeting_request` - USUALLY LEGITIMATE
- `invoice_payment` - CONTEXT DEPENDENT
- `invoice_verification` - CONTEXT DEPENDENT
- `document_download` - CONTEXT DEPENDENT
- `link_click` - CONTEXT DEPENDENT
- `credential_request` - OFTEN MALICIOUS
- `wire_transfer` - OFTEN BEC
- `gift_card_request` - OFTEN BEC
- `sensitive_data_request` - OFTEN MALICIOUS
- `bank_detail_update` - OFTEN BEC
- `urgent_callback` - OFTEN MALICIOUS
- `executive_request` - OFTEN BEC
- `vpn_or_mfa_reset` - OFTEN MALICIOUS
- `legal_threat` - OFTEN MALICIOUS

#### unique_parent_process_names Format:
- JSON array: `["winword.exe", "cmd.exe", "powershell.exe"]`
- `NULL` when no attachment

---

## 3. Signal Group Correlations

### 3.1 Sender Signal Correlations

```
IF sender_known_malicious = 1
THEN sender_domain_reputation_score ∈ [0.0, 0.35]

IF sender_spoof_detected = 1
THEN sender_name_similarity_to_vip likely ∈ [0.6, 1.0]

IF sender_temp_email_likelihood ≥ 0.7
THEN sender_domain_reputation_score ∈ [0.0, 0.4]

IF sender_domain_reputation_score ≥ 0.8
THEN sender_known_malicious = 0
THEN sender_temp_email_likelihood ∈ [0.0, 0.2]
```

### 3.2 Authentication Signal Correlations

```
IF spf_result = pass OR dkim_result = pass
THEN dmarc_result CAN BE pass (depends on alignment)

IF spf_result = fail AND dkim_result = fail
THEN dmarc_result = fail (MANDATORY)

IF spf_result = none AND dkim_result = none
THEN dmarc_result ∈ [none, fail] (MANDATORY)
```

### 3.3 File Analysis Signal Correlations

```
IF any_file_hash_malicious = 1
THEN malicious_attachment_count ≥ 1 (MANDATORY)
THEN max_metadata_suspicious_score likely ∈ [0.5, 1.0]

IF malicious_attachment_count = 0
THEN any_file_hash_malicious = 0 (MANDATORY)

IF has_executable_attachment = 1
THEN packer_detected likely = 1 (for malware)

IF unscannable_attachment_present = 1
THEN any_file_hash_malicious likely = NULL (can't determine)
THEN malicious_attachment_count likely = NULL (can't scan)
```

### 3.4 Sandbox Signal Correlations

```
IF total_components_detected_malicious > 0
THEN total_yara_match_count likely > 0
THEN total_ioc_count likely > 0
THEN max_behavioral_sandbox_score ∈ [0.5, 1.0]

IF any_macro_enabled_document = 1
THEN any_vbscript_javascript_detected likely = 1
THEN max_amsi_suspicion_score ∈ [0.3, 1.0]
THEN has_executable_attachment = 0

IF any_network_call_on_open = 1
THEN max_exfiltration_behavior_score ∈ [0.3, 1.0]
```

### 3.5 Return/Reply Path Correlations

```
IF return_path_known_malicious = 1
THEN return_path_reputation_score ∈ [0.0, 0.3]

IF reply_path_known_malicious = 1
THEN reply_path_reputation_score ∈ [0.0, 0.3]

IF return_path_mismatch_with_from = 1
THEN sender_spoof_detected likely = 1
```

### 3.6 IP Address Correlations

```
IF smtp_ip_known_malicious = 1
THEN smtp_ip_reputation_score ∈ [0.0, 0.25] (MANDATORY)
THEN sender_known_malicious likely = 1

IF smtp_ip_reputation_score ≥ 0.8
THEN smtp_ip_known_malicious = 0
```

### 3.7 URL/DNS Signal Correlations

```
IF url_count = 0
THEN ALL URL-dependent signals = NULL (MANDATORY)

IF url_shortener_detected = 1
THEN url_redirect_chain_length ≥ 1 (MANDATORY)

IF domain_known_malicious = 1
THEN url_reputation_score ∈ [0.0, 0.35]
```

### 3.8 Spam/Graymail Correlations

```
IF bulk_message_indicator = 1 AND unsubscribe_link_present = 1
THEN likely legitimate marketing

IF image_only_email = 1
THEN html_text_ratio ∈ [0.0, 0.15] (MANDATORY)
```

---

## 4. Cross-Group Correlations

### 4.1 Sender ↔ IP Address

```
IF sender_known_malicious = 1
THEN smtp_ip_known_malicious probability = 0.7
THEN smtp_ip_reputation_score ∈ [0.0, 0.4]
```

### 4.2 Sender ↔ Authentication

```
IF sender_spoof_detected = 1
THEN spf_result ∈ [fail, softfail, none] (90% probability)
THEN return_path_mismatch_with_from likely = 1
```

### 4.3 File Analysis ↔ Sandbox

```
IF any_file_hash_malicious = 1
THEN total_components_detected_malicious ≥ 1
THEN max_behavioral_sandbox_score ≥ 0.5

IF has_executable_attachment = 1
THEN packer_detected probability = 0.6
THEN max_suspicious_string_entropy_score ∈ [0.5, 1.0]
```

### 4.4 URL/DNS ↔ Link Scanning

```
IF domain_known_malicious = 1
THEN final_url_known_malicious likely = 1
THEN url_reputation_score ∈ [0.0, 0.35]

IF site_visual_similarity_to_known_brand ≥ 0.8
THEN phishing attack indicated
THEN url_reputation_score ∈ [0.0, 0.3]
```

### 4.5 BEC ↔ Sender ↔ Return/Reply

```
IF sender_name_similarity_to_vip ≥ 0.7
AND is_high_risk_role_targeted = 1
AND urgency_keywords_present = 1
THEN reply_path_diff_from_sender = 1 (90% probability)
THEN request_type ∈ [wire_transfer, gift_card_request] (80% probability)
```

---

## 5. Hard Dependency Rules

### RULE 1: URL Dependency (MANDATORY)

```
IF url_count = 0 THEN:
  • total_links_detected = 0
  • url_shortener_detected = NULL
  • url_redirect_chain_length = NULL
  • domain_known_malicious = NULL
  • final_url_known_malicious = NULL
  • dns_morphing_detected = NULL
  • url_decoded_spoof_detected = NULL
  • url_reputation_score = NULL
  • ssl_validity_status = NULL
  • site_visual_similarity_to_known_brand = NULL
  • url_rendering_behavior_score = NULL
  • domain_tech_stack_match_score = NULL
  • link_rewritten_through_redirector = NULL
  • token_validation_success = NULL
```

### RULE 2: Attachment Dependency (MANDATORY)

```
IF NO ATTACHMENT PRESENT THEN:
  • packer_detected = NULL
  • any_file_hash_malicious = NULL
  • max_metadata_suspicious_score = NULL
  • malicious_attachment_count = NULL
  • has_executable_attachment = NULL
  • unscannable_attachment_present = NULL
  • total_components_detected_malicious = NULL
  • total_yara_match_count = NULL
  • total_ioc_count = NULL
  • max_behavioral_sandbox_score = NULL
  • max_amsi_suspicion_score = NULL
  • any_macro_enabled_document = NULL
  • any_vbscript_javascript_detected = NULL
  • any_active_x_objects_detected = NULL
  • any_network_call_on_open = NULL
  • max_exfiltration_behavior_score = NULL
  • any_exploit_pattern_detected = NULL
  • total_embedded_file_count = NULL
  • max_suspicious_string_entropy_score = NULL
  • max_sandbox_execution_time = NULL
  • unique_parent_process_names = NULL
```

### RULE 3: Hash-Count Dependency (MANDATORY)

```
IF any_file_hash_malicious = 1
THEN malicious_attachment_count ≥ 1

IF malicious_attachment_count = 0
THEN any_file_hash_malicious = 0
```

### RULE 4: URL Shortener Dependency (MANDATORY)

```
IF url_shortener_detected = 1
THEN url_redirect_chain_length ≥ 1

IF url_redirect_chain_length = 0
THEN url_shortener_detected = 0
```

### RULE 5: Image-Only Dependency (MANDATORY)

```
IF image_only_email = 1
THEN html_text_ratio ∈ [0.0, 0.15]

IF html_text_ratio ≥ 0.5
THEN image_only_email = 0
```

### RULE 6: Threat Intel Reputation Dependency (MANDATORY)

```
IF sender_known_malicious = 1
THEN sender_domain_reputation_score ∈ [0.0, 0.35]

IF smtp_ip_known_malicious = 1
THEN smtp_ip_reputation_score ∈ [0.0, 0.25]

IF return_path_known_malicious = 1
THEN return_path_reputation_score ∈ [0.0, 0.30]

IF reply_path_known_malicious = 1
THEN reply_path_reputation_score ∈ [0.0, 0.30]

IF domain_known_malicious = 1
THEN url_reputation_score ∈ [0.0, 0.35]
```

### RULE 7: DMARC Logic (MANDATORY)

```
IF spf_result = fail AND dkim_result = fail
THEN dmarc_result = fail

IF spf_result = none AND dkim_result = none
THEN dmarc_result ∈ [none, fail]
```

### RULE 8: Legitimate Email Constraints (MANDATORY)

```
IF label = "Not Malicious" THEN:
  • sender_known_malicious = 0
  • any_file_hash_malicious = 0 or NULL
  • malicious_attachment_count = 0 or NULL
  • smtp_ip_known_malicious = 0
  • domain_known_malicious = 0 or NULL
  • final_url_known_malicious = 0 or NULL
  • return_path_known_malicious = 0
  • reply_path_known_malicious = 0
  • total_components_detected_malicious = 0 or NULL
  • any_exploit_pattern_detected = 0 or NULL
```

---

## 6. Malicious Scenarios

### 6.1 Phishing Attacks

#### Obvious Phishing (Low Sophistication)
```
sender_known_malicious: 0-1 (40% chance = 1)
sender_domain_reputation_score: 0.05 - 0.35
sender_spoof_detected: 1
url_count: 1-5
url_shortener_detected: 1 (60% chance)
url_redirect_chain_length: 1-5
final_url_known_malicious: 1 (70% chance)
site_visual_similarity_to_known_brand: 0.65 - 0.98
ssl_validity_status: self_signed, expired, mismatch
spf_result: fail, softfail (70%)
urgency_keywords_present: 1 (75%)
request_type: credential_request
has_executable_attachment: NULL (URL-based)
```

#### Sophisticated Phishing (High Sophistication)
```
sender_domain_reputation_score: 0.5 - 0.72 (aged domain)
spf_result: pass
dkim_result: pass
dmarc_result: pass
sender_known_malicious: 0 (unknown)
smtp_ip_known_malicious: 0
domain_known_malicious: 0
site_visual_similarity_to_known_brand: 0.7 - 0.95 (still phishing)
ssl_validity_status: valid (60%)
```

### 6.2 Business Email Compromise (BEC)

#### CEO Fraud
```
sender_name_similarity_to_vip: 0.75 - 0.98
is_high_risk_role_targeted: 1
urgency_keywords_present: 1
request_type: wire_transfer, gift_card_request, executive_request
reply_path_diff_from_sender: 1
url_count: 0-1 (text-based attack)
content_spam_score: 0.15 - 0.40 (not spammy)
spf_result: fail, softfail (80%)
```

#### Sophisticated BEC (Compromised Account)
```
spf_result: pass
dkim_result: pass
dmarc_result: pass
sender_domain_reputation_score: 0.55 - 0.78
sender_name_similarity_to_vip: 0.85 - 0.99
reply_path_diff_from_sender: 1
urgency_keywords_present: 1
```

### 6.3 Malware Delivery

#### Executable Attachment
```
has_executable_attachment: 1
any_file_hash_malicious: 1 (70%)
malicious_attachment_count: 1-2
packer_detected: 1 (60%)
max_behavioral_sandbox_score: 0.65 - 0.98
total_yara_match_count: 2-15
total_ioc_count: 5-40
any_network_call_on_open: 1 (65%)
unique_parent_process_names: ["cmd.exe", "powershell.exe"]
```

#### Macro Document
```
any_macro_enabled_document: 1
any_vbscript_javascript_detected: 1
has_executable_attachment: 0
max_amsi_suspicion_score: 0.55 - 0.95
unique_parent_process_names: ["winword.exe", "cmd.exe", "powershell.exe"]
```

#### Ransomware
```
max_exfiltration_behavior_score: 0.75 - 0.99
any_network_call_on_open: 1
max_behavioral_sandbox_score: 0.8 - 0.99
total_ioc_count: 15-80
```

### 6.4 Spam/Scam

```
content_spam_score: 0.75 - 0.99
sender_domain_reputation_score: 0.03 - 0.25
sender_temp_email_likelihood: 0.6 - 0.95
bulk_message_indicator: 1
url_count: 2-12
spf_result: fail, none (70%)
```

### 6.5 Evasion Techniques

#### Encrypted Attachment
```
unscannable_attachment_present: 1
any_file_hash_malicious: NULL (can't scan)
malicious_attachment_count: NULL
max_behavioral_sandbox_score: NULL
urgency_keywords_present: 1 (password in body)
```

#### Image-Only Email
```
image_only_email: 1
html_text_ratio: 0.02 - 0.12
content_spam_score: 0.3 - 0.6 (evaded text analysis)
url_count: 1-3
```

#### QR Code Phishing
```
qrcode_analysis: 1
image_only_email: 1
url_count: 0 (no text URLs)
html_text_ratio: 0.02 - 0.12
```

---

## 7. Not-Malicious Scenarios

### 7.1 Enterprise Internal Email

```
sender_known_malicious: 0
sender_domain_reputation_score: 0.82 - 0.98
sender_spoof_detected: 0
spf_result: pass
dkim_result: pass
dmarc_result: pass
dmarc_enforced: 1
reverse_dns_valid: 1
tls_version: TLS 1.3, TLS 1.2
smtp_ip_known_malicious: 0
smtp_ip_reputation_score: 0.8 - 0.98
return_path_mismatch_with_from: 0
reply_path_diff_from_sender: 0
is_high_risk_role_targeted: 0
urgency_keywords_present: 0
request_type: none
content_spam_score: 0.02 - 0.18
bulk_message_indicator: 0
url_count: 0-2
```

### 7.2 SMB Business Email

```
sender_domain_reputation_score: 0.55 - 0.78 (lower but acceptable)
spf_result: pass, softfail (possible misconfiguration)
dkim_result: pass, none
dmarc_result: pass, none
dmarc_enforced: 0-1
```

### 7.3 Legitimate Marketing

```
bulk_message_indicator: 1
unsubscribe_link_present: 1 (REQUIRED for legitimate)
marketing_keywords_detected: 0.55 - 0.9
content_spam_score: 0.25 - 0.55 (higher but legitimate)
sender_domain_reputation_score: 0.62 - 0.88
url_count: 3-10
url_redirect_chain_length: 0-2 (tracking redirects)
spf_result: pass (90%)
dkim_result: pass (90%)
```

### 7.4 Transactional Email (Banks, Services)

```
sender_domain_reputation_score: 0.9 - 0.99
smtp_ip_reputation_score: 0.88 - 0.99
spf_result: pass
dkim_result: pass
dmarc_result: pass
dmarc_enforced: 1
ssl_validity_status: valid
url_reputation_score: 0.9 - 0.99
```

### 7.5 Legitimate Password Reset

```
request_type: credential_request (legitimate)
sender_domain_reputation_score: 0.9 - 1.0
spf_result: pass
dkim_result: pass
dmarc_result: pass
urgency_keywords_present: 0-1 (some legitimate urgency)
```

### 7.6 Legitimate with Attachment

```
any_file_hash_malicious: 0
malicious_attachment_count: 0
has_executable_attachment: 0
max_behavioral_sandbox_score: 0.0 - 0.12
total_yara_match_count: 0
total_components_detected_malicious: 0
any_exploit_pattern_detected: 0
unique_parent_process_names: ["winword.exe"] or NULL
```

### 7.7 Misconfigured Legitimate (False Positive Candidate)

```
spf_result: softfail, fail, none
dkim_result: none, fail
dmarc_result: none, fail
sender_domain_reputation_score: 0.35 - 0.55 (low but genuine)
return_path_mismatch_with_from: 0-1
BUT: sender_known_malicious = 0
     any_file_hash_malicious = 0
     domain_known_malicious = 0
```

---

## 8. Realistic Value Ranges

### 8.1 Float Signal Ranges

| Signal | Malicious Range | Legitimate Range | Overlap Zone |
|--------|-----------------|------------------|--------------|
| sender_domain_reputation_score | 0.05 - 0.55 | 0.55 - 0.98 | 0.45 - 0.65 |
| smtp_ip_reputation_score | 0.08 - 0.50 | 0.60 - 0.99 | 0.45 - 0.60 |
| max_behavioral_sandbox_score | 0.35 - 0.98 | 0.00 - 0.25 | 0.20 - 0.40 |
| content_spam_score | 0.45 - 0.98 | 0.02 - 0.45 | 0.35 - 0.55 |
| site_visual_similarity_to_known_brand | 0.55 - 0.99 | 0.00 - 0.20 | Minimal |
| url_reputation_score | 0.05 - 0.35 | 0.70 - 0.98 | Minimal |
| html_text_ratio | 0.05 - 0.50 | 0.40 - 0.95 | 0.35 - 0.55 |

### 8.2 Variance Rules

```
- Float values should have ±0.05 to ±0.15 random variance
- Never use exact round numbers (0.5, 0.8)
- Use values like 0.47, 0.83, 0.71, 0.29
- Ensure 3 decimal place precision
```

### 8.3 Realistic Distribution

```
MALICIOUS EMAILS:
- 40% obvious (most signals bad)
- 35% moderate (mixed signals)
- 25% sophisticated (many good signals, evading detection)

LEGITIMATE EMAILS:
- 50% perfect (all signals good)
- 40% imperfect (some suspicious signals)
- 10% edge cases (many suspicious signals but genuine)
```

---

## 9. Data Generation Rules

### 9.1 Variance Application

```python
def add_variance(base_value, variance=0.1, min_val=0.0, max_val=1.0):
    value = base_value + random.uniform(-variance, variance)
    return round(max(min_val, min(max_val, value)), 3)
```

### 9.2 Correlation Enforcement

Always enforce correlations after generating initial values:

```python
# Example: Fix sender reputation if known malicious
if record['sender_known_malicious'] == 1:
    if float(record['sender_domain_reputation_score']) > 0.35:
        record['sender_domain_reputation_score'] = random.uniform(0.05, 0.35)
```

### 9.3 NULL Handling

Use NULL (empty string in CSV) for:
- Non-applicable signals (no URL → URL signals NULL)
- Unscannable content (encrypted → file analysis NULL)

### 9.4 Process Chain Generation

For malicious attachments:
```python
malicious_chains = [
    ["winword.exe", "cmd.exe"],
    ["winword.exe", "powershell.exe"],
    ["winword.exe", "cmd.exe", "powershell.exe"],
    ["excel.exe", "cmd.exe"],
    ["wscript.exe"],
    ["mshta.exe"],
    ["rundll32.exe"],
]
```

For legitimate attachments:
```python
legitimate_chains = [
    ["winword.exe"],
    ["excel.exe"],
    ["acrord32.exe"],
    NULL (70% - no execution)
]
```

---

## 10. Validation Checklist

### 10.1 Mandatory Correlation Checks

- [ ] sender_known_malicious=1 → reputation ≤ 0.35
- [ ] smtp_ip_known_malicious=1 → reputation ≤ 0.25
- [ ] url_shortener_detected=1 → redirect_chain ≥ 1
- [ ] image_only_email=1 → html_text_ratio ≤ 0.15
- [ ] domain_known_malicious=1 → url_reputation ≤ 0.35
- [ ] return_path_known_malicious=1 → reputation ≤ 0.30
- [ ] reply_path_known_malicious=1 → reputation ≤ 0.30
- [ ] any_file_hash_malicious=1 → malicious_attachment_count ≥ 1
- [ ] spf=fail AND dkim=fail → dmarc=fail
- [ ] url_count=0 → all URL signals = NULL

### 10.2 Label Integrity Checks

- [ ] Legitimate emails have NO known_malicious=1 signals
- [ ] Legitimate emails have malicious_attachment_count=0 or NULL
- [ ] Legitimate emails have any_exploit_pattern_detected=0 or NULL

### 10.3 Value Range Checks

- [ ] All float values ∈ [0.0, 1.0]
- [ ] All boolean values ∈ {0, 1, NULL}
- [ ] All enum values are valid
- [ ] No duplicate records

### 10.4 Realistic Variance Checks

- [ ] Float signals have >100 unique values
- [ ] No perfectly round numbers dominate
- [ ] Overlap zones exist between malicious and legitimate

---

## Appendix A: Quick Reference Card

### A.1 Signal Semantic Quick Guide

```
1 = BAD:
  *_known_malicious, *_detected, *_suspicious_score,
  *_behavior_score, *_similarity_to_*, *_mismatch_*,
  *_diff_from_*, urgency_*, image_only_*, *_shortener_*

1 = GOOD:
  *_reputation_score, *_valid, *_enforced, *_success,
  html_text_ratio, domain_tech_stack_match_score

COUNTS (Higher = Riskier):
  *_count, *_length, *_time
```

### A.2 Malicious Email Fingerprint

```
OBVIOUS MALICIOUS:
- Low reputation scores (<0.4)
- Failed authentication (SPF/DKIM/DMARC fail)
- High behavioral scores (>0.7)
- Known malicious indicators = 1
- Urgency + suspicious request type

SOPHISTICATED MALICIOUS:
- Medium-high reputation (0.5-0.75)
- Passing authentication
- But still has: visual similarity, BEC indicators, suspicious behavior
```

### A.3 Legitimate Email Fingerprint

```
PERFECT LEGITIMATE:
- High reputation (>0.8)
- All auth pass
- No malicious indicators
- Low behavioral scores (<0.2)
- Normal request types (none, meeting_request)

IMPERFECT LEGITIMATE:
- Medium reputation (0.5-0.7)
- Some auth issues (softfail, none)
- But NO known_malicious=1 signals
- NO malicious file hashes
```

---

## Appendix B: File Format Specification

### CSV Column Order (69 columns)

```
1.  sender_known_malicious
2.  sender_domain_reputation_score
3.  sender_spoof_detected
4.  sender_temp_email_likelihood
5.  dmarc_enforced
6.  packer_detected
7.  any_file_hash_malicious
8.  max_metadata_suspicious_score
9.  malicious_attachment_count
10. has_executable_attachment
11. unscannable_attachment_present
12. total_components_detected_malicious
13. total_yara_match_count
14. total_ioc_count
15. max_behavioral_sandbox_score
16. max_amsi_suspicion_score
17. any_macro_enabled_document
18. any_vbscript_javascript_detected
19. any_active_x_objects_detected
20. any_network_call_on_open
21. max_exfiltration_behavior_score
22. any_exploit_pattern_detected
23. total_embedded_file_count
24. max_suspicious_string_entropy_score
25. max_sandbox_execution_time
26. unique_parent_process_names
27. return_path_mismatch_with_from
28. return_path_known_malicious
29. return_path_reputation_score
30. reply_path_known_malicious
31. reply_path_diff_from_sender
32. reply_path_reputation_score
33. smtp_ip_known_malicious
34. smtp_ip_geo
35. smtp_ip_asn
36. smtp_ip_reputation_score
37. domain_known_malicious
38. url_count
39. dns_morphing_detected
40. domain_tech_stack_match_score
41. is_high_risk_role_targeted
42. sender_name_similarity_to_vip
43. urgency_keywords_present
44. request_type
45. content_spam_score
46. user_marked_as_spam_before
47. bulk_message_indicator
48. unsubscribe_link_present
49. marketing_keywords_detected
50. html_text_ratio
51. image_only_email
52. spf_result
53. dkim_result
54. dmarc_result
55. reverse_dns_valid
56. tls_version
57. total_links_detected
58. url_shortener_detected
59. url_redirect_chain_length
60. final_url_known_malicious
61. url_decoded_spoof_detected
62. url_reputation_score
63. ssl_validity_status
64. site_visual_similarity_to_known_brand
65. url_rendering_behavior_score
66. link_rewritten_through_redirector
67. token_validation_success
68. qrcode_analysis
69. label
```

---

**Document Version:** 1.0
**Last Updated:** 2026-01-12
**Total Signals:** 68
**Total Scenarios:** 28 (15 Malicious + 13 Legitimate)
