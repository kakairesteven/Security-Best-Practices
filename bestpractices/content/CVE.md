### CVEs

CVE stands for Common Vulnerabilities and Exposures and is a publicly accessible database of known security flaws in software and hardware.

CVE is a glossary that classifies vulnerabilities. The glossary analyzes vulnerabilities and then uses the Common Vulnerability Scoring System (CVSS) to evaluate the threat level of a vulnerability. A CVE score is often used to prioritize security vulnerabilities.

The CVE glossary is a project dedicated to tracking and cataloging vulnerabilities in consumer software and hardware. It is maintained by the MITRE Corporation with funding from the U.S. Department of Homeland Security. Vulnerabilities are collected and cataloged using the Security Content Automation Protocol (SCAP). SCAP evaluates vulnerability information and assigns each vulnerability a unique identifier.

Once evaluated and identified, vulnerabilities are listed in the publicly accessible MITRE glossary. After listing, vulnerabilities are analyzed by the National Institute of Standards and Technology (NIST). All vulnerabilities and analysis information are then listed in NIST's National Vulnerability Database (NVD).

## Why CVEs?

The CVE glossary was created as a baseline of communication and a source of dialogue for the security and technology industries. CVE identifiers serve to standardize vulnerability information and unify communication among security professionals. Security advisories, vulnerability databases, and bug trackers all employ this standard.

## Which Vulnerability(ies) Qualify for a CVE?

To be categorized as a CVE vulnerability, a vulnerability must meet a certain set of criteria. This includes:

### Independent of Other Issues

A vulnerability must be fixable independently of other issues.

### Acknowledged by the Vendor

The vulnerability is known by the vendor and is acknowledged to cause a security risk.

### Proven Risk

The vulnerability must be submitted with evidence of security impact that violates the vendor's security policies.

### Affecting One Codebase

Each product vulnerability gets a separate CVE. If vulnerabilities stem from the same shared protocol, standards, or libraries, a separate CVE is assigned for each vendor affected. The exception is when there is no way to use the shared component without including the vulnerability.

## What is the Common Vulnerability Scoring System (CVSS)?

CVSS is one of the ways to measure the impact of vulnerabilities, commonly known as the CVE score. The CVSS is a set of standards used to assess vulnerabilities and assign a severity score from 0 to 10 based on exploitability, impact scope, and other metrics. The current version of CVSS is v4.0, which breaks down the scale as follows:

| Severity  | Base Score |
|-----------|------------|
| None      | 0          |
| Low       | 0.1–3.9    |
| Medium    | 4.0–6.9    |
| High      | 7.0–8.9    |
| Critical  | 9.0–10.0   |

The score helps organizations gauge the urgency of addressing a particular vulnerability and allocate resources accordingly. CVSS scores are calculated using three metric groups: base, temporal, and environmental, which incorporate different characteristics of a vulnerability.

### Base Metrics

Base metrics are used most frequently by enterprises and public severity rankings, such as those provided in the NIST National Vulnerability Database. This score does not consider vulnerability characteristics that change over time (temporal metrics) or real-world factors such as user environment or measures taken by an enterprise to prevent exploitation. 

- **Exploitability metrics** include factors such as attack vector, attack complexity, and privileges required.  
- **Impact metrics** include confidentiality impact, integrity impact, and availability impact.

To calculate CVSS scores or convert scores that do not use CVSS, an NVD calculator may be used.

### Temporal Metrics

Temporal metrics allow organizations to adjust base scores according to their specific environments and security requirements. This score includes a confidentiality requirement score, an integrity requirement score, and an availability requirement score. Metrics are calculated alongside modified base metrics, such as modified attack vector and modified attack complexity, to reach an environmental metrics score.

## CVE Identifiers

When vulnerabilities are identified, a CVE Numbering Authority (CNA) assigns a number. A CVE identifier follows the format **CVE-{year}-{ID}**. There are currently 416 CNAs (414 CNAs and 2 CNA-LRs) from 40 countries, with one unaffiliated with a country. These organizations include research institutions, security, and IT vendors. CNAs are granted their authority by MITRE, which can also assign CVE numbers directly.

Vulnerability information is provided to CNAs by researchers, vendors, or users. Many vulnerabilities are discovered through bug bounty programs, which vendors establish to reward users for reporting vulnerabilities directly to them instead of making the information public. Vendors can then report vulnerabilities to a CNA along with patch information, if available.

Once a vulnerability is reported, the CNA assigns a number from its block of unique CVE identifiers. The CNA then reports the vulnerability with the assigned number to MITRE. Frequently, reported vulnerabilities have a waiting period before being made public by MITRE. This allows vendors to develop patches and reduces the likelihood of exploitation.

When vulnerabilities are made public, they are listed with an ID, a brief description, and references containing additional information or reports. As new findings emerge, this information is added to the entry.

## Impact of CVEs on Vulnerability Management

The CVE program represents a collaborative and systematic approach to identifying, cataloging, and addressing cybersecurity vulnerabilities and exposures. By offering a standardized system for identifying and referencing vulnerabilities, CVE helps organizations improve vulnerability management in several ways:

### Share Information

CVE helps organizations discuss and share information regarding vulnerabilities using a common identifier. For example, security advisories often publish CVE lists with CVSS scores that companies use to inform risk management strategies and patch planning cycles.

### Strengthen Cybersecurity Posture

CVE helps organizations effectively manage security risks, enhance threat visibility and intelligence, and strengthen their overall cybersecurity posture in an increasingly complex landscape.

### Better Correlate Data

CVE IDs facilitate data correlation, enabling IT teams to scan multiple sources for information on specific vulnerabilities.

### Select Tools and Strategies

The CVE list helps determine which security tools are best for an organization’s needs and aids in creating risk management strategies. By considering known vulnerabilities, organizations can better assess how products fit their exposure to cyberattacks and data breaches.

## Open CVE Databases

Several databases include CVE information and serve as resources for vulnerability notifications. Here are the three most commonly used:

### National Vulnerability Database (NVD)

Formed in 2005, the NVD serves as the primary CVE database for many organizations. It provides detailed information about vulnerabilities, including affected systems and potential fixes. It also scores vulnerabilities using CVSS standards. CVE information from MITRE is provided to NVD, which then analyzes the reported CVE vulnerability.

### Vulnerability Database (VulDB)

VulDB is a community-driven vulnerability database. It provides information on vulnerability management, incident response, and threat intelligence. VulDB specializes in analyzing vulnerability trends to help security teams predict and prepare for future threats.

### CVE Details

CVE Details is a database that combines NVD data with information from other sources, such as the Exploit Database. It enables users to browse vulnerabilities by vendor, product, type, and date. It includes CVE vulnerabilities, as well as those listed by Bugtraq ID and Microsoft References.

### Reporting Vulnerabilities to CNAs
When a publisher has detected a security vulnerability in its own software and it qualifies according the criteria above, it is necessary to submit a request to obtain a vulnerability identification number (CVE) from a numbering authority. The numbering authority will examine the request and publish the vulnerability if all the required information is submitted. 

The last resort option is to report directly to MITRE.

### Choosing a CVE Numbering Authority
You can't disclose vulnerabilities to just any CNA. They each have a specific scope, responsibility or comptence. Some are dedicated to specific types of product, others to specific suppliers, or even specific reporters.

### Becoming a CNA
CNAs are vendors, researchers, open source, CERT, hosted service, bug bounty provider, and consortium organizations authorized by CVE program to assign CVE IDs to vulnerabilities and publish CVE records within their own specific scopes
of coverage. An organization can request MITRE to become a CNA for a specific domain of coverage.

### Action Point
NumFocus Security Committee should consider requesting MITRE so as to be a CNA covering security vulnerabilities within 
the NumFocus Sponsored Projects and the related ecosystem.
