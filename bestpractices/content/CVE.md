### CVEs
CVE stands for Common Vulnerabilities and Exposures, and is a publicly accessible database of known security flows in software and hardware.

CVE is a glossary that classifies vulnerabilities. The glossary analyzes vulnerabilities and then uses the Common Vulnerability
Scoring System (CVSS) to evaluate the threat level of a vulnerability. A CVE score is often used for prioritizing the security
vulnerabilities.

The CVE glossary is a project dedicated to tracking and cataloging vulnerabilities in consumer software and hardware. It is maintained by the MITRE Corporation with funding from the US Division of Homeland Security. Vulnerabilities are collected and cataloged using the Security Content Automation Protocol (SCAP). SCAP evaluates vulnerability information and assigns each
vulnerability a unique identifier.

Once evaluated and identified, vulnerabilities are listed in the publicly accessible MITRE glossary. After listing, vulnerabilities are analyzed by the National Institute of Standards and Technology (NIST). All the vulnerabilities and analysis information is then listed in NIST's National Vulnerability Database (NVD).

## Why CVEs?
The CVE glossary was created as baseline of communication and source of dialogue for security and technology industries. CVE identifiers serve to standardize vulnerability information and unify communication amongs security professionals. Security advosaries, vulnerability databases, and bug trackers all employ this standard.

## Which Vulnerability(ies) qualify for a CVE
To be categorized as a CVE vulnerability, a vulnerability must be meet a certain set of criteria. This criteria includes;
#### Independent of other issues
A vulnerability must be fixed ably independently of other issues

#### Acknowledeged by the Vendor
The vulnerabiity is known by the vendor and is acknowledged to cause a security risk.

#### Is a proven risk
The vulnerability is submitted with evicence of security impact that violates the security policies of the vendor.

#### Affecting one codebase
Each product vulnerability gets a separate CVE. If the vulnerabilities stem from the same shared protocol, standards or
libraries, a separate CVE is assigned for each vendor affected. The exception is if no way to use the shared component without including the vulnerability.

## What is the Common vulnerability Scoring System, CVSS?
CVSS is one of the ways to measure the impact of vulnerabilities, which is commonly known as the CVE score. The CVSS is a set of standards used to assess a vulnerability and assign a severity along a score of 0-10. The current version of CVSS is V4.0, at the time of writing, which breaks down the scale as follows:

<table>
  <thead>
    <tr>
      <th scope="col">Severity</th>
      <th scope="col">Base Score</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th scope="row">None</th>
      <td>0</td>
    </tr>
    <tr>
      <tr>
      <th scope="row">Low</th>
      <td>0.1-3.9</td>
    </tr>
    <tr>
      <tr>
      <th scope="row">Medium</th>
      <td>4.0-6.9</td>
    </tr>
    <tr>
      <tr>
      <th scope="row">High</th>
      <td>7.0-8.9</td>
    </tr>
    <tr>
      <th scope="row">Critical</th>
      <td>9.0-10.0</td>
    </tr>
  </tbody>
</table>

To learn how to calculate CVSS or convert scores that don't use CVSS , you may use an NVD calculator.

## CVE Identifiers
When vulnerabilities are identified, a CVE Numbering authority (CVSS) assigns a number. A CVE identifier follows
the format of -CVE-{year}-{ID}. There are currently 416 (414 CNAs and 2 CNA-LRs) from 40 countries and 1 with no country affiliation. These organizations include research organizations, security and IT vendors. CNAs are granted their authority by MITRE, which can also assign CVE numbers directly.

Vulnerability information is provided to CNAs via researchers, vendors, or users. Many vulnerabilities are also discovered as a part of bug bounty programs. These programs are set up by vendors and provide a reward to users who report vulnerabilities directly to the vendor as opposed to making the information public. Vendors can then report the vulnerability to a CNA along with a patch information, if available.

Once a vulnerability is reported, the CNA assigns a number from the block of unique CVE identifier it holds. The CNA then reports the vulnerability with the assigned number of the MITRE. Frequently, reported vulnerabilities have a waiting period
before being made public by MITRE. This allows vendors to develop patches and reduces the chance that flaws are exploited once known.

When a vulnerability is made public, it is listed with its ID, a brief description of the issue, and any references containing additional information or reports. As new references or finding arise, this information is added to the the entry.

## Open CVE Databases
There are numerous databases that include CVE information and serve as resources or feeds for vulnerability notification. Below are the three most commonly used databases.

#### National Vulnerability Database, NVD
Formed in 2005 and serves as the primary CVE database for many organizations. It provides detailed information about vulnerabilities, including affected systems and potential fixes. It also scores vulnerabilities using CVSS standards.

CVE information from MITRE is provided tp NVD, which then analyses the reported CVE vulnerability.

#### Vulnerability Database, VulDB
VulDB is a community-driven vulnerability database. It provides information on a vulnerability management, incident response and threat intelligence. VulDB specilises in the analysis of vulnerability trends. These analyses are provided in an effort to help security teams predict and prepare for future threats.

#### CVE Details
CVE details is a database that combines the NVD data with information from other sources, such as the Exploit Database. It enables you to browse vulnerabilities by vendor, product, type and date. It includes CVE vulnerabilities, as well as vulnerabilities listed by Bugtraq ID and Microsoft References.
