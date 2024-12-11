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
CVSS is one of the ways to measure the impact of vulnerabilities, which is commonly known as the CVE score. The CVSS is a set of standards used to assess a vulnerability and assign a severity along a score of 0-10. The current version of CVSS is V3.1, which breaks down the scale as follows:

<table>
  <caption>
    Severity Scores
  </caption>
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
      <tr>
      <th scope="row">Critical</th>
      <td>9.0-10.0</td>
    </tr>
  </tbody>
</table>
