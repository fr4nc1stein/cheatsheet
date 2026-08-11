# Reconnaissance

**1. WHOIS Lookup:**

WHOIS is a protocol that provides information about registered domain names and IP addresses.

*   Command:

    ```
    whois <domain_name>
    ```

**2. DNS Lookup:**

DNS (Domain Name System) lookup allows you to retrieve DNS records associated with a domain name or IP address.

*   Command:

    ```
    nslookup <domain_name or IP_address>
    ```

**3. DNS Enumeration Tools:** These tools automate the process of gathering information about a target's DNS records, including subdomains.

* Examples of DNS enumeration tools:
  *   **Sublist3r**:

      `sublist3r -d <domain_name>`
  *   **DNSenum**:

      `dnsenum <domain_name>`
  *   **Fierce**:

      `fierce --domain <domain_name>`

**4. Search Engines:**

Search engines can be a valuable resource for finding publicly available information about a target.

* Examples of search engines:
  * **Google**:
    *   Search for domain-related information:

        `site:<domain_name>`
    *   Search for subdomains:

        `site:*.<domain_name>`
  * **Shodan**:
    *   Search for IP-related information and open services:

        `ip:<IP_address>`
  * **Censys**:
    *   Search for information about domains, IP addresses, certificates, etc.:

        `<search_query>`
