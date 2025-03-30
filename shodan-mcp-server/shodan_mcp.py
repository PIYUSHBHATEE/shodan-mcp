from typing import Any, Dict, List, Optional
from mcp.server.fastmcp import FastMCP
import json
import re

# Import functions from our API module
from shodan_api import (
    test_simple_response, 
    check_api_key, 
    get_shodan_filters, 
    get_shodan_search, 
    get_shodan_facets,
    get_domain_info,
    resolve_hostnames,
    reverse_lookup,
    get_cve_info,
    get_cpes,
    get_cves,
    get_shodan_host,
    get_shodan_count
)

# Initialize FastMCP server
mcp = FastMCP("shodan")

@mcp.tool()
async def test() -> Dict[str, Any]:
    """Simple test function.
    
    Tests if the MCP server is working correctly.
    """
    try:
        result = await test_simple_response()
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def check_key() -> Dict[str, Any]:
    """Check Shodan API key validity.
    
    Verifies if the configured API key is valid and returns account information.
    """
    try:
        result = await check_api_key()
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def get_filters() -> Dict[str, Any]:
    """Get available Shodan search filters.

    Returns a comprehensive list of all valid search filters that can be used in Shodan queries.

    Examples:
        - Use `country:US port:22` to find SSH servers in the United States
        - Use `ssl.cert.expired:true` to find servers with expired SSL certificates
        - Use `org:"Apple" http.title:"Login"` to find login pages on Apple's infrastructure
    """
    try:
        result = await get_shodan_filters()
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def get_facets() -> Dict[str, Any]:
    """Get available Shodan facets.

    Returns a comprehensive list of all available facets that can be used for grouping and analyzing search results.
    Facets allow you to get summary information about specific properties like countries, organizations, or ports.

    Examples:
        - Use facets like 'country' to group devices by geographic location
        - Use facets like 'org' to see distribution by organization
        - Use facets like 'port' to analyze common ports
    """
    try:
        result = await get_shodan_facets()
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def search(query: str, facets: str = None, page: int = 1, limit: int = 10) -> Dict[str, Any]:
    """Search the Shodan database with powerful filtering capabilities.
    
    Allows you to search Shodan's database of internet-facing devices and services
    using the same query syntax as the Shodan website.
    
    Parameters:
        query: Required search query using Shodan's filter syntax (e.g., "apache country:DE")
        facets: Optional comma-separated list of properties for summary information (e.g., "country,org")
        page: Optional page number for paginating through results (default: 1)
        limit: Optional number of results to return per page (default: 10, max: 100)
    
    Examples:
        - "nginx" - Find all nginx web servers
        - "country:US port:22" - Find SSH servers in the United States
        - "product:MySQL" - Find MySQL database servers
        - "os:Windows" - Find Windows devices
        - "port:80 apache limit:100" - Find up to 100 Apache web servers running on port 80
        - "ssl:true -port:443 page:2 limit:50" - Find second page of 50 SSL-enabled services on non-standard ports
    
    Note: This command consumes API credits, especially when using facets or paginating beyond the first page.
    Maximum results per query is 100 (Shodan API limit).
    
    Output Format:
    The results will be formatted as a comprehensive, detailed analysis with the following structure:
    
    1. Search Summary: Overview of the query, total results found, current page, and number of results returned
    
    2. Facet Analysis: Statistical breakdown by selected facets (if provided in the request)
    
    3. Detailed Matches: For each IP address found, comprehensive information is provided in these categories:
       
       a) IP Information:
          - IP Address: The IPv4 or IPv6 address
          - Port: The port number where the service was found
          - Protocol: The transport protocol (TCP/UDP)
          - Last Updated: When the information was last updated in Shodan
       
       b) Organization Information:
          - Organization: The organization that owns the IP address/network
          - ISP: The Internet Service Provider
          - ASN: Autonomous System Number
          - Hostnames: Any hostnames associated with this IP
          - Domains: Domain names associated with this IP
       
       c) Location Information:
          - Country: The country where the device is located
          - City: The city location (if available)
          - Region: Regional code or name
          - Coordinates: Latitude and longitude
       
       d) Service Information:
          - Product: The identified software/product name
          - Version: Software version if available
          - OS: Operating system information
          - CPE: Common Platform Enumeration identifiers
       
       e) HTTP Information (if available):
          - Server: Web server software identification
          - Title: The title of the web page
          - Status Code: HTTP status code
          - Robots.txt: Whether a robots.txt file was found
          - Sitemap.xml: Whether a sitemap.xml file was found
          - Security Headers: Security-related HTTP headers
       
       f) SSL Information (if available):
          - Cipher: The encryption cipher being used
          - Version: SSL/TLS version
          - Certificate: Details about the SSL certificate including issuer and expiration
       
       g) Service-Specific Information:
          - Raw service data and any service-specific modules (for various products/services)
    
    This detailed output allows for comprehensive analysis of each discovered device and its configuration.
    """
    try:
        # Validate input
        if not query:
            return {"status": "error", "message": "Search query is required"}
        
        # Ensure limit is within acceptable range (done in the API function but double-checking here)
        if limit > 100:
            limit = 100  # Cap at 100 results per page (Shodan API limit)
        
        # Call the get_shodan_search function with the provided parameters
        result = await get_shodan_search(query=query, facets=facets, page=page, limit=limit)
        
        # Format the result with all required sections
        if result["status"] == "success":
            # Create Shodan URL for this search (use the one from the API response if available)
            shodan_url = result.get("shodan_url")
            if not shodan_url:
                encoded_query = query.replace(" ", "%20").replace(":", "%3A").replace("\"", "%22")
                shodan_url = f"https://www.shodan.io/search?query={encoded_query}"
            
            # Create a properly formatted result
            formatted_result = {
                "status": "success",
                "Shodan URL": shodan_url,
                "Search Summary": {
                    "Query": query,
                    "Total Results": result.get("total", 0),
                    "Results Returned": len(result.get("matches", [])),
                    "Page": page,
                    "Limit": limit
                },
                "Pagination": result.get("pagination", {
                    "current_page": page,
                    "page_size": limit,
                    "total_results": result.get("total", 0),
                    "total_pages": max(1, (result.get("total", 0) + limit - 1) // limit)
                }),
                "Country Distribution": result.get("Country Distribution", []),
                "Matches": []
            }
            
            # Format each match with all the required sections
            for match in result.get("matches", []):
                formatted_match = {
                    "Basic Information": {
                        "IP Address": match.get("ip_str", "Unknown"),
                        "Organization": match.get("org"),
                        "ISP": match.get("isp"),
                        "ASN": match.get("asn"),
                        "Last Update": match.get("timestamp")
                    },
                    "Location": {
                        "Country": match.get("location", {}).get("country_name"),
                        "City": match.get("location", {}).get("city", "Unknown"),
                        "Region": match.get("location", {}).get("region_code", "Unknown"),
                        "Coordinates": f"{match.get('location', {}).get('latitude')}, {match.get('location', {}).get('longitude')}"
                    },
                    "Service Details": {
                        "Port": match.get("port"),
                        "Transport": match.get("transport"),
                        "Product": match.get("product", "Unknown"),
                        "Version": match.get("version", "Unknown"),
                        "OS": match.get("os")
                    },
                    "Hostnames": match.get("hostnames", []),
                    "Domains": match.get("domains", [])
                }
                
                # Always include CPE and CPE23 if available (even if empty)
                formatted_match["Service Details"]["CPE"] = match.get("cpe", [])
                if "cpe23" in match:
                    formatted_match["Cpe23 Details"] = match.get("cpe23", [])
                
                # Add HTTP information if available
                if "http" in match:
                    formatted_match["Web Information"] = {
                        "Server": match["http"].get("server"),
                        "Title": match["http"].get("title"),
                        "Status Code": match["http"].get("status"),
                        "Robots.txt": "Present" if match["http"].get("robots") else "Not found",
                        "Sitemap": "Present" if match["http"].get("sitemap") else "Not found",
                        "Headers": match["http"].get("headers", {})
                    }
                
                # Add SSL information if available
                if "ssl" in match:
                    formatted_match["SSL Information"] = {
                        "Cipher": match["ssl"].get("cipher"),
                        "Version": match["ssl"].get("version"),
                        "Certificate": match["ssl"].get("cert", {})
                    }
                
                # Add raw data if available (critical for full details)
                if "data" in match:
                    formatted_match["Technical Details"] = match.get("data")
                
                # Add any product-specific details for any product/service
                for key in match:
                    if key.lower().endswith("_data") or key.lower().endswith("details"):
                        module_name = key.replace("_data", "").replace("_details", "").title()
                        formatted_match[f"{module_name} Details"] = match[key]
                
                # Add direct Shodan host URL for this IP
                formatted_match["Shodan Host URL"] = f"https://www.shodan.io/host/{match.get('ip_str')}"
                
                # Add any additional fields that might be relevant
                for key, value in match.items():
                    if key not in ["ip_str", "org", "isp", "asn", "timestamp", "location", 
                                  "port", "transport", "product", "version", "os", 
                                  "hostnames", "domains", "http", "ssl", "data", "cpe", "cpe23",
                                  "_original"] and \
                       not key.lower().endswith("_data") and not key.lower().endswith("details"):
                        if key not in formatted_match:
                            formatted_match[f"Additional {key}"] = value
                
                formatted_result["Matches"].append(formatted_match)
            
            # Add pagination navigation instructions
            pagination = formatted_result["Pagination"]
            if pagination.get("has_next", page < pagination.get("total_pages", 1)):
                formatted_result["Pagination"]["Navigation"] = f"To see the next page (page {page+1}), use: search(query=\"{query}\", page={page+1}, limit={limit})"
            
            # Append formatting instructions
            formatted_result["_format_instructions"] = """
CRITICAL INSTRUCTIONS FOR OUTPUT FORMATTING:
1. YOU MUST START WITH THE SHODAN URL for this search query at the very beginning
2. INCLUDE PAGINATION INFORMATION showing current page, total pages, and how to navigate
3. YOU MUST PRESENT EACH DEVICE AS A SEPARATE DETAILED SECTION WITH CLEAR HEADERS
4. YOU MUST INCLUDE ALL AVAILABLE TECHNICAL DATA for each device, especially:
   - ALL CPE and CPE23 entries must be shown in full
   - ALL Raw Data sections must be shown completely (never summarize these)
   - ALL module-specific details must be shown in full for any product/service
   - ALL version numbers, sizes, and technical values must be preserved exactly
5. DO NOT CONDENSE OR SIMPLIFY THE OUTPUT - users need the complete technical details
6. ENSURE EVERY IP IS ANALYZED INDIVIDUALLY with its complete configuration details
7. FOR IP SPECIFIC QUERIES: Format the output as an exhaustive technical report
8. INCLUDE THE DIRECT SHODAN HOST LINK for each individual IP address

This is security-critical information that must be presented completely and accurately.
"""
            
            # Add display directive
            formatted_result["_display_directive"] = "FULL_TECHNICAL_DETAILS_REQUIRED"
            
            # Save the query for reference
            formatted_result["query"] = query
            
            return formatted_result
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def domain_info(domain: str, history: bool = False, type: str = None, page: int = 1) -> Dict[str, Any]:
    """Get DNS information and subdomains for a domain.
    
    Retrieves comprehensive DNS information for a domain including subdomains, DNS records,
    and optional historical data. This tool provides insights into a domain's DNS infrastructure
    and can help identify additional attack surface through subdomains discovery.
    
    Parameters:
        domain: Required domain name to lookup (e.g., "example.com")
        history: Optional flag to include historical DNS data (default: False)
        type: Optional DNS record type filter (A, AAAA, CNAME, NS, SOA, MX, TXT)
        page: Optional page number for paginating through results (default: 1)
    
    Examples:
        - "google.com" - Get all DNS information for google.com
        - "microsoft.com" with history=True - Include historical DNS records
        - "amazon.com" with type="A" - Only show A records
    
    Note: This command consumes 1 query credit per lookup.
    """
    try:
        # Validate input
        if not domain:
            return {"status": "error", "message": "Domain is required"}
        
        # Call the get_domain_info function with the provided parameters
        result = await get_domain_info(domain=domain, history=history, type=type, page=page)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
CRITICAL INSTRUCTIONS FOR OUTPUT FORMATTING:
1. START WITH THE SHODAN URL for this domain at the very beginning
2. ORGANIZE DNS RECORDS BY TYPE with clear section headers (A, AAAA, MX, etc.)
3. DISPLAY ALL SUBDOMAINS in a clear, organized list
4. INCLUDE ALL TECHNICAL DETAILS for each DNS record
5. PRESERVE ALL TIMESTAMPS AND VALUES exactly as shown
6. DO NOT SUMMARIZE OR OMIT any DNS records or details

Present this information as a comprehensive domain intelligence report.
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def dns_lookup(hostnames: str) -> Dict[str, Any]:
    """Resolve hostnames to IP addresses.
    
    Performs DNS resolution to find the IP addresses associated with the provided hostnames.
    This is useful for identifying the servers hosting specific domains or services.
    
    Parameters:
        hostnames: Required comma-separated list of hostnames to resolve (e.g., "google.com,facebook.com")
    
    Examples:
        - "google.com" - Resolve a single hostname
        - "github.com,gitlab.com,bitbucket.org" - Resolve multiple hostnames in one query
    """
    try:
        # Validate input
        if not hostnames:
            return {"status": "error", "message": "At least one hostname is required"}
        
        # Call the resolve_hostnames function with the provided parameter
        result = await resolve_hostnames(hostnames=hostnames)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. PRESENT RESULTS AS A CLEAR TABLE with Hostname -> IP mapping
2. HIGHLIGHT ANY INTERESTING PATTERNS such as multiple hostnames resolving to same IP
3. PRESERVE EXACT IP ADDRESSES without modification
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def reverse_dns(ips: str) -> Dict[str, Any]:
    """Find hostnames associated with IP addresses.
    
    Performs reverse DNS lookups to find the hostnames that have been defined for the given
    IP addresses. This can help identify what services or domains are hosted on specific IPs.
    
    Parameters:
        ips: Required comma-separated list of IP addresses to lookup (e.g., "8.8.8.8,1.1.1.1")
    
    Examples:
        - "8.8.8.8" - Find hostnames for Google's DNS server
        - "1.1.1.1,8.8.4.4" - Find hostnames for multiple IPs in one query
    """
    try:
        # Validate input
        if not ips:
            return {"status": "error", "message": "At least one IP address is required"}
        
        # Call the reverse_lookup function with the provided parameter
        result = await reverse_lookup(ips=ips)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. PRESENT RESULTS AS A CLEAR TABLE with IP -> Hostnames mapping
2. LIST ALL HOSTNAMES associated with each IP
3. HIGHLIGHT CASES where IPs have multiple hostnames
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def cve_info(cve_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific CVE vulnerability.
    
    Retrieves comprehensive information about a Common Vulnerability and Exposure (CVE)
    including severity scores, description, references, and affected systems.
    This helps in understanding the technical details, impact, and mitigation options
    for a specific vulnerability.
    
    Parameters:
        cve_id: Required CVE identifier (e.g., "CVE-2021-44228" or "2021-44228")
    
    Examples:
        - "CVE-2021-44228" - Get details about Log4Shell vulnerability
        - "2023-36664" - Get details about recent Windows vulnerability (CVE prefix is optional)
    
    The results include essential security metrics:
    - CVSS: Common Vulnerability Scoring System (0-10 scale of severity)
    - EPSS: Exploit Prediction Scoring System (likelihood of exploitation)
    - KEV status: Whether it's a Known Exploited Vulnerability
    """
    try:
        # Validate input
        if not cve_id:
            return {"status": "error", "message": "CVE ID is required"}
        
        # Call the get_cve_info function with the provided parameter
        result = await get_cve_info(cve_id=cve_id)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. START WITH A CLEAR VULNERABILITY SUMMARY highlighting the CVE ID, affected product, and core issue
2. PRESENT SEVERITY METRICS prominently (CVSS, EPSS, KEV status)
3. INCLUDE A DETAILED TECHNICAL DESCRIPTION of the vulnerability
4. LIST ALL REFERENCES with clear links
5. SHOW ALL AFFECTED CPEs (if available)
6. INCLUDE CLEAR PRIORITIZATION AND REMEDIATION GUIDANCE based on the severity metrics
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def find_cpes(product: str, count: bool = False, skip: int = 0, limit: int = 1000) -> Dict[str, Any]:
    """Find CPE identifiers for a specific product.
    
    Searches for Common Platform Enumeration (CPE) identifiers that match a given product name.
    CPEs are standardized identifiers that describe software, hardware, and firmware products,
    which are useful for vulnerability management and security automation.
    
    Parameters:
        product: Required product name to search for (e.g., "apache", "windows", "mikrotik")
        count: Optional flag to only return the count of matching CPEs (default: False)
        skip: Optional number of results to skip for pagination (default: 0)
        limit: Optional maximum number of results to return (default: 1000, max: 1000)
    
    Examples:
        - "apache" - Find all CPEs related to Apache products
        - "mikrotik" - Find all CPEs related to MikroTik products
        - "windows 10" - Find CPEs for Windows 10
    
    This tool is useful for:
    - Discovering exact CPE identifiers needed for vulnerability searches
    - Understanding which versions of a product are tracked in vulnerability databases
    - Building comprehensive asset inventories with standardized identifiers
    """
    try:
        # Validate input
        if not product:
            return {"status": "error", "message": "Product name is required"}
        
        # Call the get_cpes function with the provided parameters
        result = await get_cpes(product=product, count=count, skip=skip, limit=limit)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            if count:
                result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. CLEARLY STATE THE TOTAL NUMBER of CPEs found for the product
2. EXPLAIN how to retrieve the actual CPE list using the same command with count=false
"""
            else:
                result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. CLEARLY LIST ALL CPEs in an organized way
2. GROUP CPEs by version or vendor if patterns are apparent
3. EXPLAIN the CPE format briefly for user understanding
4. INDICATE if there are more results available beyond the current pagination limits
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def find_cves(cpe23: str = None, product: str = None, count: bool = False,
                    is_kev: bool = False, sort_by_epss: bool = False,
                    skip: int = 0, limit: int = 1000,
                    start_date: str = None, end_date: str = None) -> Dict[str, Any]:
    """Find vulnerabilities (CVEs) by product or CPE identifier.
    
    Searches for Common Vulnerabilities and Exposures (CVEs) that affect a specific product
    or match a given CPE identifier. This allows for targeted vulnerability discovery and
    assessment based on the technologies used in your environment.
    
    Parameters:
        cpe23: Optional CPE 2.3 identifier (e.g., "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*")
        product: Optional product name (e.g., "apache", "windows")
        count: Optional flag to only return the count of matching CVEs (default: False)
        is_kev: Optional flag to only return Known Exploited Vulnerabilities (default: False)
        sort_by_epss: Optional flag to sort results by exploitation likelihood (default: False)
        skip: Optional number of results to skip for pagination (default: 0)
        limit: Optional maximum number of results to return (default: 1000, max: 1000)
        start_date: Optional start date for filtering (format: YYYY-MM-DDTHH:MM:SS)
        end_date: Optional end date for filtering (format: YYYY-MM-DDTHH:MM:SS)
    
    Examples:
        - product="log4j" - Find CVEs affecting Log4j
        - cpe23="cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*" - Find CVEs for specific Log4j version
        - product="windows" is_kev=true - Find actively exploited Windows vulnerabilities
        - product="mikrotik" sort_by_epss=true - Find MikroTik vulnerabilities sorted by exploitation risk
    
    Note: You can specify either cpe23 OR product, but not both at the same time.
    """
    try:
        # Validate input
        if not cpe23 and not product:
            return {"status": "error", "message": "Either CPE23 or product name is required"}
        
        if cpe23 and product:
            return {"status": "error", "message": "Specify either CPE23 or product name, not both"}
        
        # Call the get_cves function with the provided parameters
        result = await get_cves(
            cpe23=cpe23,
            product=product,
            count=count,
            is_kev=is_kev,
            sort_by_epss=sort_by_epss,
            skip=skip,
            limit=limit,
            start_date=start_date,
            end_date=end_date
        )
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            if count:
                result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. CLEARLY STATE THE TOTAL NUMBER of CVEs found for the search criteria
2. SUMMARIZE the search criteria used (product/CPE, KEV status, date range)
3. EXPLAIN how to retrieve the actual CVE list using the same command with count=false
"""
            else:
                result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. START WITH A SUMMARY showing total CVEs found and severity distribution
2. HIGHLIGHT KNOWN EXPLOITED VULNERABILITIES at the top if any exist
3. FOR EACH CRITICAL OR HIGH SEVERITY CVE:
   - Show CVE ID, CVSS score, and brief description
   - Include EPSS score to indicate exploitation likelihood
   - Provide published date
4. INCLUDE PAGINATION INFORMATION if there are more results available
5. SORT by severity or EPSS score if appropriate
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def host(ip: str) -> Dict[str, Any]:
    """Get detailed information about a host IP address.
    
    Retrieves comprehensive information about a specific IP address from Shodan,
    including all open ports, services, banners, geographical location, and more.
    This provides a complete overview of the internet-facing services running on
    a target system.
    
    Parameters:
        ip: Required IP address to lookup (e.g., "8.8.8.8")
    
    Examples:
        - "8.8.8.8" - Get information about Google's public DNS server
        - "1.1.1.1" - Get information about Cloudflare's public DNS server
    
    Note: This command consumes 1 query credit per lookup.
    """
    try:
        # Validate input
        if not ip:
            return {"status": "error", "message": "IP address is required"}
        
        # Call the get_shodan_host function with the provided parameter
        result = await get_shodan_host(ip=ip)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
CRITICAL INSTRUCTIONS FOR OUTPUT FORMATTING:
1. START WITH A SUMMARY of the host including its IP, organization, and total number of open ports
2. LIST ALL OPEN PORTS prominently near the top (this is one of the most important pieces of information)
3. FOR EACH SERVICE detected, show the complete details in separate sections organized by port
4. SHOW ALL TECHNICAL DETAILS for each service, especially banners, headers, and raw data
5. PRESERVE ALL HTTP HEADERS, SSL CERTIFICATE DETAILS, CPEs, and other technical information
6. INCLUDE THE DIRECT SHODAN HOST URL for this IP
7. NEVER TRUNCATE OR ABBREVIATE banners, status codes, headers, or version strings

Present this information as a comprehensive host intelligence report.
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

@mcp.tool()
async def count(query: str, facets: str = None) -> Dict[str, Any]:
    """Count results for a Shodan search query without returning the actual hosts.
    
    Returns only the total number of results and facet information for a search query
    without consuming query credits. This is useful for understanding the scope of
    a search before retrieving actual results or for analyzing the distribution of
    results across different facets.
    
    Parameters:
        query: Required search query using Shodan's filter syntax (e.g., "apache country:DE")
        facets: Optional comma-separated list of properties for statistical breakdown (e.g., "country,org")
    
    Examples:
        - "nginx" - Count all nginx web servers
        - "port:22" facets="country,org" - See country and organization distribution for SSH servers
        - "product:MongoDB" facets="country,version" - See country and version distribution for MongoDB servers
    
    Note: This command does not consume query credits, making it efficient for preliminary research.
    """
    try:
        # Validate input
        if not query:
            return {"status": "error", "message": "Search query is required"}
        
        # Call the get_shodan_count function with the provided parameters
        result = await get_shodan_count(query=query, facets=facets)
        
        # Format the result with instructions for LLM
        if result["status"] == "success":
            result["_format_instructions"] = """
FORMATTING INSTRUCTIONS:
1. START WITH THE TOTAL NUMBER of results found for the search query
2. INCLUDE THE SHODAN URL for this search query
3. PRESENT FACET DISTRIBUTIONS in clear tables if facets were requested
4. FOR EACH FACET, show the value, count, and percentage in descending order
5. SUMMARIZE any notable patterns visible in the facet data
6. PROVIDE GUIDANCE on how to retrieve the actual results using the 'search' function
"""
        
        return result
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}

if __name__ == "__main__":
    # Initialize and run the server with stdio for ChatGPT client
    mcp.run(transport='stdio')


