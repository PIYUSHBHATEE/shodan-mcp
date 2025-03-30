from typing import Any, Dict, List, Optional
import os
from dotenv import load_dotenv
import httpx
# Import the Shodan client directly
from shodan import Shodan
import urllib.parse
import json

# Load environment variables from .env file
load_dotenv()

# Constants
API_KEY = os.getenv("SHODAN_API_KEY")  # Get API key from environment variable
USER_AGENT = "Shodan-MCP/1.0"  # Define the missing USER_AGENT constant
SHODAN_API_URL = "https://api.shodan.io"  # Define base Shodan API URL

# Initialize Shodan API client
shodan_api = Shodan(API_KEY)

async def test_simple_response() -> Dict[str, Any]:
    """A simple test function that returns a JSON object."""
    return {
        "status": "success",
        "message": "Test successful: Shodan MCP server is responding correctly."
    }

async def check_api_key() -> Dict[str, Any]:
    """Check if the Shodan API key is valid."""
    try:
        # Try to get API info
        api_info = shodan_api.info()
        
        # Return a dictionary response
        return {
            "status": "success",
            "valid": True,
            "scan_credits": api_info.get('scan_credits', 0),
            "query_credits": api_info.get('query_credits', 0),
            "monitored_ips": api_info.get('monitored_ips', 0),
            "plan": api_info.get('plan', "Unknown")
        }
    except Exception as e:
        return {
            "status": "error",
            "valid": False,
            "message": f"API Key Error: {str(e)}"
        }

async def get_shodan_filters() -> Dict[str, Any]:
    """Get available search filters in Shodan."""
    try:
        # Get filters
        filters = shodan_api.search_filters()

        # Return a dictionary response
        return {
            "status": "success",
            "filters": filters
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error: {str(e)}"
        }
                
async def get_shodan_facets() -> Dict[str, Any]:
    """Get available facets in Shodan."""
    try:
        # Get facets
        filters = shodan_api.search_facets()

        # Return a dictionary response
        return {
            "status": "success",
            "filters": filters
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error: {str(e)}"
        }

async def get_shodan_search(query: str, facets: str = None, page: int = 1, limit: int = 10) -> Dict[str, Any]:
    """Search Shodan API with comprehensive filtering and analysis.

    Executes queries against the Shodan database using filter:value syntax, returning results with optional facet analysis.
    Supports pagination, result minification, and detailed statistics by property.
    
    Parameters:
        query: [String] Shodan search query. The provided string is used to search the database of banners in Shodan, 
               with the additional option to provide filters inside the search query using a "filter:value" format. 
               For example, the following search query would find Apache Web servers located in Germany: "apache country:DE".
        facets (optional): [String] A comma-separated list of properties to get summary information on. 
                           Property names can also be in the format of "property:count", where "count" is the number of facets 
                           that will be returned for a property (i.e. "country:100" to get the top 100 countries for a search query).
        page (optional): [Integer] The page number to page through results (default: 1)
        limit (optional): [Integer] The number of results to return (default: 10, max: 100)

    Note: Consumes API credits when using filters or paginating beyond first page.
    """
    try:
        # IMPORTANT: Ensure limit is within acceptable range BEFORE making the API call
        # Shodan API has a hard cap of 100 results per request
        if limit <= 0:
            limit = 10  # Use default if invalid
        elif limit > 100:
            limit = 100  # Cap at 100 results per page (Shodan API limit)
        
        # Ensure page number is valid
        if page <= 0:
            page = 1
        
        # Detailed logging for debugging pagination
        print(f"Requesting Shodan search with: query='{query}', page={page}, limit={limit}, facets={facets}")
        
        # Based on the Shodan API client implementation, we need to decide whether to use page OR limit
        # When both are provided, the client ignores the page parameter
        # So we'll enforce proper pagination based on the Shodan API client's behavior
        
        # Calculate offset for proper pagination - this is what the Shodan API client does internally
        offset = None
        if page > 1:
            offset = (page - 1) * limit
        
        # Execute the search query against the Shodan API
        # For pagination consistency, if we're requesting a specific page, we'll use the limit+offset approach
        if offset is not None:
            search_results = shodan_api.search(query, facets=facets, limit=limit, offset=offset)
        else:
            # For page 1, we can just use the limit parameter
            search_results = shodan_api.search(query, facets=facets, limit=limit)
        
        # Verify that we got the expected number of results (for debugging)
        actual_results = len(search_results.get('matches', []))
        print(f"Received {actual_results} results from Shodan API (requested {limit})")
        
        # Create a standardized response with all required fields
        matches = []
        
        # Create Shodan URL for this search
        encoded_query = query.replace(" ", "%20").replace(":", "%3A").replace("\"", "%22")
        shodan_url = f"https://www.shodan.io/search?query={encoded_query}"
        
        for match in search_results.get('matches', []):
            # Create a structured match object with all important fields
            match_data = {
                "ip_str": match.get('ip_str', 'Unknown'),
                "org": match.get('org'),
                "isp": match.get('isp'),
                "asn": match.get('asn'),
                "timestamp": match.get('timestamp'),
                "location": match.get('location', {}),
                "port": match.get('port'),
                "transport": match.get('transport'),
                "product": match.get('product'),
                "version": match.get('version'),
                "os": match.get('os'),
                "hostnames": match.get('hostnames', []),
                "domains": match.get('domains', []),
                "cpe": match.get('cpe', [])
            }
            
            # Ensure cpe23 is included at the top level if available
            if 'opts' in match and 'cpe23' in match['opts']:
                match_data["cpe23"] = match['opts']['cpe23']
            elif 'cpe23' in match:
                match_data["cpe23"] = match['cpe23']
            
            # Add HTTP information if available
            if 'http' in match:
                match_data["http"] = match['http']
            
            # Add SSL information if available
            if 'ssl' in match:
                match_data["ssl"] = match['ssl']
            
            # Add raw data for technical details if available
            if 'data' in match:
                match_data["data"] = match['data']
            
            # Add all other service-specific modules/information
            for key in match:
                if key not in ['ip_str', 'port', 'transport', 'timestamp', 'org', 'isp', 'asn', 
                               'hostnames', 'domains', 'location', 'product', 'version', 'os', 
                               'cpe', 'http', 'ssl', 'data', '_shodan', 'hash', 'ip', 'opts']:
                    match_data[key] = match[key]
            
            # Add the original match data to preserve all fields
            match_data["_original"] = match
            
            matches.append(match_data)
             
        # Calculate country distribution if facets are available
        country_distribution = []
        if 'facets' in search_results and 'country' in search_results['facets']:
            for country in search_results['facets']['country']:
                percentage = (country['count'] / search_results.get('total', 1)) * 100
                country_distribution.append({
                    "Country": country['value'],
                    "Count": country['count'],
                    "Percentage": f"{percentage:.2f}%"
                })
        
        # Calculate total pages based on total results and limit
        total_results = search_results.get('total', 0)
        total_pages = max(1, (total_results + limit - 1) // limit)
         
        # Build the final response structure with all required information
        response = {
            "status": "success",
            "total": total_results,
            "shodan_url": shodan_url,
            "page": page,
            "limit": limit,
            "results_count": len(matches),  # Actual number of results returned
            "matches": matches,
            "facets": search_results.get('facets', {}),
            "Country Distribution": country_distribution,
            "pagination": {
                "current_page": page,
                "page_size": limit,
                "total_results": total_results,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "next_page": page + 1 if page < total_pages else None,
                "has_previous": page > 1,
                "previous_page": page - 1 if page > 1 else None
            }
        }
        
        # Log response to debug
        print(f"Found {len(matches)} results from total of {total_results} for query: {query} (page {page}, limit {limit})")
        if len(matches) < limit and page == 1 and total_results > limit:
            print(f"WARNING: Received fewer results ({len(matches)}) than requested ({limit}), but total results ({total_results}) suggests more are available.")
        
        return response
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"Error in Shodan search: {str(e)}\n{error_traceback}")
        return {
            "status": "error",
            "message": f"Error: {str(e)}",
            "traceback": error_traceback
        }

async def get_shodan_host(ip: str) -> Dict[str, Any]:
    """Get detailed information about a specific IP address/host.
    
    Retrieves all services that have been found on the given host IP, including
    geographical location, open ports, banners, and other information collected by Shodan.
    
    Parameters:
        ip: The IP address of the host to look up
    
    Note: This lookup consumes 1 query credit. If any of the extended information (history, vulns) 
    is requested, it counts as an additional query credit.
    """
    try:
        # Get host information from Shodan API
        host_info = shodan_api.host(ip)
        
        # Create a structured result with all relevant sections
        result = {
            "status": "success",
            "IP": ip,
            "Shodan URL": f"https://www.shodan.io/host/{ip}",
            "Basic Information": {
                "IP Address": host_info.get("ip_str"),
                "Organization": host_info.get("org"),
                "ISP": host_info.get("isp"),
                "ASN": host_info.get("asn"),
                "Last Update": host_info.get("last_update"),
                "Hostnames": host_info.get("hostnames", []),
                "Domains": host_info.get("domains", []),
                "OS": host_info.get("os"),
                "Tags": host_info.get("tags", [])
            },
            "Location": {
                "Country": host_info.get("country_name"),
                "Country Code": host_info.get("country_code"),
                "City": host_info.get("city"),
                "Region Code": host_info.get("region_code"),
                "Latitude": host_info.get("latitude"),
                "Longitude": host_info.get("longitude"),
                "Postal Code": host_info.get("postal_code")
            },
            "Ports": host_info.get("ports", []),
            "Services": []
        }
        
        # Process each service (port banner)
        for service in host_info.get("data", []):
            # Create a structured service entry with standard fields
            service_entry = {
                "Port": service.get("port"),
                "Transport": service.get("transport"),
                "Timestamp": service.get("timestamp"),
                "Banner": service.get("data"),
                "Service Details": {
                    "Product": service.get("product"),
                    "Version": service.get("version"),
                    "CPE": service.get("cpe", []),
                    "Module": service.get("_shodan", {}).get("module")
                }
            }
            
            # Add location information if available
            if "location" in service:
                service_entry["Location"] = {
                    "Country": service.get("location", {}).get("country_name"),
                    "City": service.get("location", {}).get("city"),
                    "Coordinates": f"{service.get('location', {}).get('latitude')}, {service.get('location', {}).get('longitude')}"
                }
            
            # Add organization information if available
            if "org" in service or "isp" in service or "asn" in service:
                service_entry["Organization"] = {
                    "Name": service.get("org"),
                    "ISP": service.get("isp"),
                    "ASN": service.get("asn")
                }
            
            # Add hostnames and domains if available
            if "hostnames" in service:
                service_entry["Hostnames"] = service.get("hostnames", [])
            if "domains" in service:
                service_entry["Domains"] = service.get("domains", [])
            
            # Add HTTP information if available
            if "http" in service:
                service_entry["HTTP"] = {
                    "Status": service.get("http", {}).get("status"),
                    "Title": service.get("http", {}).get("title"),
                    "Server": service.get("http", {}).get("server"),
                    "Robots": service.get("http", {}).get("robots", False),
                    "Sitemap": service.get("http", {}).get("sitemap", False),
                    "Headers": service.get("http", {}).get("headers", {})
                }
            
            # Add SSL information if available
            if "ssl" in service:
                service_entry["SSL"] = {
                    "Cipher": service.get("ssl", {}).get("cipher"),
                    "Version": service.get("ssl", {}).get("version"),
                    "Certificate": {
                        "Issued": service.get("ssl", {}).get("cert", {}).get("issued"),
                        "Expires": service.get("ssl", {}).get("cert", {}).get("expires"),
                        "Issuer": service.get("ssl", {}).get("cert", {}).get("issuer", {}),
                        "Subject": service.get("ssl", {}).get("cert", {}).get("subject", {})
                    }
                }
            
            # Add raw data if available
            if "opts" in service:
                service_entry["Options"] = service.get("opts", {})
            
            # Add any other service-specific modules/information
            for key in service:
                if key not in ["port", "transport", "timestamp", "data", "product", "version", 
                              "cpe", "location", "org", "isp", "asn", "hostnames", "domains", 
                              "http", "ssl", "_shodan", "opts", "hash", "ip", "ip_str"]:
                    service_entry[key] = service[key]
            
            # Add the service entry to the results
            result["Services"].append(service_entry)
        
        return result
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"Error retrieving host information: {str(e)}\n{error_traceback}")
        return {
            "status": "error",
            "message": f"Error: {str(e)}",
            "traceback": error_traceback
        }

async def get_domain_info(domain: str, history: bool = False, type: str = None, page: int = 1) -> Dict[str, Any]:
    """Get DNS information for a domain.
    
    Retrieves DNS records for the specified domain using the Shodan API, with options
    to include historical data and filter by record type.
    
    Parameters:
        domain: Domain name to lookup (e.g. "cnn.com")
        history: Whether to include historical DNS data (default: False)
        type: Optional DNS record type to filter by (A, AAAA, CNAME, NS, SOA, MX, TXT)
        page: The page number for paginating through results (default: 1)
    
    Note: Uses 1 query credit per lookup
    """
    try:
        # Get domain info from Shodan API
        domain_info = shodan_api.dns.domain_info(
            domain=domain,
            history=history,
            type=type,
            page=page
        )
        
        # Create a structured result
        result = {
            "status": "success",
            "domain": domain,
            "DNS Data": {
                "Domain": domain,
                "Records": domain_info.get('data', []),
                "Tags": domain_info.get('tags', []),
                "Subdomains": domain_info.get('subdomains', []),
            },
            "Total Records": domain_info.get('total', 0),
            "Page": page,
            "Record Types": {},
            "Shodan URL": f"https://www.shodan.io/domain/{domain}"
        }
        
        # Organize records by type for better readability
        dns_records = domain_info.get('data', [])
        record_types = {}
        
        for record in dns_records:
            record_type = record.get('type', 'Unknown')
            if record_type not in record_types:
                record_types[record_type] = []
            record_types[record_type].append(record)
        
        result["Record Types"] = record_types
        
        # Add statistics
        if domain_info.get('subdomains'):
            result["Total Subdomains"] = len(domain_info.get('subdomains', []))
        
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error: {str(e)}"
        }

async def resolve_hostnames(hostnames: str) -> Dict[str, Any]:
    """DNS lookup to find IP addresses for a list of hostnames.
    
    Uses Shodan's REST API to resolve multiple hostnames to their corresponding IP addresses.
    
    Parameters:
        hostnames: Comma-separated list of hostnames (e.g. "google.com,bing.com")
    """
    try:
        # Format as a comma-separated list if multiple hostnames are provided
        hostnames_list = [h.strip() for h in hostnames.split(',')]
        
        # Prepare the API request
        base_url = "https://api.shodan.io/dns/resolve"
        params = {
            "hostnames": ",".join(hostnames_list),
            "key": API_KEY
        }
        
        # Execute the API request
        async with httpx.AsyncClient() as client:
            response = await client.get(base_url, params=params)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
        
        # Create a structured result
        result = {
            "status": "success",
            "DNS Resolutions": [],
            "Resolution Details": data
        }
        
        # Format the results for better readability
        for hostname, ip in data.items():
            result["DNS Resolutions"].append({
                "Hostname": hostname,
                "IP Address": ip
            })
        
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error: {str(e)}"
        }

async def reverse_lookup(ips: str) -> Dict[str, Any]:
    """Reverse DNS lookup to find hostnames for a list of IP addresses.
    
    Uses Shodan's REST API to find the hostnames that have been defined for a list of IP addresses.
    
    Parameters:
        ips: Comma-separated list of IP addresses (e.g. "8.8.8.8,1.1.1.1")
    """
    try:
        # Format as a comma-separated list if multiple IPs are provided
        ip_list = [ip.strip() for ip in ips.split(',')]
        
        # Prepare the API request
        base_url = "https://api.shodan.io/dns/reverse"
        params = {
            "ips": ",".join(ip_list),
            "key": API_KEY
        }
        
        # Execute the API request
        async with httpx.AsyncClient() as client:
            response = await client.get(base_url, params=params)
            response.raise_for_status()  # Raise an exception for HTTP errors
            data = response.json()
        
        # Create a structured result
        result = {
            "status": "success",
            "Reverse DNS Lookups": [],
            "Lookup Details": data
        }
        
        # Format the results for better readability
        for ip, hostnames in data.items():
            result["Reverse DNS Lookups"].append({
                "IP Address": ip,
                "Hostnames": hostnames
            })
        
        return result
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error: {str(e)}"
        }

# CVEDB API Functions
# Base URL for CVEDB API
CVEDB_BASE_URL = "https://cvedb.shodan.io"

async def get_cve_info(cve_id: str) -> Dict[str, Any]:
    """Get detailed information about a specific CVE.
    
    Retrieves comprehensive information about a Common Vulnerability and Exposure (CVE)
    by its unique identifier, including severity scores, description, references, and
    affected CPEs.
    
    Parameters:
        cve_id: The CVE ID in the format "CVE-YYYY-NNNNN"
    """
    try:
        # Ensure CVE ID is properly formatted
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"
        
        # Prepare the API request URL
        url = f"{CVEDB_BASE_URL}/cve/{cve_id}"
        
        # Execute the API request
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            
            if response.status_code == 200:
                data = response.json()
                
                # Create a structured result with all the fields
                result = {
                    "status": "success",
                    "CVE Details": {
                        "CVE ID": data.get("cve_id"),
                        "Summary": data.get("summary"),
                        "CVSS Score": data.get("cvss"),
                        "CVSS Version": data.get("cvss_version"),
                        "CVSS v2": data.get("cvss_v2"),
                        "CVSS v3": data.get("cvss_v3"),
                        "EPSS Score": data.get("epss"),
                        "EPSS Ranking": data.get("ranking_epss"),
                        "Known Exploited Vulnerability": data.get("kev", False),
                        "Proposed Action": data.get("propose_action"),
                        "Ransomware Campaign": data.get("ransomware_campaign"),
                        "References": data.get("references", []),
                        "Published Date": data.get("published_time"),
                        "Affected CPEs": data.get("cpes", [])
                    },
                    "Vulnerability Analysis": {
                        "Severity": get_severity_level(data.get("cvss")),
                        "Exploitation Risk": get_epss_risk_level(data.get("epss")),
                        "Prioritization": get_prioritization(data.get("cvss"), data.get("epss"), data.get("kev", False))
                    },
                    "Raw Data": data
                }
                
                return result
            else:
                error_data = response.text
                try:
                    error_json = json.loads(error_data)
                    error_message = error_json.get('error', f"HTTP error {response.status_code}")
                except:
                    error_message = f"HTTP error {response.status_code}: {error_data[:100]}..."
                
                return {
                    "status": "error",
                    "message": error_message
                }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error retrieving CVE information: {str(e)}"
        }

async def get_cpes(product: str, count: bool = False, skip: int = 0, limit: int = 1000) -> Dict[str, Any]:
    """Get CPE identifiers related to a specific product.
    
    Retrieves Common Platform Enumeration (CPE) identifiers that match the specified product name,
    helping to identify potentially vulnerable components or software.
    
    Parameters:
        product: The name of the product to search for CPEs
        count: If True, returns only the count of matching CPEs
        skip: Number of CPEs to skip (for pagination)
        limit: Maximum number of CPEs to return (max: 1000)
    """
    try:
        # Prepare the API request URL and parameters
        url = f"{CVEDB_BASE_URL}/cpes"
        params = {
            "product": product,
            "count": str(count).lower(),
            "skip": skip,
            "limit": limit
        }
        
        # Execute the API request
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # Create a structured result
                if count:
                    result = {
                        "status": "success",
                        "Product": product,
                        "Total CPEs": data.get("total", 0),
                        "Raw Data": data
                    }
                else:
                    result = {
                        "status": "success",
                        "Product": product,
                        "CPEs Found": len(data.get("cpes", [])),
                        "CPE List": data.get("cpes", []),
                        "Pagination": {
                            "Skip": skip,
                            "Limit": limit
                        },
                        "Raw Data": data
                    }
                
                return result
            else:
                error_data = response.text
                try:
                    error_json = json.loads(error_data)
                    error_message = error_json.get('error', f"HTTP error {response.status_code}")
                except:
                    error_message = f"HTTP error {response.status_code}: {error_data[:100]}..."
                
                return {
                    "status": "error",
                    "message": error_message
                }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error retrieving CPEs: {str(e)}"
        }

async def get_cves(cpe23: str = None, product: str = None, count: bool = False, 
                   is_kev: bool = False, sort_by_epss: bool = False,
                   skip: int = 0, limit: int = 1000, 
                   start_date: str = None, end_date: str = None) -> Dict[str, Any]:
    """Get CVEs based on product name or CPE identifier.
    
    Retrieves Common Vulnerabilities and Exposures (CVEs) that match the specified criteria,
    allowing for targeted vulnerability discovery based on product or CPE.
    
    Parameters:
        cpe23: CPE 2.3 identifier to search for related CVEs
        product: Product name to search for related CVEs
        count: If True, returns only the count of matching CVEs
        is_kev: If True, returns only CVEs with the Known Exploited Vulnerability flag
        sort_by_epss: If True, sorts CVEs by EPSS score in descending order
        skip: Number of CVEs to skip (for pagination)
        limit: Maximum number of CVEs to return (max: 1000)
        start_date: Start date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
        end_date: End date for filtering CVEs (format: YYYY-MM-DDTHH:MM:SS)
    
    Note: You can specify either cpe23 or product, but not both.
    """
    try:
        # Verify that only one of cpe23 or product is specified
        if cpe23 and product:
            return {
                "status": "error",
                "message": "You can only specify one of 'cpe23' or 'product', not both."
            }
        
        # Prepare the API request URL and parameters
        url = f"{CVEDB_BASE_URL}/cves"
        params = {
            "count": str(count).lower(),
            "is_kev": str(is_kev).lower(),
            "sort_by_epss": str(sort_by_epss).lower(),
            "skip": skip,
            "limit": limit
        }
        
        # Add optional parameters if provided
        if cpe23:
            params["cpe23"] = cpe23
        if product:
            params["product"] = product
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        
        # Execute the API request
        async with httpx.AsyncClient() as client:
            response = await client.get(url, params=params)
            
            if response.status_code == 200:
                data = response.json()
                
                # Create a structured result
                if count:
                    result = {
                        "status": "success",
                        "Total CVEs": data.get("total", 0),
                        "Search Criteria": {
                            "CPE23": cpe23,
                            "Product": product,
                            "Is KEV": is_kev,
                            "Sort by EPSS": sort_by_epss,
                            "Date Range": f"{start_date or 'Not specified'} to {end_date or 'Present'}"
                        },
                        "Raw Data": data
                    }
                else:
                    # Process each CVE to create summary statistics
                    cves = data.get("cves", [])
                    
                    # Count severity levels
                    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
                    kev_count = 0
                    
                    for cve in cves:
                        # Count by severity
                        cvss = cve.get("cvss")
                        severity = get_severity_level(cvss)
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                        
                        # Count KEVs
                        if cve.get("kev", False):
                            kev_count += 1
                    
                    result = {
                        "status": "success",
                        "CVEs Found": len(cves),
                        "Search Criteria": {
                            "CPE23": cpe23,
                            "Product": product,
                            "Is KEV": is_kev,
                            "Sort by EPSS": sort_by_epss,
                            "Date Range": f"{start_date or 'Not specified'} to {end_date or 'Present'}"
                        },
                        "Summary Statistics": {
                            "Severity Distribution": severity_counts,
                            "Known Exploited Vulnerabilities": kev_count
                        },
                        "CVE List": cves,
                        "Pagination": {
                            "Skip": skip,
                            "Limit": limit
                        },
                        "Raw Data": data
                    }
                    
                    # If sorting by EPSS, notify in the result
                    if sort_by_epss:
                        result["Sorting"] = "Results are sorted by EPSS score (high to low)"
                
                return result
            else:
                error_data = response.text
                try:
                    error_json = json.loads(error_data)
                    error_message = error_json.get('error', f"HTTP error {response.status_code}")
                except:
                    error_message = f"HTTP error {response.status_code}: {error_data[:100]}..."
                
                return {
                    "status": "error",
                    "message": error_message
                }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error retrieving CVEs: {str(e)}"
        }

# Helper functions for CVE severity and risk assessment
def get_severity_level(cvss: float) -> str:
    """Convert CVSS score to severity level."""
    if cvss is None:
        return "None"
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0:
        return "Low"
    else:
        return "None"

def get_epss_risk_level(epss: float) -> str:
    """Convert EPSS score to risk level."""
    if epss is None:
        return "Unknown"
    if epss >= 0.5:
        return "Very High"
    elif epss >= 0.3:
        return "High"
    elif epss >= 0.1:
        return "Medium"
    elif epss > 0:
        return "Low"
    else:
        return "Very Low"

def get_prioritization(cvss: float, epss: float, kev: bool) -> str:
    """Generate prioritization guidance based on CVSS, EPSS, and KEV status."""
    if kev:
        return "Immediate Action Required - Known Exploited Vulnerability"
    
    if cvss is None or epss is None:
        return "Insufficient Information"
    
    if cvss >= 9.0 and epss >= 0.3:
        return "Critical Priority - High Impact and Likelihood"
    elif cvss >= 7.0 and epss >= 0.1:
        return "High Priority - Significant Risk"
    elif cvss >= 7.0 or epss >= 0.3:
        return "Medium-High Priority - Notable Risk"
    elif cvss >= 4.0 or epss >= 0.1:
        return "Medium Priority - Moderate Risk"
    else:
        return "Low Priority - Limited Risk"

async def get_shodan_count(query: str, facets: str = None) -> Dict[str, Any]:
    """Get the total number of results for a search query without returning any results.
    
    This search method behaves identical to "get_shodan_search" but doesn't return any host
    results, only the total number of matches and facet data if requested. This method
    does not consume query credits.
    
    Parameters:
        query: [String] Shodan search query using filter:value format
        facets: [String] Optional comma-separated list of properties to get summary information on
    
    Note: This method doesn't consume query credits, making it ideal for preliminary searches
    or for analyzing the distribution of results across different facets.
    """
    try:
        # Execute the count query against the Shodan API
        count_results = shodan_api.count(query, facets=facets)
        
        # Create Shodan URL for this search
        encoded_query = query.replace(" ", "%20").replace(":", "%3A").replace("\"", "%22")
        shodan_url = f"https://www.shodan.io/search?query={encoded_query}"
        
        # Build the response structure
        response = {
            "status": "success",
            "total": count_results.get("total", 0),
            "shodan_url": shodan_url,
            "query": query,
            "facets": count_results.get("facets", {})
        }
        
        # Calculate facet distributions if available
        facet_distributions = {}
        if "facets" in count_results:
            for facet_name, facet_values in count_results["facets"].items():
                distribution = []
                
                for entry in facet_values:
                    percentage = (entry["count"] / count_results.get("total", 1)) * 100
                    distribution.append({
                        "Value": entry["value"],
                        "Count": entry["count"],
                        "Percentage": f"{percentage:.2f}%"
                    })
                
                facet_distributions[facet_name] = distribution
        
        if facet_distributions:
            response["Facet Distributions"] = facet_distributions
        
        # Log response for debugging
        print(f"Count query found {count_results.get('total', 0)} total results for query: {query}")
        
        return response
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"Error in Shodan count search: {str(e)}\n{error_traceback}")
        return {
            "status": "error",
            "message": f"Error: {str(e)}",
            "traceback": error_traceback
        }