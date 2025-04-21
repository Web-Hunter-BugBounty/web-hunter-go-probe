
#!/usr/bin/env python3
"""
Cloud assets discovery module for ReconArsenal
"""

import os
import re
from colorama import Fore
from .utils import print_colored, show_progress, save_to_file, check_command, get_command_output

def discover_cloud_assets(domain, output_dir):
    """Discover cloud assets related to the target domain"""
    print_colored("[*] Starting cloud asset discovery...", Fore.BLUE)
    
    cloud_dir = os.path.join(output_dir, "cloud_assets")
    
    # Create directory if it doesn't exist
    if not os.path.exists(cloud_dir):
        os.makedirs(cloud_dir)
    
    # Check for tools
    tools = {
        "cloud_enum": check_command("cloud_enum"),
        "S3Scanner": check_command("S3Scanner"),
        "s3finder": check_command("s3finder"),
        "bucket_finder": check_command("bucket_finder"),
        "awscli": check_command("aws")
    }
    
    if not any(tools.values()):
        print_colored("[!] Cloud asset discovery tools not found. Using basic discovery...", Fore.YELLOW)
    
    # Sanitize domain for use in bucket/container names
    domain_parts = domain.replace('www.', '').split('.')
    company_name = domain_parts[0]
    
    # Generate potential bucket names
    bucket_names = [
        company_name,
        f"{company_name}-dev",
        f"{company_name}-staging",
        f"{company_name}-prod",
        f"{company_name}-production",
        f"{company_name}-test",
        f"{company_name}-backup",
        f"{company_name}-data",
        f"{company_name}-assets",
        f"{company_name}-files",
        f"{company_name}-media",
        f"{company_name}-static",
        f"{company_name}-public",
        f"{company_name}-private",
        f"{company_name}-internal",
        f"{company_name}-external",
        f"{company_name}-uploads",
        f"{company_name}-deploy",
        f"{company_name}-repository",
        f"{company_name}-logs",
    ]
    
    # Add variations with domain
    full_domain = '.'.join(domain_parts)
    bucket_names.extend([
        full_domain,
        f"{domain_parts[0]}.{domain_parts[1]}",
        f"{company_name}-{domain_parts[1]}",
    ])
    
    # Save bucket names to file
    bucket_names_file = os.path.join(cloud_dir, "potential_bucket_names.txt")
    save_to_file(bucket_names, bucket_names_file)
    
    # AWS S3 buckets
    aws_results = check_aws_s3(domain, company_name, bucket_names, cloud_dir, tools)
    
    # Azure Blob Storage
    azure_results = check_azure_blobs(domain, company_name, bucket_names, cloud_dir, tools)
    
    # Google Cloud Storage
    gcp_results = check_gcp_buckets(domain, company_name, bucket_names, cloud_dir, tools)
    
    # Save combined results
    all_cloud_assets = aws_results + azure_results + gcp_results
    
    if all_cloud_assets:
        cloud_summary = os.path.join(cloud_dir, "cloud_assets_summary.txt")
        save_to_file(all_cloud_assets, cloud_summary)
    
    print_colored(f"[+] Cloud asset discovery completed. Found {len(all_cloud_assets)} potential assets.", Fore.GREEN)
    
    return all_cloud_assets

def check_aws_s3(domain, company_name, bucket_names, cloud_dir, tools):
    """Check for AWS S3 buckets"""
    print_colored("[*] Checking for AWS S3 buckets...", Fore.BLUE)
    
    aws_dir = os.path.join(cloud_dir, "aws")
    if not os.path.exists(aws_dir):
        os.makedirs(aws_dir)
    
    s3_results = []
    
    # Generate S3 bucket URLs
    s3_urls = []
    for bucket in bucket_names:
        s3_urls.append(f"https://{bucket}.s3.amazonaws.com")
        s3_urls.append(f"https://s3.amazonaws.com/{bucket}")
    
    # Save S3 URLs to file
    s3_urls_file = os.path.join(aws_dir, "s3_urls.txt")
    save_to_file(s3_urls, s3_urls_file)
    
    # Use S3Scanner if available
    if tools.get("S3Scanner"):
        print_colored("[*] Using S3Scanner for S3 bucket discovery...", Fore.BLUE)
        
        s3scanner_output = os.path.join(aws_dir, "s3scanner_results.txt")
        s3scanner_cmd = f"S3Scanner scan -l {s3_urls_file} -o {s3scanner_output}"
        
        try:
            os.system(s3scanner_cmd)
            
            # Parse results
            if os.path.exists(s3scanner_output):
                with open(s3scanner_output, 'r') as f:
                    for line in f:
                        if "found" in line.lower() and "public" in line.lower():
                            s3_results.append(f"AWS S3 (Public): {line.strip()}")
                        elif "found" in line.lower():
                            s3_results.append(f"AWS S3: {line.strip()}")
        
        except Exception as e:
            print_colored(f"[!] Error running S3Scanner: {str(e)}", Fore.RED)
    
    # Use AWS CLI if available
    elif tools.get("awscli"):
        print_colored("[*] Using AWS CLI for S3 bucket validation...", Fore.BLUE)
        
        for bucket in bucket_names:
            aws_cmd = f"aws s3 ls s3://{bucket} --no-sign-request"
            
            try:
                output = get_command_output(aws_cmd)
                
                if output and "AccessDenied" not in output and "NoSuchBucket" not in output:
                    s3_results.append(f"AWS S3 (Public): s3://{bucket}")
            
            except Exception as e:
                pass
    
    # Use basic HTTP check if no tools available
    if not tools.get("S3Scanner") and not tools.get("awscli"):
        print_colored("[*] Using basic HTTP check for S3 buckets...", Fore.BLUE)
        
        import requests
        from urllib3.exceptions import InsecureRequestWarning
        
        # Suppress SSL warnings
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        
        progress = show_progress(len(s3_urls), "Checking S3 buckets")
        
        for url in s3_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                
                # Check for signs that the bucket exists
                if response.status_code in [200, 403]:
                    if "ListBucketResult" in response.text or "AccessDenied" in response.text:
                        s3_results.append(f"AWS S3: {url}")
                    
                    # Public bucket
                    if "ListBucketResult" in response.text and response.status_code == 200:
                        s3_results.append(f"AWS S3 (Public): {url}")
            
            except Exception as e:
                pass
            
            finally:
                progress.update(1)
        
        progress.close()
    
    # Save AWS results
    if s3_results:
        aws_result_file = os.path.join(aws_dir, "aws_s3_results.txt")
        save_to_file(s3_results, aws_result_file)
        
        print_colored(f"[+] Found {len(s3_results)} potential AWS S3 buckets", Fore.GREEN)
    else:
        print_colored("[-] No AWS S3 buckets found", Fore.YELLOW)
    
    return s3_results

def check_azure_blobs(domain, company_name, bucket_names, cloud_dir, tools):
    """Check for Azure Blob Storage containers"""
    print_colored("[*] Checking for Azure Blob Storage containers...", Fore.BLUE)
    
    azure_dir = os.path.join(cloud_dir, "azure")
    if not os.path.exists(azure_dir):
        os.makedirs(azure_dir)
    
    azure_results = []
    
    # Generate Azure Blob Storage URLs
    azure_urls = []
    for container in bucket_names:
        # Azure storage accounts can only use lowercase letters and numbers, max 24 chars
        account_name = re.sub(r'[^a-z0-9]', '', company_name.lower())[:24]
        azure_urls.append(f"https://{account_name}.blob.core.windows.net/{container}")
    
    # Save Azure URLs to file
    azure_urls_file = os.path.join(azure_dir, "azure_urls.txt")
    save_to_file(azure_urls, azure_urls_file)
    
    # Use basic HTTP check for Azure Blob Storage
    print_colored("[*] Using basic HTTP check for Azure Blob Storage...", Fore.BLUE)
    
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    progress = show_progress(len(azure_urls), "Checking Azure Blob Storage")
    
    for url in azure_urls:
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            # Check for signs that the container exists
            if response.status_code == 200:
                azure_results.append(f"Azure Blob Storage (Public): {url}")
            elif response.status_code == 403 and "AuthenticationFailed" not in response.text:
                azure_results.append(f"Azure Blob Storage: {url}")
        
        except Exception as e:
            pass
        
        finally:
            progress.update(1)
    
    progress.close()
    
    # Save Azure results
    if azure_results:
        azure_result_file = os.path.join(azure_dir, "azure_blob_results.txt")
        save_to_file(azure_results, azure_result_file)
        
        print_colored(f"[+] Found {len(azure_results)} potential Azure Blob Storage containers", Fore.GREEN)
    else:
        print_colored("[-] No Azure Blob Storage containers found", Fore.YELLOW)
    
    return azure_results

def check_gcp_buckets(domain, company_name, bucket_names, cloud_dir, tools):
    """Check for Google Cloud Storage buckets"""
    print_colored("[*] Checking for Google Cloud Storage buckets...", Fore.BLUE)
    
    gcp_dir = os.path.join(cloud_dir, "gcp")
    if not os.path.exists(gcp_dir):
        os.makedirs(gcp_dir)
    
    gcp_results = []
    
    # Generate GCP bucket URLs
    gcp_urls = []
    for bucket in bucket_names:
        gcp_urls.append(f"https://storage.googleapis.com/{bucket}")
        gcp_urls.append(f"https://{bucket}.storage.googleapis.com")
    
    # Save GCP URLs to file
    gcp_urls_file = os.path.join(gcp_dir, "gcp_urls.txt")
    save_to_file(gcp_urls, gcp_urls_file)
    
    # Use basic HTTP check for GCP buckets
    print_colored("[*] Using basic HTTP check for GCP buckets...", Fore.BLUE)
    
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    progress = show_progress(len(gcp_urls), "Checking GCP buckets")
    
    for url in gcp_urls:
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            # Check for signs that the bucket exists
            if response.status_code == 200:
                gcp_results.append(f"GCP Storage (Public): {url}")
            elif response.status_code == 403 and "AccessDenied" in response.text:
                gcp_results.append(f"GCP Storage: {url}")
        
        except Exception as e:
            pass
        
        finally:
            progress.update(1)
    
    progress.close()
    
    # Save GCP results
    if gcp_results:
        gcp_result_file = os.path.join(gcp_dir, "gcp_storage_results.txt")
        save_to_file(gcp_results, gcp_result_file)
        
        print_colored(f"[+] Found {len(gcp_results)} potential GCP Storage buckets", Fore.GREEN)
    else:
        print_colored("[-] No GCP Storage buckets found", Fore.YELLOW)
    
    return gcp_results

def api_fuzzing(domain, output_dir):
    """Discover and fuzz APIs"""
    print_colored("[*] Starting API discovery and fuzzing...", Fore.BLUE)
    
    api_dir = os.path.join(output_dir, "cloud_assets", "api")
    
    # Create directory if it doesn't exist
    if not os.path.exists(api_dir):
        os.makedirs(api_dir)
    
    # Check for tools
    tools = {
        "ffuf": check_command("ffuf"),
        "wfuzz": check_command("wfuzz"),
        "arjun": check_command("arjun")
    }
    
    if not any(tools.values()):
        print_colored("[!] API fuzzing tools not found. Using basic discovery...", Fore.YELLOW)
    
    # Common API paths to check
    api_paths = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/api/v3",
        "/v1",
        "/v2",
        "/v3",
        "/rest",
        "/rest/v1",
        "/rest/v2",
        "/graphql",
        "/query",
        "/service",
        "/services",
        "/swagger",
        "/swagger.json",
        "/swagger-ui.html",
        "/swagger-ui",
        "/swagger-resources",
        "/api-docs",
        "/api/docs",
        "/apidocs",
        "/openapi",
        "/openapi.json",
        "/docs/api",
        "/.well-known/openid-configuration",
        "/oauth/authorize",
        "/oauth/token",
        "/api/swagger.json",
        "/redoc",
        "/api/redoc"
    ]
    
    # Save API paths to file
    api_paths_file = os.path.join(api_dir, "api_paths.txt")
    save_to_file(api_paths, api_paths_file)
    
    # Check if domain has API endpoints
    print_colored("[*] Checking for API endpoints...", Fore.BLUE)
    
    api_endpoints = []
    base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    
    # Suppress SSL warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    progress = show_progress(len(api_paths), "Checking API paths")
    
    for path in api_paths:
        try:
            url = f"{base_url}{path}"
            response = requests.get(url, timeout=10, verify=False)
            
            # Check for signs of an API
            if response.status_code in [200, 201, 401, 403]:
                api_endpoints.append(url)
                
                # Check response type
                content_type = response.headers.get("Content-Type", "")
                
                if "application/json" in content_type or "swagger" in content_type:
                    api_endpoints.append(f"{url} (JSON API)")
                elif "application/xml" in content_type:
                    api_endpoints.append(f"{url} (XML API)")
                elif "text/html" in content_type and ("swagger" in response.text.lower() or "api" in response.text.lower()):
                    api_endpoints.append(f"{url} (API Documentation)")
        
        except Exception as e:
            pass
        
        finally:
            progress.update(1)
    
    progress.close()
    
    # Save discovered API endpoints
    if api_endpoints:
        api_endpoints_file = os.path.join(api_dir, "discovered_apis.txt")
        save_to_file(api_endpoints, api_endpoints_file)
        
        print_colored(f"[+] Found {len(api_endpoints)} potential API endpoints", Fore.GREEN)
    else:
        print_colored("[-] No API endpoints found", Fore.YELLOW)
    
    # Perform parameter discovery with Arjun
    if tools.get("arjun") and api_endpoints:
        print_colored("[*] Using Arjun for API parameter discovery...", Fore.BLUE)
        
        discovered_params = []
        
        for endpoint in api_endpoints:
            arjun_output = os.path.join(api_dir, f"arjun_{endpoint.replace('https://', '').replace('http://', '').replace('/', '_')}.json")
            arjun_cmd = f"arjun -u {endpoint} -t 10 --passive -o {arjun_output}"
            
            try:
                os.system(arjun_cmd)
                
                # Parse Arjun output
                if os.path.exists(arjun_output):
                    import json
                    
                    with open(arjun_output, 'r') as f:
                        try:
                            data = json.load(f)
                            
                            if data.get("params"):
                                params = data.get("params", [])
                                discovered_params.append(f"{endpoint}: {', '.join(params)}")
                        except json.JSONDecodeError:
                            pass
            
            except Exception as e:
                print_colored(f"[!] Error running Arjun on {endpoint}: {str(e)}", Fore.RED)
        
        # Save discovered parameters
        if discovered_params:
            params_file = os.path.join(api_dir, "discovered_parameters.txt")
            save_to_file(discovered_params, params_file)
            
            print_colored(f"[+] Discovered parameters for {len(discovered_params)} API endpoints", Fore.GREEN)
    
    # Check for leaked API keys in Swagger/OpenAPI documentation
    if api_endpoints:
        print_colored("[*] Checking for leaked API keys in documentation...", Fore.BLUE)
        
        api_leaks = []
        
        for endpoint in api_endpoints:
            try:
                response = requests.get(endpoint, timeout=10, verify=False)
                
                # Check for common API key patterns in response
                api_key_patterns = [
                    r'api[_-]key["\s\':]+([\w\d]+)',
                    r'apikey["\s\':]+([\w\d]+)',
                    r'authorization["\s\':]+([\w\d]+)',
                    r'access[_-]token["\s\':]+([\w\d]+)',
                    r'secret[_-]key["\s\':]+([\w\d]+)',
                    r'client[_-]secret["\s\':]+([\w\d]+)',
                    r'x[_-]api[_-]key["\s\':]+([\w\d]+)'
                ]
                
                for pattern in api_key_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    
                    for match in matches:
                        api_leaks.append(f"{endpoint}: Potential API key: {match}")
            
            except Exception as e:
                pass
        
        # Save API leaks
        if api_leaks:
            leaks_file = os.path.join(api_dir, "api_leaks.txt")
            save_to_file(api_leaks, leaks_file)
            
            print_colored(f"[+] Found {len(api_leaks)} potential API key leaks", Fore.GREEN)
    
    print_colored("[+] API discovery and fuzzing completed", Fore.GREEN)
    
    return api_endpoints
