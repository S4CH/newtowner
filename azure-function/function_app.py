import azure.functions as func
import aiohttp
import asyncio
import json
import hashlib
import ssl
import time
import logging
from typing import Dict, Any
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = func.FunctionApp()

@app.function_name("NewtownerHTTPCheck")
@app.route(route="newtowner-check", auth_level=func.AuthLevel.FUNCTION, methods=["POST"])
async def newtowner_http_check(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to perform HTTP checks for Newtowner
    Accepts POST requests with URL to check and returns detailed HTTP response information
    """
    try:
        # Parse request body
        req_body = req.get_json()
        if not req_body:
            return func.HttpResponse(
                json.dumps({"error": "Request body is required"}),
                status_code=400,
                mimetype="application/json"
            )
        
        url = req_body.get('url')
        method = req_body.get('method', 'GET').upper()
        headers = req_body.get('headers', {})
        timeout = req_body.get('timeout', 30)
        
        if not url:
            return func.HttpResponse(
                json.dumps({"error": "URL is required"}),
                status_code=400,
                mimetype="application/json"
            )
        
        logger.info(f"Checking URL: {url} with method: {method}")
        
        # Perform HTTP check
        result = await perform_http_check(url, method, headers, timeout)
        
        # Add Azure-specific metadata
        result['function_region'] = get_azure_region()
        result['function_execution_time_ms'] = int((time.time() * 1000) - result.get('start_time_ms', 0))
        
        # Remove internal timing data
        result.pop('start_time_ms', None)
        
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error in newtowner_http_check: {str(e)}")
        error_response = {
            "url": req_body.get('url', '') if req_body else '',
            "error": f"Function execution error: {str(e)}",
            "status_code": 0,
            "body": "",
            "body_sha256": "",
            "headers": {},
            "response_time_ms": 0,
            "ssl_certificate_pem": "",
            "ssl_certificate_error": "",
            "function_region": get_azure_region(),
            "function_execution_time_ms": 0
        }
        return func.HttpResponse(
            json.dumps(error_response),
            status_code=200,  # Return 200 to indicate function executed, even if target request failed
            mimetype="application/json"
        )

async def perform_http_check(url: str, method: str, headers: Dict[str, str], timeout: int) -> Dict[str, Any]:
    """
    Perform the actual HTTP check and return detailed response information
    """
    result = {
        "url": url,
        "status_code": 0,
        "body": "",
        "body_sha256": "",
        "headers": {},
        "response_time_ms": 0,
        "error": "",
        "ssl_certificate_pem": "",
        "ssl_certificate_error": "",
        "start_time_ms": time.time() * 1000
    }
    
    # Set default headers
    default_headers = {
        'User-Agent': 'Newtowner-Azure/1.0',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    default_headers.update(headers)
    
    try:
        # Create SSL context that captures certificate info
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        # Create connector with SSL context
        connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=10,
            limit_per_host=5,
            enable_cleanup_closed=True
        )
        
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        
        start_time = time.time()
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_config,
            headers=default_headers
        ) as session:
            
            async with session.request(method, url, allow_redirects=True) as response:
                end_time = time.time()
                result["response_time_ms"] = int((end_time - start_time) * 1000)
                
                # Get response details
                result["status_code"] = response.status
                
                # Read response body
                try:
                    body_bytes = await response.read()
                    result["body"] = body_bytes.decode('utf-8', errors='replace')
                    result["body_sha256"] = hashlib.sha256(body_bytes).hexdigest()
                except Exception as body_error:
                    logger.warning(f"Error reading response body: {str(body_error)}")
                    result["body"] = ""
                    result["body_sha256"] = ""
                
                # Get response headers
                result["headers"] = dict(response.headers)
                
                # Try to get SSL certificate information
                if response.url.scheme == 'https':
                    try:
                        ssl_info = response.connection.transport.get_extra_info('ssl_object')
                        if ssl_info:
                            peer_cert = ssl_info.getpeercert(binary_form=True)
                            if peer_cert:
                                import base64
                                cert_pem = ssl.DER_cert_to_PEM_cert(peer_cert)
                                result["ssl_certificate_pem"] = cert_pem
                    except Exception as ssl_error:
                        result["ssl_certificate_error"] = f"SSL certificate extraction error: {str(ssl_error)}"
                        logger.warning(f"SSL certificate error: {str(ssl_error)}")
                
    except asyncio.TimeoutError:
        result["error"] = f"Request timeout after {timeout} seconds"
        logger.warning(f"Timeout for URL: {url}")
    except aiohttp.ClientError as client_error:
        result["error"] = f"Client error: {str(client_error)}"
        logger.warning(f"Client error for URL {url}: {str(client_error)}")
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        logger.error(f"Unexpected error for URL {url}: {str(e)}")
    
    return result

def get_azure_region() -> str:
    """
    Attempt to determine the Azure region where this function is running
    """
    import os
    
    # Try to get region from environment variables
    region = os.environ.get('AZURE_REGION', '')
    if region:
        return region
    
    # Try to get from website resource group (common pattern)
    website_resource_group = os.environ.get('WEBSITE_RESOURCE_GROUP', '')
    if website_resource_group:
        # Extract region from resource group name if it follows naming convention
        for region_name in ['eastus', 'westus', 'westus2', 'centralus', 'northcentralus', 
                           'southcentralus', 'westcentralus', 'eastus2', 'westeurope', 
                           'northeurope', 'eastasia', 'southeastasia', 'japaneast', 
                           'japanwest', 'australiaeast', 'australiasoutheast', 'brazilsouth',
                           'canadacentral', 'canadaeast', 'uksouth', 'ukwest', 'koreacentral',
                           'koreasouth', 'francecentral', 'southafricanorth', 'uaenorth']:
            if region_name in website_resource_group.lower():
                return region_name
    
    # Try to get from function app name if it includes region
    website_site_name = os.environ.get('WEBSITE_SITE_NAME', '')
    if website_site_name:
        for region_name in ['eastus', 'westus', 'westus2', 'centralus', 'northcentralus', 
                           'southcentralus', 'westcentralus', 'eastus2', 'westeurope', 
                           'northeurope', 'eastasia', 'southeastasia', 'japaneast', 
                           'japanwest', 'australiaeast', 'australiasoutheast', 'brazilsouth',
                           'canadacentral', 'canadaeast', 'uksouth', 'ukwest', 'koreacentral',
                           'koreasouth', 'francecentral', 'southafricanorth', 'uaenorth']:
            if region_name in website_site_name.lower():
                return region_name
    
    # Default fallback
    return 'unknown'

if __name__ == "__main__":
    # For local testing
    import sys
    if len(sys.argv) > 1:
        test_url = sys.argv[1]
        result = asyncio.run(perform_http_check(test_url, 'GET', {}, 30))
        print(json.dumps(result, indent=2))
