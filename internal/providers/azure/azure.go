package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"newtowner/internal/util"
	"strings"
	"time"
)

const (
	azureFunctionURLBatchSize = 50
	functionTimeout           = 300 // 5 minutes
)

// AzureRegion represents an Azure region with its properties
type AzureRegion struct {
	Name        string
	DisplayName string
	Endpoint    string
}

// Predefined Azure regions for testing
var DefaultAzureRegions = []AzureRegion{
	{Name: "eastus", DisplayName: "East US", Endpoint: "eastus"},
	{Name: "westus2", DisplayName: "West US 2", Endpoint: "westus2"},
	{Name: "westeurope", DisplayName: "West Europe", Endpoint: "westeurope"},
	{Name: "eastasia", DisplayName: "East Asia", Endpoint: "eastasia"},
	{Name: "australiaeast", DisplayName: "Australia East", Endpoint: "australiaeast"},
	{Name: "brazilsouth", DisplayName: "Brazil South", Endpoint: "brazilsouth"},
	{Name: "canadacentral", DisplayName: "Canada Central", Endpoint: "canadacentral"},
	{Name: "japaneast", DisplayName: "Japan East", Endpoint: "japaneast"},
	{Name: "northeurope", DisplayName: "North Europe", Endpoint: "northeurope"},
	{Name: "southeastasia", DisplayName: "Southeast Asia", Endpoint: "southeastasia"},
}

type URLCheckResult struct {
	URL              string
	Error            string
	DirectRequest    util.RequestDetails
	ProviderRequest  util.RequestDetails
	Comparison       util.ComparisonResult
	PotentialBypass  bool
	BypassReason     string
	AzureRegion      string
	AzureDisplayName string
	FunctionURL      string
	TargetHostname   string
	TargetResolvedIP string
	TargetGeoCountry string
	TargetGeoRegion  string
}

func (r URLCheckResult) GetURL() string {
	return r.URL
}

func (r URLCheckResult) GetTargetHostname() string {
	return r.TargetHostname
}

func (r URLCheckResult) GetTargetResolvedIP() string {
	return r.TargetResolvedIP
}

func (r URLCheckResult) GetTargetGeoCountry() string {
	return r.TargetGeoCountry
}

func (r URLCheckResult) GetTargetGeoRegion() string {
	return r.TargetGeoRegion
}

func (r URLCheckResult) GetProcessingError() string {
	return r.Error
}

func (r URLCheckResult) GetDirectRequestDetails() util.RequestDetails {
	return r.DirectRequest
}

func (r URLCheckResult) GetDirectDisplayName() string {
	return "Direct Request Details"
}

func (r URLCheckResult) GetProviderRequestDetails() util.RequestDetails {
	return r.ProviderRequest
}

func (r URLCheckResult) GetProviderDisplayName() string {
	return "Azure Function Request"
}

func (r URLCheckResult) GetProviderSubDetails() string {
	if r.FunctionURL == "" {
		return fmt.Sprintf("Region: %s, Status: Function not available", r.AzureDisplayName)
	}
	return fmt.Sprintf("Region: %s (%s)", r.AzureDisplayName, r.AzureRegion)
}

func (r URLCheckResult) GetComparisonResult() util.ComparisonResult {
	return r.Comparison
}

func (r URLCheckResult) IsPotentialBypass() bool {
	return r.PotentialBypass
}

func (r URLCheckResult) GetBypassReason() string {
	return r.BypassReason
}

func (r URLCheckResult) ShouldSkipBodyDiff() bool {
	return r.Error != "" || r.FunctionURL == "" || r.DirectRequest.Error != "" || r.ProviderRequest.Error != ""
}

type Provider struct {
	client          *http.Client
	functionAppName string
	functionName    string
	functionKey     string
	regionsToTest   []AzureRegion
	determineRegion bool
	initialRegion   string
}

// HTTPCheckRequest represents the request structure for Azure Function
type HTTPCheckRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout int               `json:"timeout"`
}

// HTTPCheckResponse represents the response structure from Azure Function
type HTTPCheckResponse struct {
	URL                   string            `json:"url"`
	StatusCode            int               `json:"status_code"`
	Body                  string            `json:"body"`
	BodySHA256            string            `json:"body_sha256"`
	Headers               map[string]string `json:"headers"`
	ResponseTimeMs        int64             `json:"response_time_ms"`
	Error                 string            `json:"error"`
	SSLCertificatePEM     string            `json:"ssl_certificate_pem"`
	SSLCertificateError   string            `json:"ssl_certificate_error"`
	FunctionRegion        string            `json:"function_region"`
	FunctionExecutionTime int64             `json:"function_execution_time_ms"`
}

// NewProvider creates and initializes a new Azure Functions Provider
func NewProvider(ctx context.Context, functionAppName, functionName, functionKey, regionValue string, allRegionsFlag bool) (*Provider, error) {
	if functionAppName == "" {
		return nil, fmt.Errorf("function app name must be provided")
	}
	if functionName == "" {
		return nil, fmt.Errorf("function name must be provided")
	}
	if functionKey == "" {
		return nil, fmt.Errorf("function key must be provided")
	}

	client := &http.Client{
		Timeout: time.Duration(functionTimeout+30) * time.Second,
	}

	var regionsToTest []AzureRegion
	var determineRegion bool
	var initialRegion string

	if allRegionsFlag {
		regionsToTest = DefaultAzureRegions
		initialRegion = "eastus" // fallback
		log.Printf("Azure Provider: Testing all %d predefined regions", len(regionsToTest))
	} else if regionValue != "" {
		// Find the specific region
		found := false
		for _, region := range DefaultAzureRegions {
			if region.Name == regionValue {
				regionsToTest = []AzureRegion{region}
				initialRegion = regionValue
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown Azure region: %s", regionValue)
		}
		log.Printf("Azure Provider: Testing specific region: %s", regionValue)
	} else {
		// Smart region detection mode
		determineRegion = true
		initialRegion = "eastus" // fallback
		log.Printf("Azure Provider: Smart region detection mode enabled (fallback: %s)", initialRegion)
	}

	return &Provider{
		client:          client,
		functionAppName: functionAppName,
		functionName:    functionName,
		functionKey:     functionKey,
		regionsToTest:   regionsToTest,
		determineRegion: determineRegion,
		initialRegion:   initialRegion,
	}, nil
}

// CheckURLs performs checks for the given URLs using Azure Functions
func (p *Provider) CheckURLs(urls []string) ([]URLCheckResult, error) {
	log.Printf("Azure Provider: Checking %d URLs. Mode: %s", len(urls), func() string {
		if p.determineRegion {
			return fmt.Sprintf("smart geo-detection (1 region per URL, fallback: %s)", p.initialRegion)
		}
		if len(p.regionsToTest) > 1 {
			return fmt.Sprintf("%d regions", len(p.regionsToTest))
		}
		if len(p.regionsToTest) == 1 {
			return fmt.Sprintf("specified region: %s", p.regionsToTest[0].Name)
		}
		return "unknown (error in region setup)"
	}())

	ctx := context.Background()
	allResults := make([]URLCheckResult, 0)

	for _, rawURL := range urls {
		log.Printf("Azure Provider: Processing URL: %s", rawURL)

		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			allResults = append(allResults, URLCheckResult{
				URL:   rawURL,
				Error: fmt.Sprintf("Error parsing URL: %v", err),
			})
			continue
		}

		baseTargetHostname := parsedURL.Hostname()
		if baseTargetHostname == "" {
			allResults = append(allResults, URLCheckResult{
				URL:            rawURL,
				Error:          "Could not extract hostname from URL",
				TargetHostname: baseTargetHostname,
			})
			continue
		}

		log.Printf("  Hostname: %s", baseTargetHostname)

		// Get geo-location and make direct request once per URL
		var targetResolvedIP, targetGeoCountry, targetGeoRegionName string
		geoLoc, resolvedIP, geoErr := util.ResolveHostAndGetGeoLocation(baseTargetHostname)
		if geoErr != nil {
			log.Printf("  Warning: Error resolving host or getting geolocation for %s: %v", baseTargetHostname, geoErr)
		} else {
			targetResolvedIP = resolvedIP.String()
			targetGeoCountry = geoLoc.CountryCode
			targetGeoRegionName = geoLoc.RegionName
			log.Printf("  Resolved IP: %s, Country: %s, GeoLocation: %s", resolvedIP.String(), geoLoc.CountryCode, geoLoc.RegionName)
		}

		log.Printf("  Making direct request to %s", rawURL)
		directRequestDetails := util.MakeHTTPRequest(ctx, "GET", rawURL, false)
		if directRequestDetails.Error != "" {
			log.Printf("    Direct request error: %s", directRequestDetails.Error)
		} else {
			log.Printf("    Direct request completed. Status: %d, Body SHA256: %s, Time: %dms",
				directRequestDetails.StatusCode, directRequestDetails.BodySHA256, directRequestDetails.ResponseTime)
		}

		// Determine regions to test for this URL
		regionsForThisURL := p.regionsToTest
		if p.determineRegion {
			determinedRegion, err := p.determineAzureRegionFromGeo(targetGeoCountry, targetGeoRegionName)
			if err != nil {
				log.Printf("  Smart region detection failed for %s (%s, %s): %v. Skipping Azure check for this URL.",
					rawURL, targetGeoCountry, targetGeoRegionName, err)
				result := URLCheckResult{
					URL:              rawURL,
					Error:            fmt.Sprintf("Azure region auto-detection failed: %v", err),
					DirectRequest:    directRequestDetails,
					TargetHostname:   baseTargetHostname,
					TargetResolvedIP: targetResolvedIP,
					TargetGeoCountry: targetGeoCountry,
					TargetGeoRegion:  targetGeoRegionName,
				}
				allResults = append(allResults, result)
				continue
			}
			regionsForThisURL = []AzureRegion{determinedRegion}
			log.Printf("  Smartly determined Azure region for %s: %s", rawURL, determinedRegion.Name)
		}

		if len(regionsForThisURL) == 0 {
			log.Printf("  No Azure regions to test for URL %s. Skipping Azure checks.", rawURL)
			result := URLCheckResult{
				URL:              rawURL,
				Error:            "No Azure regions configured or determined for testing this URL",
				DirectRequest:    directRequestDetails,
				TargetHostname:   baseTargetHostname,
				TargetResolvedIP: targetResolvedIP,
				TargetGeoCountry: targetGeoCountry,
				TargetGeoRegion:  targetGeoRegionName,
			}
			allResults = append(allResults, result)
			continue
		}

		// Test each region for this URL
		for _, currentRegion := range regionsForThisURL {
			log.Printf("    Testing URL %s in Azure region: %s", rawURL, currentRegion.Name)

			currentResult := URLCheckResult{
				URL:              rawURL,
				AzureRegion:      currentRegion.Name,
				AzureDisplayName: currentRegion.DisplayName,
				TargetHostname:   baseTargetHostname,
				TargetResolvedIP: targetResolvedIP,
				TargetGeoCountry: targetGeoCountry,
				TargetGeoRegion:  targetGeoRegionName,
				DirectRequest:    directRequestDetails,
			}

			// Construct Azure Function URL for this region
			functionURL := p.buildFunctionURL(currentRegion.Name)
			currentResult.FunctionURL = functionURL

			// Make request via Azure Function
			log.Printf("    Making request via Azure Function in region %s: %s", currentRegion.Name, functionURL)
			azureResponse, err := p.makeAzureFunctionRequest(ctx, functionURL, rawURL)
			if err != nil {
				currentResult.Error = fmt.Sprintf("Error calling Azure Function in region %s: %v", currentRegion.Name, err)
				currentResult.ProviderRequest.Error = currentResult.Error
				currentResult.ProviderRequest.URL = rawURL
				log.Printf("      Azure Function request error: %s", currentResult.Error)
			} else {
				// Convert Azure response to RequestDetails
				currentResult.ProviderRequest = util.RequestDetails{
					URL:                 azureResponse.URL,
					StatusCode:          azureResponse.StatusCode,
					Body:                azureResponse.Body,
					BodySHA256:          azureResponse.BodySHA256,
					Headers:             p.convertHeaders(azureResponse.Headers),
					ResponseTime:        azureResponse.ResponseTimeMs,
					Error:               azureResponse.Error,
					SSLCertificatePEM:   azureResponse.SSLCertificatePEM,
					SSLCertificateError: azureResponse.SSLCertificateError,
				}

				log.Printf("      Azure Function request completed. Status: %d, Body SHA256: %s, Time: %dms",
					azureResponse.StatusCode, azureResponse.BodySHA256, azureResponse.ResponseTimeMs)

				if azureResponse.Error != "" {
					currentResult.Error = fmt.Sprintf("Azure Function reported error: %s", azureResponse.Error)
				}
			}

			// Compare responses
			if currentResult.DirectRequest.Error == "" && currentResult.ProviderRequest.Error == "" {
				comparisonResult, potentialBypass, bypassReason := util.CompareHTTPResponses(currentResult.DirectRequest, currentResult.ProviderRequest)
				currentResult.Comparison = comparisonResult
				currentResult.PotentialBypass = potentialBypass
				currentResult.BypassReason = bypassReason

				if potentialBypass {
					log.Printf("      Potential Bypass Detected for %s in region %s: %s", rawURL, currentRegion.Name, bypassReason)
				} else {
					log.Printf("      No significant differences detected for %s in region %s", rawURL, currentRegion.Name)
				}
			} else {
				log.Printf("      Bypass assessment for %s in region %s inconclusive due to errors", rawURL, currentRegion.Name)
				currentResult.PotentialBypass = false
				if currentResult.DirectRequest.Error != "" && currentResult.ProviderRequest.Error != "" {
					currentResult.BypassReason = "Comparison skipped due to both direct and Azure Function request errors"
				} else if currentResult.DirectRequest.Error != "" {
					currentResult.BypassReason = "Comparison skipped due to direct request error"
				} else {
					currentResult.BypassReason = "Comparison skipped due to Azure Function request error"
				}
			}

			allResults = append(allResults, currentResult)
		}
	}

	return allResults, nil
}

// buildFunctionURL constructs the Azure Function URL for a given region
func (p *Provider) buildFunctionURL(region string) string {
	return fmt.Sprintf("https://%s-%s.azurewebsites.net/api/%s?code=%s",
		p.functionAppName, region, p.functionName, p.functionKey)
}

// makeAzureFunctionRequest calls the Azure Function to perform HTTP check
func (p *Provider) makeAzureFunctionRequest(ctx context.Context, functionURL, targetURL string) (*HTTPCheckResponse, error) {
	requestPayload := HTTPCheckRequest{
		URL:     targetURL,
		Method:  "GET",
		Timeout: functionTimeout,
	}

	jsonPayload, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request payload: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", functionURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Newtowner/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request to Azure Function: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("function returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var azureResponse HTTPCheckResponse
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&azureResponse); err != nil {
		return nil, fmt.Errorf("error decoding Azure Function response: %v", err)
	}

	return &azureResponse, nil
}

// convertHeaders converts map[string]string to http.Header
func (p *Provider) convertHeaders(headers map[string]string) http.Header {
	result := make(http.Header)
	for k, v := range headers {
		result.Set(k, v)
	}
	return result
}

// determineAzureRegionFromGeo determines the best Azure region based on geolocation
func (p *Provider) determineAzureRegionFromGeo(countryCode, _ string) (AzureRegion, error) {
	countryCode = strings.ToUpper(countryCode)

	// Region mapping based on geography
	regionMap := map[string]string{
		"US": "eastus",        // United States -> East US
		"CA": "canadacentral", // Canada -> Canada Central
		"GB": "westeurope",    // United Kingdom -> West Europe
		"DE": "westeurope",    // Germany -> West Europe
		"FR": "westeurope",    // France -> West Europe
		"NL": "westeurope",    // Netherlands -> West Europe
		"IT": "westeurope",    // Italy -> West Europe
		"ES": "westeurope",    // Spain -> West Europe
		"NO": "northeurope",   // Norway -> North Europe
		"SE": "northeurope",   // Sweden -> North Europe
		"DK": "northeurope",   // Denmark -> North Europe
		"FI": "northeurope",   // Finland -> North Europe
		"JP": "japaneast",     // Japan -> Japan East
		"AU": "australiaeast", // Australia -> Australia East
		"NZ": "australiaeast", // New Zealand -> Australia East
		"BR": "brazilsouth",   // Brazil -> Brazil South
		"SG": "southeastasia", // Singapore -> Southeast Asia
		"MY": "southeastasia", // Malaysia -> Southeast Asia
		"TH": "southeastasia", // Thailand -> Southeast Asia
		"ID": "southeastasia", // Indonesia -> Southeast Asia
		"PH": "southeastasia", // Philippines -> Southeast Asia
		"VN": "southeastasia", // Vietnam -> Southeast Asia
		"HK": "eastasia",      // Hong Kong -> East Asia
		"TW": "eastasia",      // Taiwan -> East Asia
		"KR": "eastasia",      // South Korea -> East Asia
		"CN": "eastasia",      // China -> East Asia (Note: Azure China is separate)
		"IN": "eastasia",      // India -> East Asia (closest available)
	}

	if regionName, found := regionMap[countryCode]; found {
		for _, region := range DefaultAzureRegions {
			if region.Name == regionName {
				return region, nil
			}
		}
	}

	// Fallback to East US
	for _, region := range DefaultAzureRegions {
		if region.Name == p.initialRegion {
			return region, nil
		}
	}

	return AzureRegion{}, fmt.Errorf("unable to determine Azure region for country %s", countryCode)
}
