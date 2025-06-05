# Azure Functions Provider Setup

This directory contains the Azure Function implementation for the Newtowner Azure provider.

## Prerequisites

1. **Azure CLI**: Install from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli
2. **Azure Functions Core Tools**: Install from https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local
3. **Python 3.9+**: Required for Azure Functions Python runtime

## Deployment Steps

### 1. Login to Azure
```bash
az login
```

### 2. Create Resource Groups and Function Apps

For each Azure region you want to support, create a Function App. Here's an example for multiple regions:

```bash
# Set variables
RESOURCE_GROUP_PREFIX="newtowner"
FUNCTION_APP_PREFIX="newtowner-http-check"
STORAGE_ACCOUNT_PREFIX="newtownerstorage"
SUBSCRIPTION_ID="your-subscription-id"

# Select your subscription
az account set --subscription $SUBSCRIPTION_ID

# Create Function Apps in multiple regions
REGIONS=("eastus" "westus2" "westeurope" "eastasia" "australiaeast" "brazilsouth" "canadacentral" "japaneast" "northeurope" "southeastasia")

for region in "${REGIONS[@]}"; do
    echo "Creating resources in $region..."
    
    # Create resource group
    az group create --name "${RESOURCE_GROUP_PREFIX}-${region}" --location $region
    
    # Create storage account
    az storage account create \
        --name "${STORAGE_ACCOUNT_PREFIX}${region}" \
        --location $region \
        --resource-group "${RESOURCE_GROUP_PREFIX}-${region}" \
        --sku Standard_LRS
    
    # Create function app
    az functionapp create \
        --resource-group "${RESOURCE_GROUP_PREFIX}-${region}" \
        --consumption-plan-location $region \
        --runtime python \
        --runtime-version 3.9 \
        --functions-version 4 \
        --name "${FUNCTION_APP_PREFIX}-${region}" \
        --storage-account "${STORAGE_ACCOUNT_PREFIX}${region}"
        
    echo "Created Function App: ${FUNCTION_APP_PREFIX}-${region}"
done
```

### 3. Deploy the Function Code

Deploy to each Function App:

```bash
for region in "${REGIONS[@]}"; do
    echo "Deploying to ${FUNCTION_APP_PREFIX}-${region}..."
    
    # Deploy the function
    func azure functionapp publish "${FUNCTION_APP_PREFIX}-${region}" --python
    
    echo "Deployed to $region"
done
```

### 4. Get Function Keys

After deployment, get the function keys for authentication:

```bash
for region in "${REGIONS[@]}"; do
    echo "Getting function key for $region..."
    
    # Get the function key
    FUNCTION_KEY=$(az functionapp function keys list \
        --function-name "NewtownerHTTPCheck" \
        --name "${FUNCTION_APP_PREFIX}-${region}" \
        --resource-group "${RESOURCE_GROUP_PREFIX}-${region}" \
        --query "default" -o tsv)
    
    echo "Region: $region"
    echo "Function Key: $FUNCTION_KEY"
    echo "Function URL: https://${FUNCTION_APP_PREFIX}-${region}.azurewebsites.net/api/newtowner-check?code=$FUNCTION_KEY"
    echo "---"
done
```

## Configuration

Add the following to your `configuration.json`:

```json
{
  "azure_function_app_name": "newtowner-http-check",
  "azure_function_name": "newtowner-check",
  "azure_function_key": "your-function-key-here"
}
```

## Usage

```bash
# Test a single region
./newtowner --provider azure --region eastus --urls urls.txt

# Test all configured regions
./newtowner --provider azure --all-regions --urls urls.txt

# Smart region detection (automatically choose best region per URL)
./newtowner --provider azure --urls urls.txt
```

## Testing the Function Locally

You can test the function locally before deployment:

```bash
cd azure-function
func start

# In another terminal, test with curl:
curl -X POST http://localhost:7071/api/newtowner-check \
  -H "Content-Type: application/json" \
  -d '{"url": "https://httpbin.org/get", "method": "GET", "timeout": 30}'
```

## Function Monitoring

You can monitor your functions through:

1. **Azure Portal**: Go to your Function App → Monitor
2. **Application Insights**: Automatically enabled for detailed logging
3. **Azure CLI**:
   ```bash
   az monitor log-analytics query \
     --workspace "your-workspace-id" \
     --analytics-query "traces | where message contains 'newtowner'"
   ```

## Cost Considerations

- **Consumption Plan**: Pay only for execution time (~$0.20 per million executions)
- **Storage**: Minimal cost for function code storage
- **Bandwidth**: Outbound data transfer charges may apply for high-volume testing

## Security Notes

- Function keys provide authentication
- Consider using Azure Key Vault for production deployments
- Functions run in a managed environment with automatic HTTPS
- Each region deployment is isolated

## Troubleshooting

1. **Deployment Issues**:
   ```bash
   func azure functionapp logstream "newtowner-http-check-eastus"
   ```

2. **Runtime Errors**: Check Application Insights logs in Azure Portal

3. **Connectivity Issues**: Verify function URLs and keys are correct

4. **Timeout Issues**: Increase function timeout in `host.json` if needed
