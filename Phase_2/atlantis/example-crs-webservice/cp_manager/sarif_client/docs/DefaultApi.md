# sarif_client.DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**match_patch_post**](DefaultApi.md#match_patch_post) | **POST** /match/patch/ | Request Patch-SARIF match
[**match_pov_post**](DefaultApi.md#match_pov_post) | **POST** /match/pov/ | Request POV-SARIF match
[**match_sarif_post**](DefaultApi.md#match_sarif_post) | **POST** /match/sarif/ | Request POV-SARIF match


# **match_patch_post**
> match_patch_post(patch_match_request=patch_match_request)

Request Patch-SARIF match

### Example


```python
import sarif_client
from sarif_client.models.patch_match_request import PatchMatchRequest
from sarif_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = sarif_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with sarif_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = sarif_client.DefaultApi(api_client)
    patch_match_request = sarif_client.PatchMatchRequest() # PatchMatchRequest | PatchMatchRequest (optional)

    try:
        # Request Patch-SARIF match
        api_instance.match_patch_post(patch_match_request=patch_match_request)
    except Exception as e:
        print("Exception when calling DefaultApi->match_patch_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patch_match_request** | [**PatchMatchRequest**](PatchMatchRequest.md)| PatchMatchRequest | [optional] 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | OK |  -  |
**400** | Bad Request |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **match_pov_post**
> match_pov_post(pov_match_request=pov_match_request)

Request POV-SARIF match

### Example


```python
import sarif_client
from sarif_client.models.pov_match_request import POVMatchRequest
from sarif_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = sarif_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with sarif_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = sarif_client.DefaultApi(api_client)
    pov_match_request = sarif_client.POVMatchRequest() # POVMatchRequest | POVMatchRequest (optional)

    try:
        # Request POV-SARIF match
        api_instance.match_pov_post(pov_match_request=pov_match_request)
    except Exception as e:
        print("Exception when calling DefaultApi->match_pov_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pov_match_request** | [**POVMatchRequest**](POVMatchRequest.md)| POVMatchRequest | [optional] 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | OK |  -  |
**400** | Bad Request |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **match_sarif_post**
> match_sarif_post(sarif_match_request=sarif_match_request)

Request POV-SARIF match

### Example


```python
import sarif_client
from sarif_client.models.sarif_match_request import SARIFMatchRequest
from sarif_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = sarif_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with sarif_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = sarif_client.DefaultApi(api_client)
    sarif_match_request = sarif_client.SARIFMatchRequest() # SARIFMatchRequest | SARIFMatchRequest (optional)

    try:
        # Request POV-SARIF match
        api_instance.match_sarif_post(sarif_match_request=sarif_match_request)
    except Exception as e:
        print("Exception when calling DefaultApi->match_sarif_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **sarif_match_request** | [**SARIFMatchRequest**](SARIFMatchRequest.md)| SARIFMatchRequest | [optional] 

### Return type

void (empty response body)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | OK |  -  |
**400** | Bad Request |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

