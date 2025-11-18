# patch_client.PatchApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**v1_patch_post**](PatchApi.md#v1_patch_post) | **POST** /v1/patch/ | Request Patch Generation
[**v1_patch_pov_id_get**](PatchApi.md#v1_patch_pov_id_get) | **GET** /v1/patch/{pov_id}/ | Patch Status


# **v1_patch_post**
> v1_patch_post(patch_request=patch_request)

Request Patch Generation

request a patch generation with PoV

### Example


```python
import patch_client
from patch_client.models.patch_request import PatchRequest
from patch_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = patch_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with patch_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = patch_client.PatchApi(api_client)
    patch_request = patch_client.PatchRequest() # PatchRequest | Patch Request (optional)

    try:
        # Request Patch Generation
        api_instance.v1_patch_post(patch_request=patch_request)
    except Exception as e:
        print("Exception when calling PatchApi->v1_patch_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patch_request** | [**PatchRequest**](PatchRequest.md)| Patch Request | [optional] 

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

# **v1_patch_pov_id_get**
> PatchStatus v1_patch_pov_id_get(pov_id)

Patch Status

yield the status of patch generation

### Example


```python
import patch_client
from patch_client.models.patch_status import PatchStatus
from patch_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = patch_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with patch_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = patch_client.PatchApi(api_client)
    pov_id = 'pov_id_example' # str | POV ID

    try:
        # Patch Status
        api_response = api_instance.v1_patch_pov_id_get(pov_id)
        print("The response of PatchApi->v1_patch_pov_id_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling PatchApi->v1_patch_pov_id_get: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pov_id** | **str**| POV ID | 

### Return type

[**PatchStatus**](PatchStatus.md)

### Authorization

No authorization required

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json

### HTTP response details

| Status code | Description | Response headers |
|-------------|-------------|------------------|
**200** | OK |  -  |
**400** | Bad Request |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

