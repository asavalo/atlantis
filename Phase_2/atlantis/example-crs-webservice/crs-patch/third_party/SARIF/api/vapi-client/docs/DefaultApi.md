# openapi_client.DefaultApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**broadcast_sarif_post**](DefaultApi.md#broadcast_sarif_post) | **POST** /broadcast/sarif/ | 
[**submit_patch_patch_id_get**](DefaultApi.md#submit_patch_patch_id_get) | **GET** /submit/patch/{patch_id} | 
[**submit_patch_pov_pov_id_post**](DefaultApi.md#submit_patch_pov_pov_id_post) | **POST** /submit/patch/pov/{pov_id} | 
[**submit_pov_post**](DefaultApi.md#submit_pov_post) | **POST** /submit/pov/ | 
[**submit_pov_pov_id_get**](DefaultApi.md#submit_pov_pov_id_get) | **GET** /submit/pov/{pov_id} | 
[**submit_sarif_post**](DefaultApi.md#submit_sarif_post) | **POST** /submit/sarif/ | 
[**task_sarif_post**](DefaultApi.md#task_sarif_post) | **POST** /task/sarif/ | 


# **broadcast_sarif_post**
> broadcast_sarif_post(payload)

submit a SARIF Assessment

### Example


```python
import openapi_client
from openapi_client.models.types_sarif_assessment_broadcast import TypesSarifAssessmentBroadcast
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    payload = openapi_client.TypesSarifAssessmentBroadcast() # TypesSarifAssessmentBroadcast | Submission body

    try:
        api_instance.broadcast_sarif_post(payload)
    except Exception as e:
        print("Exception when calling DefaultApi->broadcast_sarif_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **payload** | [**TypesSarifAssessmentBroadcast**](TypesSarifAssessmentBroadcast.md)| Submission body | 

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **submit_patch_patch_id_get**
> TypesPatchSubmissionResponse submit_patch_patch_id_get(patch_id)

yield the status of vuln testing

### Example


```python
import openapi_client
from openapi_client.models.types_patch_submission_response import TypesPatchSubmissionResponse
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    patch_id = 'patch_id_example' # str | Patch ID

    try:
        api_response = api_instance.submit_patch_patch_id_get(patch_id)
        print("The response of DefaultApi->submit_patch_patch_id_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->submit_patch_patch_id_get: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **patch_id** | **str**| Patch ID | 

### Return type

[**TypesPatchSubmissionResponse**](TypesPatchSubmissionResponse.md)

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **submit_patch_pov_pov_id_post**
> TypesPatchSubmissionResponse submit_patch_pov_pov_id_post(pov_id, payload)

submit a patch for pov

### Example


```python
import openapi_client
from openapi_client.models.types_patch_submission import TypesPatchSubmission
from openapi_client.models.types_patch_submission_response import TypesPatchSubmissionResponse
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    pov_id = 'pov_id_example' # str | POV ID
    payload = openapi_client.TypesPatchSubmission() # TypesPatchSubmission | Submission body

    try:
        api_response = api_instance.submit_patch_pov_pov_id_post(pov_id, payload)
        print("The response of DefaultApi->submit_patch_pov_pov_id_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->submit_patch_pov_pov_id_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pov_id** | **str**| POV ID | 
 **payload** | [**TypesPatchSubmission**](TypesPatchSubmission.md)| Submission body | 

### Return type

[**TypesPatchSubmissionResponse**](TypesPatchSubmissionResponse.md)

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **submit_pov_post**
> TypesPOVSubmissionResponse submit_pov_post(payload)

submit a POV

### Example


```python
import openapi_client
from openapi_client.models.types_pov_submission import TypesPOVSubmission
from openapi_client.models.types_pov_submission_response import TypesPOVSubmissionResponse
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    payload = openapi_client.TypesPOVSubmission() # TypesPOVSubmission | Submission body

    try:
        api_response = api_instance.submit_pov_post(payload)
        print("The response of DefaultApi->submit_pov_post:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->submit_pov_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **payload** | [**TypesPOVSubmission**](TypesPOVSubmission.md)| Submission body | 

### Return type

[**TypesPOVSubmissionResponse**](TypesPOVSubmissionResponse.md)

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **submit_pov_pov_id_get**
> TypesPOVSubmissionResponse submit_pov_pov_id_get(pov_id)

yield the status of vuln testing

### Example


```python
import openapi_client
from openapi_client.models.types_pov_submission_response import TypesPOVSubmissionResponse
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    pov_id = 'pov_id_example' # str | POV ID

    try:
        api_response = api_instance.submit_pov_pov_id_get(pov_id)
        print("The response of DefaultApi->submit_pov_pov_id_get:\n")
        pprint(api_response)
    except Exception as e:
        print("Exception when calling DefaultApi->submit_pov_pov_id_get: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **pov_id** | **str**| POV ID | 

### Return type

[**TypesPOVSubmissionResponse**](TypesPOVSubmissionResponse.md)

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **submit_sarif_post**
> submit_sarif_post(payload)

submit a SARIF Assessment

### Example


```python
import openapi_client
from openapi_client.models.types_sarif_assessment_submission import TypesSarifAssessmentSubmission
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    payload = openapi_client.TypesSarifAssessmentSubmission() # TypesSarifAssessmentSubmission | Submission body

    try:
        api_instance.submit_sarif_post(payload)
    except Exception as e:
        print("Exception when calling DefaultApi->submit_sarif_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **payload** | [**TypesSarifAssessmentSubmission**](TypesSarifAssessmentSubmission.md)| Submission body | 

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **task_sarif_post**
> task_sarif_post(payload)

Reqeust a SARIF Assessment

### Example


```python
import openapi_client
from openapi_client.models.types_sarif import TypesSarif
from openapi_client.rest import ApiException
from pprint import pprint

# Defining the host is optional and defaults to http://localhost
# See configuration.py for a list of all supported configuration parameters.
configuration = openapi_client.Configuration(
    host = "http://localhost"
)


# Enter a context with an instance of the API client
with openapi_client.ApiClient(configuration) as api_client:
    # Create an instance of the API class
    api_instance = openapi_client.DefaultApi(api_client)
    payload = openapi_client.TypesSarif() # TypesSarif | SARIF body

    try:
        api_instance.task_sarif_post(payload)
    except Exception as e:
        print("Exception when calling DefaultApi->task_sarif_post: %s\n" % e)
```



### Parameters


Name | Type | Description  | Notes
------------- | ------------- | ------------- | -------------
 **payload** | [**TypesSarif**](TypesSarif.md)| SARIF body | 

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
**401** | Unauthorized |  -  |
**404** | Not Found |  -  |
**500** | Internal Server Error |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

