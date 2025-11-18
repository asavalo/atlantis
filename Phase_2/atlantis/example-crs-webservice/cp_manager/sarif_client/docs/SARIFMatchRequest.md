# SARIFMatchRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**metadata** | **object** | String to string map containing data that should be attached to outputs like log messages and OpenTelemetry trace attributes for traceability | 
**sarif** | **object** | SARIF Report compliant with provided schema | 
**sarif_id** | **str** |  | 

## Example

```python
from sarif_client.models.sarif_match_request import SARIFMatchRequest

# TODO update the JSON string below
json = "{}"
# create an instance of SARIFMatchRequest from a JSON string
sarif_match_request_instance = SARIFMatchRequest.from_json(json)
# print the JSON string representation of the object
print(SARIFMatchRequest.to_json())

# convert the object into a dict
sarif_match_request_dict = sarif_match_request_instance.to_dict()
# create an instance of SARIFMatchRequest from a dict
sarif_match_request_from_dict = SARIFMatchRequest.from_dict(sarif_match_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


