# POVMatchRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pov_id** | **str** |  | 
**fuzzer_name** | **str** | Fuzz Tooling fuzzer that exercises this vuln  4KiB max size | 
**sanitizer** | **str** | Fuzz Tooling Sanitizer that exercises this vuln  4KiB max size | 
**testcase** | **str** | Base64 encoded vuln trigger  2MiB max size before Base64 encoding | 
**crash_log** | **str** | Crash log from the POV  2MiB max size | 

## Example

```python
from sarif_client.models.pov_match_request import POVMatchRequest

# TODO update the JSON string below
json = "{}"
# create an instance of POVMatchRequest from a JSON string
pov_match_request_instance = POVMatchRequest.from_json(json)
# print the JSON string representation of the object
print(POVMatchRequest.to_json())

# convert the object into a dict
pov_match_request_dict = pov_match_request_instance.to_dict()
# create an instance of POVMatchRequest from a dict
pov_match_request_from_dict = POVMatchRequest.from_dict(pov_match_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


