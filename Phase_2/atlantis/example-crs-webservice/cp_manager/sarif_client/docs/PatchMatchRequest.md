# PatchMatchRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pov_id** | **str** | patched pov id | 
**patch_id** | **str** | patch id | 
**diff** | **str** | patch diff | 

## Example

```python
from sarif_client.models.patch_match_request import PatchMatchRequest

# TODO update the JSON string below
json = "{}"
# create an instance of PatchMatchRequest from a JSON string
patch_match_request_instance = PatchMatchRequest.from_json(json)
# print the JSON string representation of the object
print(PatchMatchRequest.to_json())

# convert the object into a dict
patch_match_request_dict = patch_match_request_instance.to_dict()
# create an instance of PatchMatchRequest from a dict
patch_match_request_from_dict = PatchMatchRequest.from_dict(patch_match_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


