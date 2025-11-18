# PatchStatus


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pov_id** | **str** | POV ID | 
**status** | **str** |  | 
**patch_diff** | **str** | Base64 encoded patch in unified diff format  null indicates the status is not succeeded | [optional] 

## Example

```python
from patch_client.models.patch_status import PatchStatus

# TODO update the JSON string below
json = "{}"
# create an instance of PatchStatus from a JSON string
patch_status_instance = PatchStatus.from_json(json)
# print the JSON string representation of the object
print(PatchStatus.to_json())

# convert the object into a dict
patch_status_dict = patch_status_instance.to_dict()
# create an instance of PatchStatus from a dict
patch_status_from_dict = PatchStatus.from_dict(patch_status_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


