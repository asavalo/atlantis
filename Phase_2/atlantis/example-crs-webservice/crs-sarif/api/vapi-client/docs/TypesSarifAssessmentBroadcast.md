# TypesSarifAssessmentBroadcast


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**analysis_result** | **Dict[str, object]** | Analysis result in form of object # TODO: Fix fields 128KiB max size | 
**sarif_id** | **str** |  | 
**fuzzer_name** | **str** | Fuzz Tooling fuzzer that exercises this vuln  4KiB max size | 

## Example

```python
from openapi_client.models.types_sarif_assessment_broadcast import TypesSarifAssessmentBroadcast

# TODO update the JSON string below
json = "{}"
# create an instance of TypesSarifAssessmentBroadcast from a JSON string
types_sarif_assessment_broadcast_instance = TypesSarifAssessmentBroadcast.from_json(json)
# print the JSON string representation of the object
print(TypesSarifAssessmentBroadcast.to_json())

# convert the object into a dict
types_sarif_assessment_broadcast_dict = types_sarif_assessment_broadcast_instance.to_dict()
# create an instance of TypesSarifAssessmentBroadcast from a dict
types_sarif_assessment_broadcast_from_dict = TypesSarifAssessmentBroadcast.from_dict(types_sarif_assessment_broadcast_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


