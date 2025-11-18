# TypesSarifAssessmentSubmission


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**assessment** | [**TypesAssessment**](TypesAssessment.md) |  | 
**description** | **str** | Plain text reasoning for the assessment  128KiB max size | 
**sarif_id** | **str** |  | 
**pov_id** | **str** |  | [optional] 

## Example

```python
from openapi_client.models.types_sarif_assessment_submission import TypesSarifAssessmentSubmission

# TODO update the JSON string below
json = "{}"
# create an instance of TypesSarifAssessmentSubmission from a JSON string
types_sarif_assessment_submission_instance = TypesSarifAssessmentSubmission.from_json(json)
# print the JSON string representation of the object
print(TypesSarifAssessmentSubmission.to_json())

# convert the object into a dict
types_sarif_assessment_submission_dict = types_sarif_assessment_submission_instance.to_dict()
# create an instance of TypesSarifAssessmentSubmission from a dict
types_sarif_assessment_submission_from_dict = TypesSarifAssessmentSubmission.from_dict(types_sarif_assessment_submission_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


