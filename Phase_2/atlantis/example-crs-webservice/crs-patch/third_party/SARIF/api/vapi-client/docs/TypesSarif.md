# TypesSarif


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**metadata** | **object** | String to string map containing data that should be attached to outputs like log messages and OpenTelemetry trace attributes for traceability | 
**sarif** | **object** | SARIF Report compliant with provided schema | 
**sarif_id** | **str** |  | 

## Example

```python
from openapi_client.models.types_sarif import TypesSarif

# TODO update the JSON string below
json = "{}"
# create an instance of TypesSarif from a JSON string
types_sarif_instance = TypesSarif.from_json(json)
# print the JSON string representation of the object
print(TypesSarif.to_json())

# convert the object into a dict
types_sarif_dict = types_sarif_instance.to_dict()
# create an instance of TypesSarif from a dict
types_sarif_from_dict = TypesSarif.from_dict(types_sarif_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


