# generate virtual key
curl -X POST "http://litellm:4000/key/generate" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <master-key>" \
     -d '{
          "duration": "string",
          "max_budget": 1000.0,
          "metadata": {},
          "budget_id": "<budget id string to put this key under>"
        }'

# there is also soft_budget for getting notifications

# generate budget id (seems useful for limiting budget per cp)
curl -X POST "http://litellm:4000/budget/new" \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <master-key>" \
     -d '{
          "budget_id": "<budget id string>",
          "max_budget": 10000.0
        }'
