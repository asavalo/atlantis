(
  SHOW_LOGS=1 \
  MAX_TOTAL_BYTES=120000 \
  CHUNK_BYTES=7000 \
  BATCH_FILES=10 \
  LLM_MAX_TOKENS=700 \
  TIMEOUT=900 \
  ~/crs_repo_cwe_strict.sh \
    ~/accumulo \
    "access control, authentication, authorization, secrets handling" \
    ~/accumulo_full_repo.json
)
