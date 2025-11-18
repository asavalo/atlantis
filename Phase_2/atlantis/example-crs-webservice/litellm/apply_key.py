import os

KEYs = ["ANTHROPIC_BUDGET_LIMIT", "SONNET4_TPM", "OPUS4_TPM"]

def apply(fname):
    with open(fname, "rt") as f:
        data = f.read()

    for key in KEYs:
        value = os.getenv(key)
        if value is None:
            print (f"{key} must be in env")
            exit(0)
        key = "os.environ/" + key
        data =data.replace(key, value)

    with open(fname, "wt") as f:
        f.write(data)

apply("./config.yaml")
apply("./model_config.yaml")
