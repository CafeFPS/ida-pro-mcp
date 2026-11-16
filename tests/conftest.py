import os

# The fork hides outputSchema by default; the spec tests exercise it.
os.environ.setdefault("IDA_MCP_OUTPUT_SCHEMA", "1")
