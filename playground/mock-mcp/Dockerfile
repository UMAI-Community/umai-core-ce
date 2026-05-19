# Mock MCP server — a deliberately-vulnerable HTTP endpoint that pretends
# to be an unauthenticated Model Context Protocol daemon. Returns canned
# "tool execution" output so the demo script has something to leak in
# Stage 1 (defenseless) before UMAI Core's kernel agent silences it in
# Stage 3 (the drop).

FROM python:3.12-alpine

WORKDIR /srv
COPY server.py /srv/server.py

EXPOSE 8080
CMD ["python", "-u", "/srv/server.py"]
