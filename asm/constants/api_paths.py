"""
API endpoint paths for discovery module
"""

from typing import List

# Common paths for API documentation and specs
SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/swagger/v3/swagger.json",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api-docs/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
]

OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi/v1.json",
    "/openapi/v2.json",
    "/openapi/v3.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/.well-known/openapi.json",
    "/.well-known/openapi.yaml",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/gql",
    "/playground",
    "/graphiql",
    "/altair",
    "/explorer",
]

API_DOC_PATHS = [
    "/docs",
    "/docs/",
    "/api/docs",
    "/api-docs",
    "/documentation",
    "/api/documentation",
    "/redoc",
    "/api/redoc",
    "/rapidoc",
    "/reference",
    "/api-reference",
    "/developer",
    "/developers",
    "/api/explorer",
]

COMMON_API_PATHS = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/v1",
    "/v2",
    "/v3",
    "/rest",
    "/rest/api",
    "/api/health",
    "/api/status",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/status",
    "/ping",
    "/version",
]
