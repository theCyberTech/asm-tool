"""
API paths and GraphQL introspection query for API discovery
"""

# Swagger and OpenAPI paths
SWAGGER_PATHS = [
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/api-docs",
    "/api/docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/swagger",
    "/swaggerapi",
    "/swagger/v1/api-docs",
]

OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yaml",
    "/openapi/v3/api-docs",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/openapi",
    "/openapi/v3",
    "/v3/api-docs",
    "/swagger/v3/api-docs",
]

# GraphQL paths
GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/graphql/v2",
    "/graphql/api",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
    "/api/graphiql",
    "/__graphql",
]

# API documentation paths
API_DOC_PATHS = [
    "/api-docs",
    "/docs/api",
    "/documentation",
    "/api-documentation",
    "/developer/api",
    "/swagger",
    "/swagger-ui",
    "/redoc",
    "/api/docs/swagger",
    "/apidocs",
]

# Common API paths
COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    "/rest",
    "/rest/api",
    "/api/rest",
    "/rest/v1",
    "/rest/v2",
]

# GraphQL introspection query
GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType {
      name
      fields {
        name
      }
    }
    mutationType {
      name
      fields {
        name
      }
    }
  }
}
"""
