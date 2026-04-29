"""Minimal example: import strawberry-graphql to verify install through the proxy."""

import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def hello(self) -> str:
        return "Hello, Shieldoo Gate!"


def main():
    schema = strawberry.Schema(query=Query)
    result = schema.execute_sync("{ hello }")
    print(f"GraphQL result: {result.data}")


if __name__ == "__main__":
    main()
