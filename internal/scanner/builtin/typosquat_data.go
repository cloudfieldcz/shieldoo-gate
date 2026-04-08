package builtin

import "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"

// popularPackageSeed contains the top popular packages per ecosystem.
// Used to seed the popular_packages DB table on first run.
// Sources: PyPI download stats, npm download counts, RubyGems stats (2026-Q1).
var popularPackageSeed = map[scanner.Ecosystem][]string{
	scanner.EcosystemPyPI: {
		"requests", "boto3", "urllib3", "setuptools", "typing-extensions",
		"botocore", "certifi", "idna", "charset-normalizer", "python-dateutil",
		"packaging", "s3transfer", "pyyaml", "numpy", "pip",
		"six", "jmespath", "cryptography", "cffi", "wheel",
		"pycparser", "attrs", "platformdirs", "pyasn1", "colorama",
		"filelock", "tomli", "importlib-metadata", "zipp", "jinja2",
		"markupsafe", "click", "pytz", "pygments", "pydantic",
		"fsspec", "pydantic-core", "decorator", "wrapt", "jsonschema",
		"more-itertools", "pluggy", "aiohttp", "protobuf", "grpcio",
		"pandas", "scipy", "pillow", "matplotlib", "tqdm",
		"flask", "django", "sqlalchemy", "celery", "redis",
		"psycopg2", "gunicorn", "httpx", "fastapi", "uvicorn",
		"pyjwt", "paramiko", "docker", "pytest", "coverage",
		"black", "mypy", "ruff", "isort", "flake8",
		"beautifulsoup4", "lxml", "scrapy", "selenium", "playwright",
		"networkx", "scikit-learn", "tensorflow", "torch", "transformers",
		"openai", "anthropic", "langchain", "boto3-stubs", "aws-cdk-lib",
		"azure-core", "azure-storage-blob", "google-cloud-storage", "google-auth",
		"rich", "typer", "httptools", "uvloop", "orjson",
		"pynacl", "bcrypt", "passlib", "itsdangerous", "werkzeug",
		"alembic", "mako", "greenlet", "gevent", "eventlet",
	},
	scanner.EcosystemNPM: {
		"lodash", "chalk", "react", "express", "commander",
		"axios", "debug", "moment", "request", "async",
		"tslib", "fs-extra", "glob", "uuid", "semver",
		"minimist", "yargs", "inquirer", "rxjs", "bluebird",
		"underscore", "jquery", "typescript", "webpack", "eslint",
		"prettier", "babel-core", "next", "vue", "angular",
		"mocha", "jest", "chai", "sinon", "supertest",
		"dotenv", "cors", "body-parser", "cookie-parser", "helmet",
		"mongoose", "sequelize", "prisma", "knex", "pg",
		"redis", "ioredis", "socket.io", "ws", "node-fetch",
		"rimraf", "mkdirp", "cross-env", "concurrently", "nodemon",
		"pm2", "winston", "pino", "morgan", "bunyan",
		"jsonwebtoken", "passport", "bcryptjs", "crypto-js", "jose",
		"zod", "joi", "yup", "ajv", "class-validator",
		"tailwindcss", "postcss", "autoprefixer", "sass", "less",
		"d3", "three", "chart.js", "recharts", "highcharts",
		"puppeteer", "playwright", "cheerio", "jsdom", "happy-dom",
		"aws-sdk", "@aws-sdk/client-s3", "@azure/storage-blob", "@google-cloud/storage",
		"graphql", "apollo-server", "type-graphql", "nexus", "pothos",
		"esbuild", "vite", "rollup", "parcel", "turbopack",
	},
	scanner.EcosystemRubyGems: {
		"rails", "rake", "bundler", "rspec", "nokogiri",
		"rack", "activesupport", "actionpack", "activerecord", "actionview",
		"puma", "sidekiq", "devise", "pg", "redis",
		"minitest", "capybara", "selenium-webdriver", "webdrivers", "faker",
		"rubocop", "simplecov", "aws-sdk", "json", "rest-client",
		"faraday", "httparty", "sinatra", "thin", "unicorn",
	},
	scanner.EcosystemNuGet: {
		"Newtonsoft.Json", "System.Text.Json", "Serilog", "AutoMapper",
		"MediatR", "FluentValidation", "Dapper", "EntityFramework",
		"xunit", "NUnit", "Moq", "Polly", "Swashbuckle",
		"Microsoft.Extensions.DependencyInjection", "Microsoft.AspNetCore.Mvc",
	},
	scanner.EcosystemDocker: {
		"nginx", "alpine", "ubuntu", "node", "python",
		"postgres", "redis", "mysql", "mongo", "golang",
		"openjdk", "httpd", "traefik", "consul", "vault",
	},
}
