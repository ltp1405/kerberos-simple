# Kerberos Infrastructure

## Overview

This crate provides a set of tools to manage a Kerberos infrastructure, including:

- A Kerberos client for TCP and UDP protocols

- A Kerberos server for TCP and UDP protocols, containing a configurable set of services: storage, and cache

## Usage

### Kerberos Client

Please refer to the [client example](kerberos-infra/tests/main.rs) for a complete example.

### How to configure the database?

Notes: You must have an instance of PostgreSQL running on your local machine. You can use Docker to run a PostgreSQL instance by using the following command:

```bash
docker run --name kerberos -e POSTGRES_PASSWORD=password -p 5455:5432 -d postgres
```

This crate provides the PostgreSQL database implementation in which we can configure by using yaml file. First, create a folder called "database" in your current directory and create a file called "base.yaml" in the "database" folder. The base.yaml should contain only the basic configuration of the database and have the following format:

```yaml
postgres:
  host: "localhost"
  port: 5455
  username: "postgres"
  password: "password"
  name: "kerberos"
  require_ssl: false
```

Next, create a file called "local.yaml" in the "database" folder. The local.yaml should override and add some additional configuration to the base.yaml, use for local development. The local.yaml should have the following format:

```yaml
postgres:
  require_ssl: false
```

Next, create a file called "prod.yaml" in the "database" folder. The prod.yaml should override and add some additional configuration to the base.yaml, use for production. The production.yaml should have the following format:

```yaml
postgres:
  require_ssl: true
```

Finally, you can use the following code to load the configuration and create a database connection. Please refer to the [database example](kerberos-infra/src/server/infra/database/tests/mod.rs) for a complete example.

### How to configure the server (host, and cache)?

First, create a folder called "server" in your current directory and create a file called "base.yaml" in the "server" folder. The base.yaml should contain only the basic configuration of the server and have the following format:

```yaml
host:
 protocol: "tcp" # or "udp"
 as_port: 88
 tgs_port: 89
 host: "localhost"

cache:
 capacity: 100
 ttl: 3600 # in seconds
```

Next, create "local.yaml" and "prod.yaml" in the "server" folder. The local.yaml and prod.yaml should override some configurations in the base.yaml, use for local development and production.

### Kerberos Server

You must complete the setup for database, host, and cache configuration before running the server.
