# Docker Setup for Dinkybell E-commerce

This guide explains how to set up and use Docker containers for the Dinkybell E-commerce backend development environment.

## Components

This Docker setup provides:

1. **PostgreSQL** - The primary relational database for persistent storage
2. **Redis** - In-memory database for rate limiting, caching, and session management

## Prerequisites

- Docker and Docker Compose installed on your machine
- The project's `.env` file properly configured with required parameters

## Getting Started

### 1. Environment Configuration

The `.env` file contains the configuration for both the application and Docker services. Make sure it's properly set up:

```properties
# Database
DB_HOST...

# Redis
REDIS_HOST...

# Email settings...
```

### 2. Starting the Services

To start all services (PostgreSQL and Redis):

```bash
docker-compose up -d
```

To start specific services only:

```bash
# For PostgreSQL only
docker-compose up -d postgres

# For Redis only
docker-compose up -d redis
```

### 3. Accessing Management Interfaces

The management interfaces PgAdmin and Redis Commander are no longer available in this Docker configuration. To manage PostgreSQL and Redis, use local tools such as psql, DBeaver, TablePlus, Redis CLI or other clients of your choice, connecting to the services exposed on ports:

- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

### 4. Using with the Spring Boot Application

When running the application locally, the containers are accessible through:

- PostgreSQL: localhost:5432
- Redis: localhost:6379

No configuration changes are needed in the application as it already uses these defaults.

### 5. Data Persistence

All data is persisted in Docker volumes:

- `postgres_data`: PostgreSQL database files
- `redis_data`: Redis data (with append-only file enabled)

This means your data will survive container restarts.

## Troubleshooting

### 1. Port Conflicts

If you already have PostgreSQL or Redis running on your host machine, you'll have port conflicts. You can either:

- Stop the local services
- Change the port mappings in `docker-compose.yml`

### 2. Connection Issues

If the application can't connect to the services, ensure:

- The containers are running (`docker-compose ps`)
- The application is using the correct connection details
- No firewall is blocking the connections

### 3. Viewing Logs

```bash
# All logs
docker-compose logs

# Service-specific logs
docker-compose logs postgres
docker-compose logs redis

# Follow logs in real-time
docker-compose logs -f
```

## Useful Commands

```bash
# Stop all services
docker-compose down

# Restart a specific service
docker-compose restart redis

# View container status
docker-compose ps

# Remove volumes (CAUTION: Deletes all data)
docker-compose down -v
```
