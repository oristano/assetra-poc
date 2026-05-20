.PHONY: up down build migrate ingest inspect reset logs test clean

# Start all services in the background
up:
	cp -n .env.example .env 2>/dev/null || true
	docker compose up -d --build

# Stop all services
down:
	docker compose down

# Build the app image only
build:
	docker compose build app

# Apply database migrations
migrate:
	docker compose exec app ./assetra-poc migrate

# Run the ingest pipeline
ingest:
	docker compose exec app ./assetra-poc ingest

# Print inspect summary
inspect:
	docker compose exec app ./assetra-poc inspect

# Clear all ingested data (keeps schema)
reset:
	docker compose exec app ./assetra-poc reset

# Tail all container logs
logs:
	docker compose logs -f

# Run all unit tests (no containers required)
test:
	go test ./...

# Remove containers, volumes, and built images
clean:
	docker compose down -v --rmi local

# Open a psql shell against the Postgres container
psql:
	docker compose exec postgres psql -U assetra -d assetra

# Run an interactive Steampipe query session
steampipe-shell:
	docker compose exec steampipe steampipe query
