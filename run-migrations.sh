#!/bin/sh

echo "Running migrations..."
migrate -path ./migrations -database "$DATABASE_URL" -verbose up 

echo "Migrations completed."