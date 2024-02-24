DOCKER_IMAGE=shahradel/supasec
DOCKER_TAG=dev

DOCKER_DATABASE_IMAGE=postgres:alpine

DATABASE_NAME=supasec
DATABASE_PASSWORD=super-secret-password

DOCKER_BUILD=docker buildx build

.PHONY: build
build:
	$(DOCKER_BUILD) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: db
db:
	docker run --name supasec-db -e POSTGRES_PASSWORD=$(DATABASE_PASSWORD) -d -p 5432:5432 $(DOCKER_DATABASE_IMAGE)
	npx prisma migrate dev --name init --create-db

.PHONY: db-stop
db-stop:
	docker rm -f supasec-db

