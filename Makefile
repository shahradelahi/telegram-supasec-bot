###################################################
### Variables
###################################################

DOCKER_IMAGE=shahradel/supasec
DOCKER_TAG=dev

DOCKER_BUILD=docker buildx build

###################################################
### Targets
###################################################

.PHONY: build
build:
	$(DOCKER_BUILD) -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

.PHONY: dev
dev:
	docker compose -f docker-compose.dev.yml up

.PHONY: start
start:
	docker compose -f docker-compose.yml up -d

.PHONY: stop
stop:
	docker compose rm -fsv

########### Database ###########

.PHONY: db
db:
	docker rm -f supasec-db || true
	docker run -d --name supasec-db -p 5432:5432 -e POSTGRES_PASSWORD=super-secret-password -e POSTGRES_DB=supasec postgres:alpine
	sleep 5
	npx prisma db push

###########