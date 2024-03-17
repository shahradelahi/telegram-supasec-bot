<div style="text-align: center; margin-bottom: 20px;">
  <img src="https://github.com/shahradelahi/telegram-supasec-bot/blob/master/animated-logo.gif" alt="Supasec Bot" width="180" />
</div>

# Supasec Bot

> Checkout the [Supasec Bot](https://t.me/supasecbot) on the Telegram.

This is a virus scanner bot for the Telegram. It uses the [VirusTotal API](https://www.virustotal.com/en/documentation/public-api/) to scan files for viruses.

## ⚙️ Build

This project uses Docker to build and start the app. Follow the instructions below to build the app and start it locally.

### Pre-requisites

- [Docker](https://docs.docker.com/engine/install/)
- [Make](https://www.gnu.org/software/make/)

### Build

```bash
$ make build
```

## 🚀 Start

### Database

The bot uses the `Postgres` database to store the user's data. You use the following command to get an instance on the Docker.

```bash
docker run -d \
  --name supasec-db 
  -e POSTGRES_PASSWORD=super-secret-password \
  -e POSTGRES_DB=supasec \
  -p 5432:5432 \
  postgres:alpine
```

### Bot

```bash
docker run -d \
  --name supasec-bot \
  -e TG_TOKEN=your-telegram-bot-token \
  -e VT_API_KEY=your-virustotal-api-key \
  -e DATABASE_URL="postgres://postgres:super-secret-password@localhost:5432/supasec?schema=private" \
  shahradel/supasec:dev
```

### Environment Variables

Checkout [the `.env.example`](.env.example) file to see the environment variables that you need to set.

## License

[GPL-3.0](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi)
