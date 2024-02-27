ARG NODE_VERSION=20.11.1
ARG ALPINE_VERSION=3.19

FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-alpine${ALPINE_VERSION} as base
WORKDIR /

# Update and upgrade the system
RUN apk update && apk upgrade && \
    rm -rf /var/cache/apk/*


#FROM base as deps
#
## Setup pnpm
#ENV PNPM_HOME="/pnpm"
#ENV PATH="$PNPM_HOME:$PATH"
#RUN corepack enable
#
#WORKDIR /dep/dev
#COPY package.json pnpm-lock.yaml ./
#RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
#
#WORKDIR /dep/prod
#COPY package.json pnpm-lock.yaml ./
#RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile --prod
#

FROM base as build
WORKDIR /build

# Setup pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile

COPY . .
RUN pnpm build

# Prsima
RUN pnpm run db:generate


FROM base
WORKDIR /app

ENV NODE_ENV=production
ENV LOG_LEVEL=info

# Copy the build files
COPY --from=build /build/node_modules node_modules
COPY --from=build /build/dist dist
COPY --from=build /build/package.json package.json

USER node
CMD ["npm", "start"]


