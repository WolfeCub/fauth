FROM rust AS api
COPY ./api /app
WORKDIR /app
RUN cargo build --release

FROM node AS ui
RUN npm -g i pnpm
COPY ./ui /app
WORKDIR /app
RUN pnpm i
RUN pnpm build

FROM rust AS run
COPY --from=api /app/target/release/ /app/api/
COPY --from=ui /app/dist /app/ui/dist
WORKDIR /app/api

CMD /app/api/fauth-api
