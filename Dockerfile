FROM node AS ui
RUN npm -g i pnpm
COPY ./ui /app
WORKDIR /app
RUN pnpm i
RUN pnpm build

FROM rust AS api
COPY ./api /app/api
COPY --from=ui /app/dist /app/ui/dist
WORKDIR /app/api
RUN cargo build --release
RUN mv ./target/release/fauth-api .

CMD /app/api/fauth-api
