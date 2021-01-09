FROM node:lts-alpine as frontend_builder
WORKDIR /build
COPY ./frontend .
RUN npm install
RUN npm run build
WORKDIR /app


FROM golang:alpine

ENV GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

COPY . .

RUN go build -o main .

WORKDIR /app

RUN ls /app
RUN cp /build/main .
RUN mkdir ./frontend
COPY --from=frontend_builder /build/dist ./frontend
RUN ls /app
RUN ls /app/frontend

EXPOSE 443 80 3001

CMD ["/app/main"]

