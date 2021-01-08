FROM node:lts-alpine as frontend_builder
WORKDIR /build
COPY ./frontend .
#RUN ls .
#RUN ls ./frontend
RUN npm install
RUN npm run build
WORKDIR /app
#RUN mkdir ./frontend
#RUN cp -r /build/dist ./frontend/dist


FROM golang:alpine

ENV GO111MODULE=on \
    GOOS=linux \
    GOARCH=amd64

#COPY ./frontend/dist .
#RUN ls .
#RUN ls ./frontend

WORKDIR /build

COPY . .

RUN go build -o main .

WORKDIR /app

RUN ls /app
RUN cp /build/main .
#RUN mkdir ./frontend
#RUN cp -r /build/frontend/dist ./frontend/dist
#RUN ls ./frontend
#RUN ls ./frontend
#RUN ls /build/frontend
#RUN cp -r /build/frontend/dist ./frontend
#RUN ls /dist/frontend
RUN mkdir ./frontend
COPY --from=frontend_builder /build/dist ./frontend
RUN ls /app
RUN ls /app/frontend

EXPOSE 443
EXPOSE 80
EXPOSE 3001

CMD ["/app/main"]

