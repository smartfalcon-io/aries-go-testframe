#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-bullseye as golang
RUN apt update && apt install -y build-essential
COPY ./images/agent-rest/libindy_vdr.so /usr/local/lib
COPY ./images/agent-rest/libindy_vdr.h /usr/local/include
ENV LD_LIBRARY_PATH=$GOPATH/src/github.com/hyperledger/aries-framework-go/images/agent-rest/libindy_vdr.so
ENV APR_ONLY_LIBS = -lapr-1 -lpthread
# SET(CMAKE_THREAD_LIBS_INIT "-lpthread")
#       SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
#       set(CMAKE_HAVE_THREADS_LIBRARY 1)
#       set(CMAKE_USE_WIN32_THREADS_INIT 0)
#       set(CMAKE_USE_PTHREADS_INIT 1)
#       set(THREADS_PREFER_PTHREAD_FLAG ON)
ADD . $GOPATH/src/github.com/hyperledger/aries-framework-go
WORKDIR $GOPATH/src/github.com/hyperledger/aries-framework-go
ENV EXECUTABLES go git

FROM golang as aries-framework
LABEL org.opencontainers.image.source https://github.com/hyperledger/aries-framework-go

ARG GO_TAGS
ARG GOPROXY
# COPY ./images/agent-rest/libindy_vdr.so /usr/local/lib
# COPY ./images/agent-rest/libindy_vdr.h /usr/local/include
# ENV LD_LIBRARY_PATH=$GOPATH/src/github.com/hyperledger/aries-framework-go/images/agent-rest/libindy_vdr.so
RUN GO_TAGS=${GO_TAGS} GOPROXY=${GOPROXY} make agent-rest


FROM ubuntu:jammy as base
# RUN apt add -U --no-cache ca-certificates 
#     #   gcc \
#     #   libc-dev \
#     #   libgcc \
#     #   libc6-compat ;
RUN apt-get update && apt-get install -y \
   ca-certificates
COPY --from=aries-framework /go/src/github.com/hyperledger/aries-framework-go/build/bin/aries-agent-rest /usr/local/bin
COPY ./images/agent-rest/libindy_vdr.so /usr/local/lib
COPY ./images/agent-rest/libindy_vdr.h /usr/local/include
ENV LD_LIBRARY_PATH=$GOPATH/src/github.com/hyperledger/aries-framework-go/images/agent-rest/libindy_vdr.so
ENTRYPOINT ["aries-agent-rest"]