# Docker support
Build static executable and create docker image from `scratch` (2.62MB)

## Build image

### docker build
> docker build . -f contrib/docker/Dockerfile -t miniscript

### makefile
> make docker

## Run miniscript within docker
> echo "thresh(3,c:pk(key_1),sc:pk(key_2),sc:pk(key_3),sdv:older(12960))" | docker run -i --rm miniscript