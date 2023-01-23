
FROM gcc AS builder

COPY bitcoin /src/bitcoin
COPY compiler.h compiler.cpp main.cpp Makefile /src/

WORKDIR  /src
RUN make static

FROM scratch

COPY --from=builder /src/miniscript /miniscript 

CMD ["/miniscript"]
ENTRYPOINT ["/miniscript"]
