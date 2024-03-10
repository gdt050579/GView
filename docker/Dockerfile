# This not yet functional!
FROM ubuntu:latest

RUN apt-get update -y && apt-get install wget jq unzip libx11-dev libxext6 -y && mkdir /GView

WORKDIR /GView

RUN wget -O releases.json https://api.github.com/repos/gdt050579/GView/releases && \
    jq -r '.[0].assets | . [] | select(.name|test(".*Linux.*")) .browser_download_url' releases.json > link.txt && \
    wget -i link.txt && \
    unzip GView-Linux* && \
    rm -f GView-Linux-* \ && \
    ./GView reset && \
    sed -i 's/Frontend = default/Frontend = SDL/' GView.ini

CMD ["./GView"]