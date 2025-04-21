FROM ubuntu:noble AS base

# Install wine
RUN sudo dpkg --add-architecture i386 && \
    sudo mkdir -pm755 /etc/apt/keyrings && \
    wget -O - https://dl.winehq.org/wine-builds/winehq.key | sudo gpg --dearmor -o /etc/apt/keyrings/winehq-archive.key - && \
    sudo wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources && \
    sudo apt update && sudo apt install --install-recommends winehq-stable && sudo apt clean && sudo rm -rf /var/lib/apt/lists/*

# Install MSITools
RUN sudo apt install msitools


FROM base AS build
COPY create_devenv.py /tmp/create_devenv.py
COPY winhelpers.py /tmp/winhelpers.py
RUN python3 /tmp/create_devenv.py /tmp/dls /th06_prefix

FROM base AS final
COPY --from=build /th06_prefix /th06_prefix
ENV TH06_DEVENV_PREFIX=/th06_prefix
