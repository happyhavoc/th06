FROM ubuntu:noble AS base

# Install wine and msitools
RUN dpkg --add-architecture i386 && \
    mkdir -pm755 /etc/apt/keyrings && \
    apt-get update && apt-get install -y wget gpg && \
    wget -O - https://dl.winehq.org/wine-builds/winehq.key | gpg --dearmor -o /etc/apt/keyrings/winehq-archive.key - && \
    wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/noble/winehq-noble.sources && \
    apt-get update && apt-get install -y --install-recommends winehq-stable msitools && \
    apt-get remove --autoremove -y wget gpg && apt-get clean && rm -rf /var/lib/apt/lists/*

FROM base AS build
COPY create_devenv.py /tmp/create_devenv.py
COPY winhelpers.py /tmp/winhelpers.py
COPY th06run.bat /tmp/th06run.bat
COPY th06vars.bat /tmp/th06vars.bat
COPY pragma_var_order.cpp /tmp/pragma_var_order.cpp
RUN python3 /tmp/create_devenv.py /tmp/dls /th06_prefix

FROM base AS final
COPY --from=build /th06_prefix /th06_prefix
ENV TH06_DEVENV_PREFIX=/th06_prefix
