FROM ubuntu:22.04

# Nodejs deps
RUN apt-get update && apt-get upgrade
RUN apt-get install -y curl git
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
RUN apt-get install -y nodejs

# Install rust
WORKDIR "/"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Build/rapidsnark deps
RUN apt-get install -y build-essential libgmp-dev libsodium-dev nasm nlohmann-json3-dev

# Install circom
WORKDIR "/"
RUN git clone https://github.com/iden3/circom.git
WORKDIR "/circom"
RUN /root/.cargo/bin/cargo build --release
RUN /root/.cargo/bin/cargo install --path circom

# Install snarkjs
RUN npm install -g snarkjs

# Install rapidsnark
WORKDIR "/"
RUN git clone https://github.com/iden3/rapidsnark.git
WORKDIR "/rapidsnark"
RUN npm install
RUN git submodule init
RUN git submodule update
RUN npx task createFieldSources
RUN npx task buildProver

RUN mkdir /workspace
WORKDIR "/workspace"
