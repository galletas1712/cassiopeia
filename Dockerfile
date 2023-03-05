FROM ubuntu:22.04

RUN mkdir -p /workspace/cassiopeia
ENV HOME /workspace
WORKDIR "/workspace"

# Nodejs deps
RUN apt-get update && apt-get upgrade -y
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
RUN /workspace/.cargo/bin/cargo build --release
RUN /workspace/.cargo/bin/cargo install --path circom

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

# Build witness generator
COPY ./zkp /workspace/cassiopeia/zkp
WORKDIR "/workspace/cassiopeia/zkp/output/cassiopeia_cpp"
RUN make

# Init npm deps
COPY ./package.json /workspace/cassiopeia/package.json
WORKDIR "/workspace/cassiopeia"
RUN npm install

# Build PVSS
COPY ./pvss /workspace/cassiopeia/pvss
RUN mkdir /pvss_target
WORKDIR "/workspace/cassiopeia/pvss"
RUN /workspace/.cargo/bin/cargo build --release --target-dir=/pvss_target

WORKDIR "/workspace/cassiopeia"
COPY . /workspace/cassiopeia
