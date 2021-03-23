FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH mobsfstatic.mobsfstatic.Mobsfstatic

# Install any service dependencies here
RUN apt-get update && apt-get install -y openjdk-8-jre-headless java-common libc6-i386 lib32z1 lib32gcc1 unzip wget && rm -rf /var/lib/apt/lists/*
RUN python3.7 -m pip install requests
RUN python3.7 -m pip install requests_toolbelt

RUN wget -O /tmp/dex2jar.zip https://github.com/pxb1988/dex2jar/releases/download/2.0/dex-tools-2.0.zip
RUN unzip -o /tmp/dex2jar.zip -d /opt/al_support
RUN chmod +x /opt/al_support/dex2jar-2.0/*.sh

RUN rm -rf /tmp/*
# Switch to assemblyline user
USER assemblyline

# Copy mobsf service code
WORKDIR /opt/al_service
COPY . .
