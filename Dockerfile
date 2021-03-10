FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH mobsfstatic.Mobsfstatic

# Install any service dependencies here
# For example: RUN apt-get update && apt-get install -y libyaml-dev

RUN pip install requests
RUN pip install requests_toolbelt

# Switch to assemblyline user
USER assemblyline

# Copy mobsf service code
WORKDIR /opt/al_service
COPY . .
