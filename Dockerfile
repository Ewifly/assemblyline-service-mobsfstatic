FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH mobsfstatic.mobsfstatic.Mobsfstatic

USER root

# Install any service dependencies here
RUN apt-get update && apt-get install -y wget 
RUN python3.7 -m pip install requests
RUN python3.7 -m pip install requests_toolbelt
# Switch to assemblyline user
USER assemblyline

# Copy mobsf service code
WORKDIR /opt/al_service
COPY . .
