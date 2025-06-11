# Use SDK image for build and runtime
FROM mcr.microsoft.com/dotnet/sdk:5.0

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Restore, build, and publish
RUN dotnet restore
RUN dotnet build -c Release

# Optional: publish to a folder, not strictly needed if you want to run from source
RUN dotnet publish -c Release -o /app/out

# Default to shell for debugging
ENTRYPOINT ["/bin/bash"]
