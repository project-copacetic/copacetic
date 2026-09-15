FROM mcr.microsoft.com/dotnet/sdk:8.0 AS app

WORKDIR /app

COPY TestApp.csproj .
RUN dotnet restore

COPY . .
RUN dotnet build -c Release

CMD ["dotnet", "bin/Release/net8.0/TestApp.dll"]
