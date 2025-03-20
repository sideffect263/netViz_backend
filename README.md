# NetScan360 Server

A powerful Node.js backend service providing comprehensive network scanning, security assessment, and technology detection capabilities.

## Features

- **DNS Analysis**: Domain lookup, DNS record retrieval, and subdomain enumeration
- **Network Tools**: Ping, traceroute, port scanning, and geolocation services
- **Security Assessment**: SSL/TLS certificate validation, WHOIS information, and security headers analysis
- **Technology Detection**: Web technology fingerprinting and server configuration analysis
- **Shodan Integration**: Leverage Shodan API for additional host information

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netscan360-server.git
cd netscan360-server

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys and configuration
```

## Environment Variables

The application requires the following environment variables:

```
PORT=5000
NODE_ENV=development

# API keys
SHODAN_API_KEY=your_shodan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
IPINFO_API_KEY=your_ipinfo_api_key

# Security settings
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX=100

# CORS settings
CORS_ORIGIN=http://localhost:3000
```

## Usage

### Development Mode

```bash
npm run dev
```

### Production Mode

```bash
npm start
```

## API Endpoints

### DNS Analysis

- `GET /api/dns/lookup/:domain` - Domain lookup
- `GET /api/dns/records/:domain/:type` - DNS records for a domain
- `GET /api/dns/subdomains/:domain` - Enumerate subdomains

### Network Tools

- `GET /api/network/ping/:host` - Ping a host
- `GET /api/network/traceroute/:host` - Trace route to a host
- `GET /api/network/scan/:host/:ports` - Port scanning
- `GET /api/network/geolocation/:ip` - IP geolocation data

### Security Assessment

- `GET /api/security/ssl/:domain` - SSL/TLS certificate analysis
- `GET /api/security/whois/:domain` - WHOIS information
- `GET /api/security/headers/:url` - Security headers analysis

### Technology Detection

- `GET /api/tech/detect/:url` - Detect technologies used by a website
- `GET /api/tech/server/:url` - Server information

### Shodan API

- `GET /api/shodan/host/:ip` - Get Shodan host information

## Deployment

This application is configured for deployment on Render. The repository includes a `render.yaml` file with the necessary configuration.

### To Deploy on Render:

1. Push your code to a Git repository (GitHub, GitLab, etc.)
2. Create a new Web Service on Render
3. Connect your Git repository
4. Set the environment variables in Render's dashboard
5. Deploy the service

## Security Considerations

- The application implements rate limiting to prevent abuse
- CORS is configured to restrict access to known origins
- Helmet is used to set secure HTTP headers
- Environment variables are used for sensitive configuration

## License

[MIT](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
