# JA4 Fingerprint Security Analyzer

A Cloudflare Workers application that analyzes JA4 fingerprints to provide security assessments and threat intelligence.

## Overview

This application leverages Cloudflare's GraphQL API and Workers AI to analyze JA4 fingerprints and generate comprehensive security assessments. It provides insights into traffic patterns, potential security risks, and actionable recommendations based on advanced metrics and behavioral analysis.

## Features

- **JA4 Fingerprint Analysis**: Detailed analysis of JA4 fingerprints with traffic metrics and security signals
- **AI-Powered Security Assessment**: Uses Cloudflare Workers AI with Llama 3.3 70B model to generate security insights
- **WAF Rule Analysis**: Identifies triggered WAF rules and their implications
- **Traffic Pattern Visualization**: Analyzes traffic patterns, source IPs, and user agents
- **Actionable Recommendations**: Provides specific security recommendations based on the analysis

## Technical Details

### Key Components

- **Cloudflare Workers**: Serverless execution environment
- **Workers AI**: Llama 3.3 70B model for security analysis
- **GraphQL API**: Fetches comprehensive JA4 data from Cloudflare's analytics
- **Static Assets**: Clean, responsive UI for displaying analysis results

### JA4 Metrics Analyzed

The application analyzes several key JA4 metrics:

- **HTTP Protocol Ratios**: Ratio of HTTP/2 and HTTP/3 requests to total requests
- **Heuristic Detection**: Ratio of requests flagged by heuristic-based scoring
- **Request Volume**: Quantile position and rank based on request count
- **User Agent Diversity**: Rank based on variety of user agents
- **Browser Traffic**: Ratio of browser-based requests
- **Path Diversity**: Rank based on unique request paths
- **Caching Behavior**: Ratio of cacheable responses
- **IP Diversity**: Rank and quantile position based on unique client IPs

## Deployment

This application is deployed as a Cloudflare Worker. To deploy:

```bash
npx wrangler deploy
```

## Configuration

The application requires the following environment variables in `wrangler.jsonc`:

- `API_TOKEN`: Cloudflare API token with Analytics access
- `ACCOUNT_ID`: Cloudflare account ID

## Usage

Send a POST request to `/api/analyze` with a JSON body containing the JA4 fingerprint:

```json
{
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
}
```

The response includes a comprehensive security assessment with risk level, key findings, and recommendations.

## License

Copyright © 2025
