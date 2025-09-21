# JA4 Fingerprint Security Analyzer

A Cloudflare Worker that analyzes JA4 fingerprints using GraphQL API and Workers AI to provide security assessments and threat intelligence.

![JA4 Fingerprint Security Analyzer](https://r2.zxc.co.in/git_readme/ja4.png)

## Features

- **AI-Powered Analysis**: Uses Llama 3.3 70B model to generate security insights
- **Traffic Analysis**: Visualizes traffic patterns, bot scores, and status codes
- **Security Metrics**: Analyzes WAF triggers, IP distribution, and JA4 signals
- **Risk Assessment**: Provides risk level and actionable recommendations

## Technology

- **Cloudflare Workers**: Serverless execution environment
- **Workers AI**: AI inference with Llama 3.3 70B
- **GraphQL API**: Data retrieval from Cloudflare Analytics
- **Responsive UI**: Clean interface for analysis results

## Quick Start

### Required Variables

- **CLOUDFLARE_ACCOUNT_ID**: Your Cloudflare account ID (found in the Cloudflare dashboard URL)
- **CLOUDFLARE_API_KEY**: Your Cloudflare API key with Analytics permissions
[text](https://developers.cloudflare.com/secrets-store/)  

### Deployment

```bash
npx wrangler deploy
```

### Usage

Access the web interface or send a POST request to `/api/analyze`:

```json
{
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
}
```

## License

Copyright © 2025 Cloudflare
