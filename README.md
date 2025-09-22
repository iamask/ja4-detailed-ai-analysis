# JA4 Fingerprint Security Analyzer

A Cloudflare Worker that analyzes JA4 fingerprints using GraphQL API and Workers AI to provide security assessments and threat intelligence.

![JA4 Fingerprint Security Analyzer](https://r2.zxc.co.in/git_readme/ja4.png)

## Features

- **AI-Powered Analysis**: Uses Llama 3.3 70B model to generate security insights
- **Traffic Analysis**: Visualizes traffic patterns, bot scores, and status codes
- **Security Metrics**: Analyzes WAF triggers, IP distribution, and JA4 signals
- **Risk Assessment**: Provides risk level and actionable recommendations
- **Weighted Averaging**: Calculates hourly averages for bot scores and WAF attack scores using weighted averaging
- **Real-time Data**: Fetches JA4 signals from the last hour for up-to-date analysis

## Technology

- **Cloudflare Workers**: Serverless execution environment
- **Workers AI**: AI inference with Llama 3.3 70B
- **GraphQL API**: Data retrieval from Cloudflare Analytics
- **Advanced Data Processing**: Statistical analysis with weighted averaging
- **Time-Series Analysis**: Hourly breakdown of security metrics

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

### Weighted Averaging

The application uses weighted averaging to calculate more accurate hourly metrics:

#### Bot Score Weighted Averaging

Bot scores are averaged by weighting each score based on its request count. For example:

```
Given for a specific hour:
- Bot Score: 10, Request Count: 50
- Bot Score: 30, Request Count: 100
- Bot Score: 80, Request Count: 25

Weighted Average = (10×50 + 30×100 + 80×25) ÷ (50+100+25) = 31.43
```

This provides a more accurate representation of the typical bot behavior during each hour by giving more influence to scores with higher traffic volume.

#### WAF Attack Scores Averaging

Similarly, WAF attack scores (Overall, RCE, SQL Injection, XSS) are averaged hourly to provide clearer security insights.

### Real-time JA4 Signals

The application fetches JA4 signals from the last 60 minutes using Cloudflare's GraphQL API, providing up-to-date intelligence about the fingerprint's recent behavior.

## License

Copyright © 2025 Cloudflare
