function errorResponse(error, message, status = 400) {
	return new Response(JSON.stringify({ error, message }), { 
		status, 
		headers: { 
			'Content-Type': 'application/json',
			'Access-Control-Allow-Origin': '*'
		} 
	});
}

/**
 * Execute a GraphQL query against Cloudflare's API
 */
async function executeGraphQLQuery(query, variables, apiToken) {
	const response = await fetch('https://api.cloudflare.com/client/v4/graphql', {
		method: 'POST',
		headers: {
			'Authorization': `Bearer ${apiToken}`,
			'Content-Type': 'application/json',
		},
		body: JSON.stringify({ query, variables }),
	});

	if (!response.ok) {
		throw new Error(`GraphQL request failed: ${response.status} ${response.statusText}`);
	}

	return await response.json();
}

/**
 * Get current date and date ranges for queries
 */
function getDateRanges() {
	const now = new Date();
	const today = now.toISOString().split('T')[0]; // YYYY-MM-DD format for GraphQL date filters
	const tenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000); // For real-time data queries
	const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // Weekly analysis window
	const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // Monthly trend analysis
	
	return {
		today,
		tenMinutesAgo: tenMinutesAgo.toISOString(),
		sevenDaysAgo: sevenDaysAgo.toISOString().split('T')[0], // Date only for daily aggregation
		thirtyDaysAgo: thirtyDaysAgo.toISOString().split('T')[0], // Date only for daily aggregation
	};
}


/**
 * GraphQL Queries for JA4 Analysis
 */
const QUERIES = {
	// WAF Attack Score Analysis - Shows WAF attack scores over time
	wafAttackScores: `
		query WafAttackScores($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 288
						orderBy: [datetimeHour_ASC]
					) {
						count
						dimensions {
							wafAttackScore
							wafAttackScoreClass
							wafRceAttackScore
							wafSqliAttackScore
							wafXssAttackScore
							datetimeHour
						}
					}
				}
			}
		}
	`,

	// IP Address Analysis - Shows top source IPs for this JA4 fingerprint
	ipAnalysis: `
		query IPAnalysis($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 20
						orderBy: [count_DESC]
					) {
						count
						dimensions {
							clientIP
							clientCountryName
						}
					}
				}
			}
		}
	`,
	
	// Hostname Analysis - Shows which domains this JA4 fingerprint accesses (last 30 days)
	hostnameAnalysis: `
		query HostnameAnalysis($accountTag: String!, $ja4: String!, $dateGte: Date!, $dateLte: Date!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date_geq: $dateGte, date_leq: $dateLte, ja4: $ja4 }
						limit: 20
						orderBy: [count_DESC]
					) {
						count
						dimensions {
							clientRequestHTTPHost
						}
					}
				}
			}
		}
	`,
	
	
	// User Agent Analysis - Shows which user agents this JA4 fingerprint uses
	userAgentAnalysis: `
		query UserAgentAnalysis($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 10
						orderBy: [count_DESC]
					) {
						count
						dimensions {
							userAgent
						}
					}
				}
			}
		}
	`,
	
	// Path Analysis - Shows which URL paths this JA4 fingerprint accesses
	pathAnalysis: `
		query PathAnalysis($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 20
						orderBy: [count_DESC]
					) {
						count
						dimensions {
							clientRequestPath
							clientRequestQuery
							
						}
					}
				}
			}
		}
	`,
	
	// ASN Analysis - Shows which Autonomous System Numbers this JA4 fingerprint originates from
	asnAnalysis: `
		query ASNAnalysis($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 20
						orderBy: [count_DESC]
					) {
						count
						dimensions {
							clientAsn
							clientASNDescription
						}
					}
				}
			}
		}
	`,
	
	// Status Code Analysis - Shows hourly breakdown of HTTP response codes for this JA4
	statusCodeAnalysis: `
		query StatusCodeAnalysis($accountTag: String!, $ja4: String!, $date: Date!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 100
					) {
						count
						dimensions {
							datetimeHour
							edgeResponseStatus
						}
					}
				}
			}
		}
	`,

	// JA4 Signals Intelligence - Advanced behavioral signals for this fingerprint
	ja4Signals: `
		query JA4Signals($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptive(
						filter: { date: $date, ja4: $ja4 }
						limit: 1
					) {
						ja4Signals {
							signalName
							signalValue
						}
						ja4
					}
				}
			}
		}
	`,
	
	// Daily Activity Analysis - Shows JA4 fingerprint activity over last 30 days
	dailyActivity: `
		query DailyActivity($accountTag: String!, $ja4: String!, $dateGte: Date!, $dateLte: Date!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date_geq: $dateGte, date_leq: $dateLte, ja4: $ja4 }
						limit: 31
						orderBy: [date_DESC]
					) {
						count
						dimensions {
							date
						}
					}
				}
			}
		}
	`,

	// WAF Rules Triggered - Detailed WAF rules triggered by this JA4 fingerprint
	wafRulesTriggered: `
		query WafRulesTriggered($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					firewallEventsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 100
					) {
						count
						dimensions {
							attackSignatureRefs
							attackSignatureCategories
							action
							clientIPClass
							ruleId
							rulesetId
							source
						}
					}
				}
			}
		}
	`
};

/**
 * Generate AI security analysis for JA4 fingerprint data
 */
async function generateAISecurityAnalysis(analysisData, env) {
	try {
		// Extract key data points for AI analysis
		const ja4 = analysisData.analysis.targetJA4;
		const totalRequests = analysisData.analysis.totalRequests || 0;
		const uniqueIPs = analysisData.analysis.uniqueIPs || 0;
		const avgBotScore = analysisData.analysis.avgBotScore || 0;
		const signals = analysisData.analysis.ja4Signals || {};
		
		// Extract WAF data
		const wafRules = analysisData.analysis.trafficBreakdown?.topWafRules || [];
		const wafScores = analysisData.analysis.trafficBreakdown?.wafAttackScores || [];
		
		// Extract traffic patterns
		const topIPs = analysisData.analysis.trafficBreakdown?.topIPs || [];
		const topPaths = analysisData.analysis.trafficBreakdown?.topPaths || [];
		const topHostnames = analysisData.analysis.trafficBreakdown?.topHostnames || [];
		const topUserAgents = analysisData.analysis.trafficBreakdown?.topUserAgents || [];
		const dailyActivity = analysisData.analysis.trafficBreakdown?.dailyActivity || [];
		
		// Prepare context for AI analysis
		const context = {
			ja4,
			totalRequests,
			uniqueIPs,
			avgBotScore,
			signals,
			wafRules: wafRules.slice(0, 5), // Limit to top 5 for context
			topIPs: topIPs.slice(0, 5),
			topPaths: topPaths.slice(0, 5),
			topHostnames: topHostnames.slice(0, 5),
			topUserAgents: topUserAgents.slice(0, 3),
			dailyActivitySummary: dailyActivity.length > 0 ? 
				`${dailyActivity.length} days of activity with ${dailyActivity.reduce((sum, day) => sum + day.count, 0)} total requests` : 
				'No daily activity data available'
		};
		
		// Generate security insights using Cloudflare Workers AI
		const prompt = `
			You are a cybersecurity expert specializing in traffic analysis and threat detection.
			Analyze the following JA4 fingerprint data and provide a concise security assessment.
			Focus on identifying potential security risks, anomalies, or suspicious patterns.
			
			JA4 Fingerprint: ${ja4}
			Total Requests: ${totalRequests}
			Unique IPs: ${uniqueIPs}
			Average Bot Score: ${avgBotScore}
			
			Signals: ${JSON.stringify(signals)}
			
			WAF Rules Triggered: ${JSON.stringify(wafRules)}
			
			Top IPs: ${JSON.stringify(topIPs)}
			Top Paths: ${JSON.stringify(topPaths)}
			Top Hostnames: ${JSON.stringify(topHostnames)}
			Top User Agents: ${JSON.stringify(topUserAgents)}
			
			Provide a security assessment with these sections:
			1. Overall Risk Assessment (Low/Medium/High/Critical)
			2. Key Security Findings (3-5 bullet points)
			3. Recommendations (2-3 actionable steps)
			
			Keep your analysis concise, professional, and focused on security implications.
		`;
		
		const aiResponse = await env.AI.run('@cf/openai/gpt-oss-120b', {
			instructions: 'You are a cybersecurity expert providing concise, actionable security analysis.',
			input: prompt,
		});
		
		return {
			securityAnalysis: aiResponse,
			generatedAt: new Date().toISOString()
		};
	} catch (error) {
		console.error('Error generating AI security analysis:', error);
		return {
			securityAnalysis: 'Unable to generate security analysis at this time.',
			error: error.message,
			generatedAt: new Date().toISOString()
		};
	}
}

/**
 * Fetch all JA4 analysis data from GraphQL API
 */
async function fetchJA4Data(ja4, accountTag, apiToken) {
	const dates = getDateRanges();
	const results = {};
	
	// Execute all queries in parallel
	const queryPromises = [
		{ name: 'statusCodeAnalysis', query: QUERIES.statusCodeAnalysis },
		{ name: 'hostnames', query: QUERIES.hostnameAnalysis },
		{ name: 'userAgents', query: QUERIES.userAgentAnalysis },
		{ name: 'paths', query: QUERIES.pathAnalysis },
		{ name: 'asnData', query: QUERIES.asnAnalysis },
		{ name: 'ipData', query: QUERIES.ipAnalysis },
		{ name: 'wafScores', query: QUERIES.wafAttackScores },
		{ name: 'ja4Signals', query: QUERIES.ja4Signals },
		{ name: 'wafRulesTriggered', query: QUERIES.wafRulesTriggered },
		{ name: 'dailyActivity', query: QUERIES.dailyActivity },
	].map(async ({ name, query }) => {
		try {
			// Use different parameters for queries that need a date range
			const needsRange = name === 'dailyActivity' || name === 'hostnames';
			const queryParams = needsRange
				? { accountTag, ja4, dateGte: dates.thirtyDaysAgo, dateLte: dates.today }
				: { accountTag, ja4, date: dates.today };
			
			const response = await executeGraphQLQuery(
				query,
				queryParams,
				apiToken
			);
			
			if (response.errors && response.errors.length > 0) {
				console.error(`GraphQL errors for ${name}:`, response.errors);
				return { name, data: null, error: response.errors[0].message };
			}
			
			return { name, data: response.data, error: null };
		} catch (error) {
			console.error(`Error executing ${name} query:`, error);
			return { name, data: null, error: error.message };
		}
	});
	
	const queryResults = await Promise.all(queryPromises);
	
	// Process results
	queryResults.forEach(({ name, data, error }) => {
		if (data) {
			results[name] = data;
		} else {
			results[name] = { error };
		}
	});
	
	return results;
}

/**
 * Main handler for JA4 analysis
 */
async function handleAnalysis(request, env, ctx) {
	console.log('handleAnalysis function called');
	try {
		console.log('Starting analysis request');


		if (!env.API_TOKEN) {
			console.log('API token not configured');
			return errorResponse('Configuration Error', 'API_TOKEN is not configured. Please set it in wrangler.jsonc', 500);
		}

		if (!env.ACCOUNT_ID) {
			console.log('Account ID not configured');
			return errorResponse('Configuration Error', 'ACCOUNT_ID is not configured', 500);
		}

		let targetJA4 = null;
		if (request.method === 'POST') {
			console.log('Processing POST request');
			const body = await request.json();
			targetJA4 = body.ja4 || null;
			console.log('Extracted JA4 from request:', targetJA4);
		}

		if (!targetJA4) {
			console.log('No JA4 provided in request');
			return errorResponse('JA4 fingerprint required', 'Please provide a JA4 fingerprint to analyze', 400);
		}

		const now = new Date();
		console.log(`Starting analysis for JA4: ${targetJA4}`);

		// Fetch all JA4 data from GraphQL API
		console.log('Fetching JA4 data from Cloudflare GraphQL API...');
		const analysisData = await fetchJA4Data(
			targetJA4,
			env.ACCOUNT_ID,
			env.API_TOKEN
		);

		console.log('GraphQL data fetched, preparing response...');

		// Structure JA4 signals from GraphQL data
		const ja4SignalsData = {};
		if (analysisData.ja4Signals?.viewer?.accounts?.[0]?.httpRequestsAdaptive?.[0]?.ja4Signals) {
			analysisData.ja4Signals.viewer.accounts[0].httpRequestsAdaptive[0].ja4Signals.forEach(signal => {
				ja4SignalsData[signal.signalName] = signal.signalValue;
			});
		}

		// Calculate statistics from GraphQL data
		const totalRequests = analysisData.statusCodeAnalysis?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
			?.reduce((sum, item) => sum + item.count, 0) || 0;
		
		const uniqueIPs = analysisData.asnData?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups?.length || 0;
		
		// Extract bot score if available from WAF data
		let avgBotScore = 0;
		if (analysisData.wafRulesTriggered?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups) {
			const botScores = [];
			analysisData.wafRulesTriggered.viewer.accounts[0].httpRequestsAdaptiveGroups.forEach(item => {
				if (item.dimensions.botScore !== undefined) {
					botScores.push(item.dimensions.botScore);
				}
			});
			if (botScores.length > 0) {
				avgBotScore = botScores.reduce((a, b) => a + b, 0) / botScores.length;
			}
		}
		
		// Extract WAF rule data from WAF rules triggered analysis
		const wafRuleData = {};
		if (analysisData.wafRulesTriggered?.viewer?.accounts?.[0]?.firewallEventsAdaptiveGroups) {
			analysisData.wafRulesTriggered.viewer.accounts[0].firewallEventsAdaptiveGroups.forEach(item => {
				if (item.dimensions.ruleId) {
					const ruleId = item.dimensions.ruleId;
					if (!wafRuleData[ruleId]) {
						wafRuleData[ruleId] = {
							ruleId,
							count: 0,
							action: item.dimensions.action || 'unknown',
							categories: item.dimensions.attackSignatureCategories || [],
							source: item.dimensions.source || 'unknown'
						};
					}
					wafRuleData[ruleId].count += item.count;
				}
			});
		}

		// Format the response with clean structure
		const response = {
			analysis: {
				targetJA4,
				totalRequests,
				uniqueIPs,
				avgBotScore: avgBotScore.toFixed(2),
				ja4Signals: ja4SignalsData,
				fingerprints: [{
					ja4: targetJA4,
					count: totalRequests,
					uniqueIPs,
					avgBotScore,
					signals: ja4SignalsData
				}],
				trafficBreakdown: {
					statusCodeDistribution: analysisData.statusCodeAnalysis?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.map(d => ({
							datetimeHour: d.dimensions.datetimeHour,
							status: d.dimensions.edgeResponseStatus,
							count: d.count
						})) || [],
					topHostnames: analysisData.hostnames?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.slice(0, 5).map(h => ({
							hostname: h.dimensions.clientRequestHTTPHost,
							count: h.count
						})) || [],
					topUserAgents: analysisData.userAgents?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.slice(0, 5).map(ua => ({
							userAgent: ua.dimensions.userAgent || '[Empty]',
							count: ua.count
						})) || [],
					asnDistribution: analysisData.asnData?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.slice(0, 5).map(asn => ({
							asn: asn.dimensions.clientAsn,
							asnDescription: asn.dimensions.clientASNDescription,
							count: asn.count
						})) || [],
					topPaths: analysisData.paths?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.slice(0, 5).map(path => ({
							path: path.dimensions.clientRequestPath || '/',
							query: path.dimensions.clientRequestQuery || '',
							count: path.count
						})) || [],
					topIPs: analysisData.ipData?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.slice(0, 10).map(ip => ({
							ip: ip.dimensions.clientIP,
							country: ip.dimensions.clientCountryName || 'Unknown',
							count: ip.count
						})) || [],
					topWafRules: Object.values(wafRuleData)
						.sort((a, b) => b.count - a.count)
						.slice(0, 10)
						.map(rule => ({
							ruleId: rule.ruleId,
							action: rule.action,
							categories: rule.categories,
							source: rule.source,
							count: rule.count
						})) || [],
					wafAttackScores: analysisData.wafScores?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.map(item => ({
							hour: item.dimensions.datetimeHour,
							overallScore: item.dimensions.wafAttackScore || 0,
							scoreClass: item.dimensions.wafAttackScoreClass || 'none',
							rceScore: item.dimensions.wafRceAttackScore || 0,
							sqliScore: item.dimensions.wafSqliAttackScore || 0,
							xssScore: item.dimensions.wafXssAttackScore || 0,
							count: item.count
						})) || [],
					dailyActivity: analysisData.dailyActivity?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups
						?.map(day => ({
							date: day.dimensions.date,
							count: day.count
						})) || []
				},
			},
			timestamp: now.toISOString()
		};
		
		// Generate AI security analysis
		console.log('Generating AI security analysis...');
		const aiAnalysis = await generateAISecurityAnalysis(response, env);
		response.aiSecurityAnalysis = aiAnalysis;

		return new Response(JSON.stringify(response, null, 2), {
			headers: { 
				'Content-Type': 'application/json',
				'Access-Control-Allow-Origin': '*'
			}
		});
	} catch (error) {
		console.error('Error in handleAnalysis:', error);
		return errorResponse('Failed to analyze JA4', error instanceof Error ? error.message : 'Unknown error', 500);
	}
}


export default {
	async fetch(request, env, ctx) {
		console.log('Worker fetch called, pathname:', new URL(request.url).pathname);
		const url = new URL(request.url);

		// Handle CORS preflight
		if (request.method === 'OPTIONS') {
			return new Response(null, {
				headers: {
					'Access-Control-Allow-Origin': '*',
					'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
					'Access-Control-Allow-Headers': 'Content-Type',
				},
			});
		}

		if (url.pathname === '/api/analyze') {
			console.log('Routing to handleAnalysis');
			return await handleAnalysis(request, env, ctx);
		}

		// Handle favicon requests
		if (url.pathname === '/favicon.ico') {
			return new Response(null, { status: 404 });
		}

		// Serve static assets if ASSETS binding is available
		if (env.ASSETS) {
			return env.ASSETS.fetch(request);
		}

		// Fallback for missing ASSETS binding
		return new Response('Not found', { status: 404 });
	},
};
