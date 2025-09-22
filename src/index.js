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
	
	// Create formatted date string in the format "YYYY-MM-DDT00:00:00Z"
	const todayFormatted = `${today}T00:00:00Z`;
	
	// Create rolling 60-minute window (current time to one hour ago)
	// Format as full ISO strings for DateTime type parameters
	const currentTime = now.toISOString(); // Current time in ISO format
	const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000).toISOString(); // One hour ago in ISO format
	
	const tenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000); // For real-time data queries
	const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); // Weekly analysis window
	const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); // Monthly trend analysis
	
	return {
		today,
		todayFormatted, // YYYY-MM-DDT00:00:00Z format
		currentTime,    // Current time in ISO format
		oneHourAgo,     // One hour ago in ISO format
		tenMinutesAgo: tenMinutesAgo.toISOString(),
		sevenDaysAgo: sevenDaysAgo.toISOString().split('T')[0], // Date only for daily aggregation
		thirtyDaysAgo: thirtyDaysAgo.toISOString().split('T')[0], // Date only for daily aggregation
	};
}


/**
 * GraphQL Queries for JA4 Analysis
 */
const QUERIES = {
	// Bot Score Analysis - Shows bot scores by hour
	botScoresByHour: `
		query BotScoresByHour($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						limit: 1000
						orderBy: [datetimeHour_ASC]
					) {
						count
						dimensions {
							botScore
							datetimeHour
						}
					}
				}
			}
		}
	`,

	// WAF Attack Score Analysis - Shows WAF attack scores over time
	wafAttackScores: `
		query WafAttackScores($accountTag: String!, $ja4: String!, $date: String!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptiveGroups(
						filter: { date: $date, ja4: $ja4 }
						orderBy: [datetimeHour_ASC]
						limit: 1000
					) {
						count
						dimensions {
							wafAttackScore
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
						orderBy: [datetimeHour_ASC]
						limit: 1000
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

	// JA4 Signals Intelligence - Advanced behavioral signals for this fingerprint (rolling 60 minutes)
	ja4Signals: `
		query JA4Signals($accountTag: String!, $ja4: String!, $from: DateTime!, $to: DateTime!) {
			viewer {
				accounts(filter: { accountTag: $accountTag }) {
					accountTag
					httpRequestsAdaptive(
						filter: { 
							ja4: $ja4,
							datetime_geq: $from,
							datetime_lt: $to
						}
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
		
		// Generate security insights using Cloudflare Workers AI with Llama 3.3 70B model
		// Format the prompt as a conversation for the Llama model with clear instructions
		const systemPrompt = `You are a cybersecurity expert specializing in traffic analysis and threat detection. 
		You analyze network traffic patterns and provide concise, actionable security assessments.
		Your analysis should be professional, focused on security implications, and formatted clearly.
		
		FORMATTING REQUIREMENTS:
		1. Start with EXACTLY ONE heading "Security Assessment" and nothing else before it
		2. For the risk level, list the risk level as "Low", "Medium", "High", "Very High", or "Extreme"
		3. Format recommendations as a bulletbed list with each item starting with "- " (not "include:" or other prefixes)
		4. Keep your entire response clean, concise and well-structured
		
		When analyzing JA4 fingerprints, consider these metrics and their meanings:
		- h2h3_ratio_1h: Ratio of HTTP/2 and HTTP/3 requests to total requests. Higher values indicate more modern protocols.
		- heuristic_ratio_1h: Ratio of requests flagged by heuristic-based scoring. Higher values may indicate suspicious behavior.
		- reqs_quantile_1h: Quantile position based on request count. Higher values mean more requests compared to other fingerprints.
		- uas_rank_1h: Rank based on user agent diversity. Lower values indicate higher diversity of user agents.
		- browser_ratio_1h: Ratio of browser-based requests. Higher values suggest legitimate browser traffic.
		- paths_rank_1h: Rank based on unique request paths. Lower values indicate higher path diversity.
		- reqs_rank_1h: Rank based on request count. Lower values indicate higher request volumes.
		- cache_ratio_1h: Ratio of cacheable responses. Higher values suggest normal web browsing behavior.
		- ips_rank_1h: Rank based on unique client IPs. Lower values indicate traffic from many different IPs.
		- ips_quantile_1h: Quantile position based on unique client IPs. Higher values mean more unique IPs than most fingerprints.
		
		IMPORTANT SECURITY INDICATORS:
		- Lower attack scores combined with more WAF Rules Triggered strongly indicates malicious bot activity. This pattern shows bots trying to avoid detection while still triggering security rules.
		- Multiple WAF rule triggers across different categories (e.g., SQL injection, XSS, and path traversal) from the same JA4 fingerprint is a strong indicator of automated scanning tools or malicious bots.`;
		
		// Create a clean, structured user prompt with the data
		const userPrompt = `Analyze the following JA4 fingerprint data and provide a security assessment.
		
		## Traffic Data
		- JA4 Fingerprint: ${ja4}
		- Total Requests: ${totalRequests}
		- Unique IPs: ${uniqueIPs}
		- Average Bot Score: ${avgBotScore}
		
		## JA4 Metrics
		- HTTP/2 & HTTP/3 Ratio: ${signals.h2h3_ratio_1h || 'N/A'}
		- Heuristic Detection Ratio: ${signals.heuristic_ratio_1h || 'N/A'}
		- Request Volume Quantile: ${signals.reqs_quantile_1h || 'N/A'}
		- User Agent Diversity Rank: ${signals.uas_rank_1h || 'N/A'}
		- Browser Traffic Ratio: ${signals.browser_ratio_1h || 'N/A'}
		- Path Diversity Rank: ${signals.paths_rank_1h || 'N/A'}
		- Request Volume Rank: ${signals.reqs_rank_1h || 'N/A'}
		- Cache Response Ratio: ${signals.cache_ratio_1h || 'N/A'}
		- IP Diversity Rank: ${signals.ips_rank_1h || 'N/A'}
		- IP Diversity Quantile: ${signals.ips_quantile_1h || 'N/A'}
		
		## Security Signals
		${JSON.stringify(signals, null, 2)}
		${signals.attack_score_1h !== undefined ? `Note: Lower attack scores combined with WAF rule triggers often indicate sophisticated bots trying to evade detection.` : ''}
		
		## WAF Rules Triggered (Important: More rules triggered often indicates malicious activity)
		${JSON.stringify(wafRules, null, 2)}
		${wafRules.length > 0 ? `Note: This fingerprint triggered ${wafRules.length} different WAF rules, which may indicate scanning or attack attempts.` : 'No WAF rules were triggered by this fingerprint.'}
		
		## Traffic Patterns
		- Top IPs: ${JSON.stringify(topIPs)}
		- Top Paths: ${JSON.stringify(topPaths)}
		- Top Hostnames: ${JSON.stringify(topHostnames)}
		- Top User Agents: ${JSON.stringify(topUserAgents)}
		
		Your response MUST follow this EXACT format:
		1. Start with the heading "Security Assessment"
		2. Include risk level assessment (Low/Medium/High/Critical)
		3. Add a brief paragraph explaining the overall assessment
		4. Include a "Key Findings:" section with 3-5 bullet points (each starting with "- ")
		5. Include a "Recommendations:" section with 2-3 bullet points (each starting with "- ")
		
		DO NOT include any other headings, titles, or prefixes like "Threat Intelligence" or "include:".
		Keep your analysis concise, professional, and focused on security implications.`;
		
		// Create messages array for the Llama 3.3 model
		const messages = [
			{ role: "system", content: systemPrompt },
			{ role: "user", content: userPrompt }
		];
		
		// Call the Llama 3.3 70B model with error handling
		let aiResponse;
		try {
			// According to the docs, we need to use the messages format with optimized parameters
			aiResponse = await env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", { 
				messages,
				max_tokens: 1024, // Increase max tokens to avoid truncation
				temperature: 0.3, // Lower temperature for more consistent, focused responses
				top_p: 0.95, // Higher top_p for better quality while maintaining focus
				top_k: 40, // Limit token selection to improve coherence
				repetition_penalty: 1.2 // Discourage repetitive text
			});
			
			console.log('AI response type:', typeof aiResponse);
			console.log('AI response structure:', JSON.stringify(aiResponse).substring(0, 200));
			
		} catch (error) {
			console.error('AI model error:', error);
			// Log detailed error information for debugging
			const errorDetails = {
				message: error.message || 'Unknown error',
				stack: error.stack,
				time: new Date().toISOString(),
				ja4: ja4,
				totalRequests: totalRequests
			};
			console.error('AI processing error details:', JSON.stringify(errorDetails));
			
			// Provide a fallback analysis with error information
			return {
				securityAnalysis: generateFallbackAnalysis(ja4, totalRequests, uniqueIPs, wafRules),
				error: `AI processing error: ${error.message || 'Unknown error'}`,
				errorTime: new Date().toISOString(),
				generatedAt: new Date().toISOString(),
				isAIFallback: true
			};
		}
		
		// Extract the security analysis text from the AI response
		// The Llama 3.3 model returns an object with a 'response' property
		const extractSecurityAnalysis = (response) => {
			// Check for null or undefined response
			if (!response) {
				console.warn('AI response is null or undefined');
				return 'Unable to generate security analysis';
			}
			
			// Handle different response formats
			if (typeof response === 'string') {
				return response; // Already a string, use directly
			}
			
			if (typeof response === 'object') {
				// Check for common response properties in different AI models
				if (response.response) {
					return response.response; // Llama 3.3 format
				}
				
				// Try to find any meaningful string content
				const stringProps = Object.entries(response)
					.filter(([_, value]) => typeof value === 'string' && value.trim().length > 10)
					.map(([_, value]) => value);
				
				if (stringProps.length > 0) {
					// Use the longest string as it's likely the main content
					return stringProps.reduce((a, b) => a.length > b.length ? a : b);
				}
				
				// If we can't find a suitable string property, stringify the object
				try {
					return JSON.stringify(response, null, 2);
				} catch (e) {
					console.error('Error stringifying AI response:', e);
					return 'Error processing AI response';
				}
			}
			
			// Fallback for unexpected response types
			return `Unable to process response of type ${typeof response}`;
		};
		
		// Extract the security analysis text
		const securityAnalysisText = extractSecurityAnalysis(aiResponse);
		
		// Log a sample of the extracted text for debugging
		if (securityAnalysisText) {
			const previewLength = Math.min(100, securityAnalysisText.length);
			console.log(`Extracted analysis (${securityAnalysisText.length} chars): ${securityAnalysisText.substring(0, previewLength)}...`);
		} else {
			console.warn('Extracted security analysis is empty');
		}
		
		return {
			securityAnalysis: securityAnalysisText,
			generatedAt: new Date().toISOString(),
			isAIGenerated: true
		};
	} catch (error) {
		console.error('Error generating AI security analysis:', error);
		
		// Log detailed error information for troubleshooting
		const errorContext = {
			type: 'GeneralAIProcessingError',
			message: error.message || 'Unknown error',
			stack: error.stack,
			time: new Date().toISOString(),
			ja4: ja4,
			totalRequests: totalRequests,
			uniqueIPs: uniqueIPs,
			wafRulesCount: wafRules ? wafRules.length : 0
		};
		console.error('AI analysis failed with context:', JSON.stringify(errorContext));
		
		return {
			securityAnalysis: generateFallbackAnalysis(ja4, totalRequests, uniqueIPs, wafRules),
			error: `Unable to process JA4 fingerprint analysis: ${error.message || 'Unknown error'}`,
			errorDetails: errorContext,
			generatedAt: new Date().toISOString(),
			isAIFallback: true
		};
	}
}

/**
 * Generate a fallback security analysis when AI model fails
 */
function generateFallbackAnalysis(ja4, totalRequests, uniqueIPs, wafRules) {
	// Create a generic error message when AI processing fails
	return `The JA4 fingerprint analysis could not be completed. This may be due to a temporary issue with the AI processing system. Please try again later and Check the Workers logs for more information`;
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
		{ name: 'botScores', query: QUERIES.botScoresByHour },
		{ name: 'ja4Signals', query: QUERIES.ja4Signals },
		{ name: 'wafRulesTriggered', query: QUERIES.wafRulesTriggered },
		{ name: 'dailyActivity', query: QUERIES.dailyActivity },
	].map(async ({ name, query }) => {
		try {
			// Use different parameters for different query types
			let queryParams;
			
			if (name === 'dailyActivity' || name === 'hostnames') {
				// Queries that need a date range
				queryParams = { accountTag, ja4, dateGte: dates.thirtyDaysAgo, dateLte: dates.today };
			} else if (name === 'ja4Signals') {
				// JA4Signals query uses a rolling 60-minute window (current time to one hour ago)
				queryParams = { 
					accountTag, 
					ja4, 
					from: dates.oneHourAgo, 
					to: dates.currentTime 
				};
			} else {
				// Standard queries with a single date
				queryParams = { accountTag, ja4, date: dates.today };
			}
			
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

		// Check if we have any data for this JA4 fingerprint
		const hasJa4Data = !!analysisData.ja4Signals?.viewer?.accounts?.[0]?.httpRequestsAdaptive?.[0];
		
		// If no data found for this JA4 fingerprint, return an error response
		if (!hasJa4Data) {
			console.log('No JA4 fingerprint data found for:', targetJA4);
			return new Response(JSON.stringify({
				error: 'Not Found',
				message: `No data found for JA4 fingerprint: ${targetJA4}. This fingerprint may not exist in your account's traffic or may be too recent.`,
				timestamp: new Date().toISOString()
			}), {
				status: 404,
				headers: { 
					'Content-Type': 'application/json',
					'Access-Control-Allow-Origin': '*'
				}
			});
		}
		
		// Structure JA4 signals from GraphQL data
		const ja4SignalsData = {};
		
		// Extract JA4 signals including metrics
		if (analysisData.ja4Signals?.viewer?.accounts?.[0]?.httpRequestsAdaptive?.[0]?.ja4Signals) {
			analysisData.ja4Signals.viewer.accounts[0].httpRequestsAdaptive[0].ja4Signals.forEach(signal => {
				ja4SignalsData[signal.signalName] = signal.signalValue;
			});
			
			// Log the available signals for debugging
			console.log('Available JA4 signals:', 
				analysisData.ja4Signals.viewer.accounts[0].httpRequestsAdaptive[0].ja4Signals
					.map(s => s.signalName)
					.join(', ')
			);
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
		// Process bot scores by hour and calculate hourly averages
		const hourlyBotScores = [];
		if (analysisData.botScores?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups) {
			// Group scores by hour
			const scoresByHour = {};
			
			// Process each data point
			analysisData.botScores.viewer.accounts[0].httpRequestsAdaptiveGroups.forEach(item => {
				if (item.dimensions.botScore !== undefined && item.dimensions.datetimeHour) {
					const hour = item.dimensions.datetimeHour;
					const hourKey = hour.split('T')[0] + 'T' + hour.split('T')[1].substring(0, 2) + ':00:00Z';
					
					if (!scoresByHour[hourKey]) {
						scoresByHour[hourKey] = {
							scores: [],
							totalCount: 0
						};
					}
					
					// Add weighted scores (each score is weighted by its request count)
					scoresByHour[hourKey].scores.push({
						score: item.dimensions.botScore,
						count: item.count
					});
					scoresByHour[hourKey].totalCount += item.count;
				}
			});
			
			// Calculate weighted average for each hour
			Object.keys(scoresByHour).forEach(hour => {
				const hourData = scoresByHour[hour];
				
				// Calculate weighted average
				let weightedSum = 0;
				hourData.scores.forEach(item => {
					weightedSum += (item.score * item.count);
				});
				
				const avgScore = hourData.totalCount > 0 ? 
					Math.round((weightedSum / hourData.totalCount) * 100) / 100 : 0;
				
				hourlyBotScores.push({
					hour,
					botScore: avgScore,
					count: hourData.totalCount,
					dataPoints: hourData.scores.length // Number of data points averaged
				});
			});
			
			// Sort by hour
			hourlyBotScores.sort((a, b) => new Date(a.hour) - new Date(b.hour));
		}

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
					hourlyBotScores: hourlyBotScores || [],
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
					wafAttackScores: (() => {
						// Get raw data from API
						const rawScores = analysisData.wafScores?.viewer?.accounts?.[0]?.httpRequestsAdaptiveGroups || [];
						
						// Group scores by hour
						const scoresByHour = {};
						
						// Process each data point
						rawScores.forEach(item => {
							const hour = item.dimensions.datetimeHour;
							const hourKey = hour.split('T')[0] + 'T' + hour.split('T')[1].substring(0, 2) + ':00:00Z';
							const count = item.count || 1; // Use request count for weighting, default to 1 if not available
							
							if (!scoresByHour[hourKey]) {
								scoresByHour[hourKey] = {
									overallScores: [],
									rceScores: [],
									sqliScores: [],
									xssScores: [],
									totalCount: 0,
									dataPoints: 0
								};
							}
							
							// Add scores with their weights (request count)
							if (item.dimensions.wafAttackScore !== undefined) {
								scoresByHour[hourKey].overallScores.push({
									score: item.dimensions.wafAttackScore,
									count: count
								});
							}
							if (item.dimensions.wafRceAttackScore !== undefined) {
								scoresByHour[hourKey].rceScores.push({
									score: item.dimensions.wafRceAttackScore,
									count: count
								});
							}
							if (item.dimensions.wafSqliAttackScore !== undefined) {
								scoresByHour[hourKey].sqliScores.push({
									score: item.dimensions.wafSqliAttackScore,
									count: count
								});
							}
							if (item.dimensions.wafXssAttackScore !== undefined) {
								scoresByHour[hourKey].xssScores.push({
									score: item.dimensions.wafXssAttackScore,
									count: count
								});
							}
							
							// Update total count and data points
							scoresByHour[hourKey].totalCount += count;
							scoresByHour[hourKey].dataPoints += 1;
						});
						
						// Calculate weighted averages for each hour
						return Object.keys(scoresByHour).map(hour => {
							const hourData = scoresByHour[hour];
							
							// Helper function to calculate weighted average
							const calculateWeightedAverage = scoreArray => {
								if (!scoreArray || scoreArray.length === 0) return 0;
								
								let weightedSum = 0;
								let totalWeight = 0;
								
								scoreArray.forEach(item => {
									weightedSum += (item.score * item.count);
									totalWeight += item.count;
								});
								
								return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
							};
							
							return {
								hour,
								overallScore: calculateWeightedAverage(hourData.overallScores),
								rceScore: calculateWeightedAverage(hourData.rceScores),
								sqliScore: calculateWeightedAverage(hourData.sqliScores),
								xssScore: calculateWeightedAverage(hourData.xssScores),
								// Add count information
								dataPoints: hourData.dataPoints,
								totalRequests: hourData.totalCount
							};
						});
					})() || [],
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
