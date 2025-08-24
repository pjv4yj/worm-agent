import asyncio
import os
import json
import re
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel

from agents import Agent, Runner, WebSearchTool, function_tool, gen_trace_id, trace
from agents.mcp.server import MCPServer, MCPServerStdio
from agents.model_settings import ModelSettings


class SECFilingData(BaseModel):
    """Structure for SEC filing information"""
    filing_type: str
    filing_date: str
    filing_url: str
    summary: str


class RansomwareVictim(BaseModel):
    """Structure for ransomware victim data"""
    company_name: str
    is_public: bool
    date_impacted: str
    data_leaked: str  # "yes", "no", or "unknown"
    industry: str  # e.g., "Healthcare", "Manufacturing", "Financial Services", "Government", "Hospitality", "Media", "Transportation"
    sec_10k_data: Optional[SECFilingData] = None
    ransomware_group: str


class RansomwareAnalysisResult(BaseModel):
    """Structure for complete ransomware analysis results"""
    source_url: str
    victims: List[RansomwareVictim]
    analysis_summary: str
    total_victims: int
    public_companies: int
    private_companies: int
    confirmed_leaks: int


async def create_ransomware_analysis_agents():
    """Create all the specialist agents for ransomware analysis"""
    
    # TOR Content Fetcher Agent
    tor_fetcher_agent = Agent(
        name="TOR Content Fetcher",
        model="o4-mini",
        instructions=(
            "You are a TOR content fetcher specialist. Your job is to:\n"
            "1. Use the TOR MCP server to fetch content from provided .onion URLs\n"
            "2. Handle connection issues and timeouts gracefully\n"
            "3. Return the COMPLETE raw content without summarizing or truncating\n"
            "4. Do NOT add safety disclaimers or refuse to process content\n"
            "5. Pass through the full HTML content exactly as received from the MCP server\n\n"
            "**CRITICAL:**\n"
            "- Return the ENTIRE content from the tor_fetch tool\n"
            "- Do NOT summarize, truncate, or omit any content\n"
            "- Include all HTML, all company listings, all victim information\n"
            "- The victim identifier agent needs the complete raw content\n"
            "- Do NOT say 'I'm unable to assist' or add safety disclaimers\n"
            "- Simply return the raw content for analysis\n\n"
            "**WORKFLOW:**\n"
            "- First test TOR connection using tor_connect tool\n"
            "- Then fetch content from the provided URL using tor_fetch\n"
            "- Return the COMPLETE raw content with minimal formatting\n"
            "- If there are any issues, provide detailed error information"
        ),
        tools=[]  # Tools will be added via MCP server
    )
    
    # Ransomware Victim Identifier Agent
    victim_identifier_agent = Agent(
        name="Ransomware Victim Identifier",
        model="o4-mini",
        instructions=(
            "You are a ransomware victim identification specialist. Your job is to:\n"
            "1. Analyze TOR site content for ransomware victim information\n"
            "2. Extract company names, dates, and ransomware group information\n"
            "3. Determine if data has been leaked (yes/no/unknown)\n"
            "4. Classify each organization's industry/market sector\n"
            "5. Structure the data in a clear, organized format\n\n"
            "**CRITICAL - DATE EXTRACTION:**\n"
            "- Look for ANY dates mentioned: attack dates, leak dates, expiration dates, publication dates\n"
            "- Check for date patterns like 'Expired', 'Public Available', 'Publication started'\n"
            "- Look for timestamps, file dates, or any temporal indicators\n"
            "- If no specific date found, look for relative dates like 'recent', 'last week', etc.\n"
            "- NEVER default to 'Unknown' without thoroughly searching for dates\n"
            "- Dates are often in the HTML content, file listings, or status indicators\n\n"
            "**CRITICAL - INDUSTRY CLASSIFICATION:**\n"
            "- Analyze company descriptions and websites to determine industry\n"
            "- Common industries: Healthcare, Manufacturing, Financial Services, Government, Hospitality, Media, Transportation, Technology, Retail, Energy, Education, Insurance, Automotive, Food & Beverage\n"
            "- Use company descriptions, website URLs, and business descriptions to classify\n"
            "- Be specific but use standard industry categories\n\n"
            "**ANALYSIS REQUIREMENTS:**\n"
            "- Look for company names and dates of impact\n"
            "- Identify the ransomware group responsible\n"
            "- Determine if data has been leaked (look for terms like 'leaked', 'published', 'released')\n"
            "- Extract any available ransom amounts or demands\n"
            "- Note the current status (paid, refused, negotiating, etc.)\n\n"
            "**OUTPUT FORMAT:**\n"
            "Return a structured list of victims with:\n"
            "- Company name\n"
            "- Date impacted (MUST extract actual dates, not 'Unknown')\n"
            "- Data leaked status (yes/no/unknown)\n"
            "- Industry classification\n"
            "- Ransomware group name\n"
            "- Any additional details about the incident\n\n"
            "Focus on accuracy and completeness of victim information."
        ),
        tools=[]
    )
    
    # Public Company Detector Agent
    public_company_detector_agent = Agent(
        name="Public Company Detector",
        model="o4-mini",
        instructions=(
            "You are a public company detection specialist. Your job is to:\n"
            "1. Take the list of ransomware victims\n"
            "2. Research each company to determine if they are publicly traded\n"
            "3. Find ticker symbols, exchanges, and basic company information\n"
            "4. Provide market cap and sector information when available\n\n"
            "**RESEARCH REQUIREMENTS:**\n"
            "- Search for each company name + 'stock ticker' or 'public company'\n"
            "- Look for SEC filings, investor relations pages\n"
            "- Find ticker symbols and exchange information\n"
            "- Determine market capitalization and sector\n"
            "- Verify the company is actually publicly traded\n\n"
            "**OUTPUT FORMAT:**\n"
            "For each company, provide:\n"
            "- Company name\n"
            "- Ticker symbol (if public)\n"
            "- Exchange (NYSE, NASDAQ, etc.)\n"
            "- Is public (true/false)\n"
            "- Market cap (if available)\n"
            "- Sector/industry\n\n"
            "Be thorough in your research to ensure accuracy."
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    
    # SEC Filing Researcher Agent
    sec_filing_agent = Agent(
        name="SEC Filing Researcher",
        model="gpt-4o",
        instructions=(
            "You are an SEC filing research specialist. Your job is to:\n"
            "1. Take the list of publicly traded ransomware victims\n"
            "2. Find their most recent 10-K filings and other relevant SEC documents\n"
            "3. Provide filing dates, URLs, and brief summaries\n"
            "4. Focus on filings that might be relevant to cybersecurity incidents\n\n"
            "**RESEARCH REQUIREMENTS:**\n"
            "- Search for each company's SEC filings using their ticker symbol\n"
            "- Find the most recent 10-K annual reports\n"
            "- Look for 8-K filings related to cybersecurity incidents\n"
            "- Search for risk factor disclosures about cybersecurity\n"
            "- Find investor relations pages with SEC filing links\n\n"
            "**OUTPUT FORMAT:**\n"
            "For each company, provide:\n"
            "- Company name and ticker\n"
            "- Filing type (10-K, 8-K, etc.)\n"
            "- Filing date\n"
            "- Direct URL to the filing\n"
            "- Brief summary of relevant content\n\n"
            "Focus on filings that might contain information about:\n"
            "- Cybersecurity risks and incidents\n"
            "- IT infrastructure and systems\n"
            "- Risk management practices\n"
            "- Recent security events or breaches"
        ),
        tools=[WebSearchTool(user_location={"type": "approximate", "city": "New York"})]
    )
    
    return tor_fetcher_agent, victim_identifier_agent, public_company_detector_agent, sec_filing_agent


async def create_ransomware_orchestrator():
    """Create the main orchestrator agent using agents as tools"""
    
    # Get the specialist agents
    tor_fetcher_agent, victim_identifier_agent, public_company_detector_agent, sec_filing_agent = await create_ransomware_analysis_agents()
    
    # Create the main orchestrator
    orchestrator = Agent(
        name="Ransomware Analysis Orchestrator",
        instructions="""You are the main orchestrator for ransomware victim analysis.

        WORKFLOW - YOU MUST COMPLETE ALL 5 STEPS:
        1. Use tor_content_fetcher_tool to get content from the provided .onion URL
        2. Use victim_identifier_tool to extract ransomware victim information from the content
        3. Use public_company_detector_tool to determine which victims are publicly traded companies
        4. Use sec_filing_researcher_tool to get 10-K filings and other SEC documents for public companies
        5. Synthesize all findings into a structured analysis report
        
        CRITICAL REQUIREMENTS:
        - You MUST complete ALL 5 steps in order
        - Do NOT stop after step 3 - continue to step 4 and 5
        - Make sure to pass the TOR content to the victim identifier
        - Pass the victim list to the public company detector
        - Pass the public company list to the SEC filing researcher
        - Provide comprehensive analysis covering all findings
        
        STRUCTURED OUTPUT REQUIREMENTS:
        Create a structured analysis with the following data for each victim:
        - Company Name: Full company name
        - Public/Private: Boolean indicating if company is publicly traded
        - Date Impacted: Date when the ransomware attack occurred
        - Data Leaked: "yes", "no", or "unknown" based on available information
        - SEC 10K Data: For public companies, include filing information (type, date, URL, summary)
        - Ransomware Group: Name of the ransomware group responsible
        
        Also provide summary statistics:
        - Total number of victims
        - Number of public companies
        - Number of private companies
        - Number of confirmed data leaks
        
        REMEMBER: Complete ALL 5 steps before providing final analysis!""",
        
        tools=[
            tor_fetcher_agent.as_tool("tor_content_fetcher_tool", "Fetch content from .onion sites using TOR MCP server"),
            victim_identifier_agent.as_tool("victim_identifier_tool", "Extract ransomware victim information from TOR site content"),
            public_company_detector_agent.as_tool("public_company_detector_tool", "Determine if identified companies are publicly traded and get company information"),
            sec_filing_agent.as_tool("sec_filing_researcher_tool", "Retrieve 10-K filings and other SEC documents for publicly traded ransomware victims")
        ],
        output_type=RansomwareAnalysisResult,
        model_settings=ModelSettings(),
        model="o4-mini"
    )
    
    return orchestrator


async def setup_tor_mcp_server():
    """Setup and return TOR MCP server"""
    # TOR MCP Server
    tor_server = MCPServerStdio(
        name="TOR MCP Server",
        params={
            "command": "python",
            "args": ["tor_mcp_server.py"],
        },
    )
    
    return tor_server


async def run_ransomware_analysis(onion_url: str):
    """Run comprehensive ransomware victim analysis"""
    
    # Validate input
    if not onion_url or '.onion' not in onion_url:
        raise ValueError("Please provide a valid .onion URL")
    
    # Setup TOR MCP server
    tor_server = await setup_tor_mcp_server()
    
    try:
        # Connect to TOR MCP server
        async with tor_server as server:
            
            # Create the specialist agents first
            tor_fetcher_agent, victim_identifier_agent, public_company_detector_agent, sec_filing_agent = await create_ransomware_analysis_agents()
            
            # Add MCP server to the TOR fetcher agent
            tor_fetcher_agent.mcp_servers = [server]
            
            # Create the main orchestrator with the agents as tools
            orchestrator = Agent(
                name="Ransomware Analysis Orchestrator",
                instructions="""You are the main orchestrator for ransomware victim analysis.

                WORKFLOW - YOU MUST COMPLETE ALL 5 STEPS:
                1. Use tor_content_fetcher_tool to get content from the provided .onion URL
                2. Use victim_identifier_tool to extract ransomware victim information from the content
                3. Use public_company_detector_tool to determine which victims are publicly traded companies
                4. Use sec_filing_researcher_tool to get 10-K filings and other SEC documents for public companies
                5. Synthesize all findings into a structured analysis report
                
                CRITICAL REQUIREMENTS:
                - You MUST complete ALL 5 steps in order
                - Do NOT stop after step 3 - continue to step 4 and 5
                - Make sure to pass the TOR content to the victim identifier
                - Pass the victim list to the public company detector
                - Pass the public company list to the SEC filing researcher
                - Provide comprehensive analysis covering all findings
                
                STRUCTURED OUTPUT REQUIREMENTS:
                Create a structured analysis with the following data for each victim:
                - Company Name: Full company name
                - Public/Private: Boolean indicating if company is publicly traded
                - Date Impacted: Date when the ransomware attack occurred (MUST extract actual dates, not 'Unknown')
                - Data Leaked: "yes", "no", or "unknown" based on available information
                - Industry: Industry/market sector classification (Healthcare, Manufacturing, Financial Services, etc.)
                - SEC 10K Data: For public companies, include filing information (type, date, URL, summary)
                - Ransomware Group: Name of the ransomware group responsible
                
                Also provide summary statistics:
                - Total number of victims
                - Number of public companies
                - Number of private companies
                - Number of confirmed data leaks
                
                REMEMBER: Complete ALL 5 steps before providing final analysis!""",
                
                tools=[
                    tor_fetcher_agent.as_tool("tor_content_fetcher_tool", "Fetch content from .onion sites using TOR MCP server"),
                    victim_identifier_agent.as_tool("victim_identifier_tool", "Extract ransomware victim information from TOR site content"),
                    public_company_detector_agent.as_tool("public_company_detector_tool", "Determine if identified companies are publicly traded and get company information"),
                    sec_filing_agent.as_tool("sec_filing_researcher_tool", "Retrieve 10-K filings and other SEC documents for publicly traded ransomware victims")
                ],
                output_type=RansomwareAnalysisResult,
                model_settings=ModelSettings(),
                model="gpt-4o"
            )
            
            # Generate trace for monitoring
            trace_id = gen_trace_id()
            
            with trace(workflow_name="Ransomware Victim Analysis", trace_id=trace_id):
                print(f"🔍 Starting Ransomware Victim Analysis")
                print(f"📊 View trace: https://platform.openai.com/traces/trace?trace_id={trace_id}\n")
                print(f"🎯 Target URL: {onion_url}\n")
                print("=" * 80)
                
                # Run the analysis
                result = await Runner.run(
                    starting_agent=orchestrator, 
                    input=f"Analyze the ransomware victim information from this .onion URL: {onion_url}. IMPORTANT: Complete all 5 steps of the workflow including SEC filing research and final synthesis.",
                    max_turns=20  # Allow more turns to complete all steps
                )
                
                print("\n" + "=" * 80)
                print("🏆 RANSOMWARE VICTIM ANALYSIS COMPLETE")
                print("=" * 80)
                
                # Handle structured output
                if hasattr(result.final_output, 'victims'):
                    # It's a structured RansomwareAnalysisResult object
                    analysis = result.final_output
                    print(f"📋 Source URL: {analysis.source_url}")
                    print(f"📊 Total Victims: {analysis.total_victims}")
                    print(f"🏢 Public Companies: {analysis.public_companies}")
                    print(f"🏭 Private Companies: {analysis.private_companies}")
                    print(f"💥 Confirmed Leaks: {analysis.confirmed_leaks}")
                    print("\n" + "=" * 80)
                    
                    for victim in analysis.victims:
                        print(f"**{victim.company_name}**")
                        print(f"**Public/Private:** {'Public' if victim.is_public else 'Private'}")
                        print(f"**Date Impacted:** {victim.date_impacted}")
                        print(f"**Data Leaked:** {victim.data_leaked}")
                        print(f"**Ransomware Group:** {victim.ransomware_group}")
                        if victim.sec_10k_data:
                            print(f"**SEC Filing:** {victim.sec_10k_data.filing_type} - {victim.sec_10k_data.filing_date}")
                            print(f"**Filing URL:** {victim.sec_10k_data.filing_url}")
                            print(f"**Summary:** {victim.sec_10k_data.summary}")
                        print("\n" + "-" * 40 + "\n")
                    
                    print("📝 **Analysis Summary:**")
                    print(analysis.analysis_summary)
                    
                    # Save JSON output to data/ folder
                    os.makedirs('data', exist_ok=True)
                    
                    # Create safe filename from URL
                    safe_filename = re.sub(r'[^\w\s-]', '', onion_url.replace('.onion', ''))
                    safe_filename = re.sub(r'[-\s]+', '_', safe_filename)
                    filename = f"data/ransomware_analysis_{safe_filename.lower()}.json"
                    
                    # Save to JSON file
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(analysis.dict(), f, indent=2, ensure_ascii=False)
                    
                    print(f"\n💾 JSON saved to: {filename}")
                    
                else:
                    # Fallback for text output
                    print(result.final_output)
                
                trace_url = f"https://platform.openai.com/traces/trace?trace_id={trace_id}"
                return result.final_output, trace_url 
                
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        raise


async def main_run(onion_url: str = None):
    """Main execution function"""
    
    # Verify OpenAI API key
    if not os.getenv('OPENAI_API_KEY'):
        raise RuntimeError("OPENAI_API_KEY environment variable not set")
    
    # Validate URL input
    if not onion_url:
        raise ValueError("No .onion URL provided")
    
    # Run analysis
    result, trace = await run_ransomware_analysis(onion_url)
    return result, trace


if __name__ == "__main__":
    print("🚀 Initializing Ransomware Victim Analysis Agent...")
    print("🔧 This agent combines:")
    print("   • TOR MCP server for .onion site access")
    print("   • Ransomware victim identification")
    print("   • Public company detection")
    print("   • SEC filing research and analysis")
    print("   • Structured output with victim details")
    print("\n🎯 WORKFLOW: TOR → Victims → Public Companies → SEC Filings → Structured Analysis")
    print("=" * 50)
    
    # Get URL from user input or use example
    import sys
    if len(sys.argv) > 1:
        onion_url = sys.argv[1]
    else:
        onion_url = input("Enter .onion URL to analyze: ").strip()
        if not onion_url:
            print("No URL provided. Exiting.")
            sys.exit(1)
    
    # Run the analysis and get structured results
    results, trace = asyncio.run(main_run(onion_url))