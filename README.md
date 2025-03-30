# 🌐 SHODAN-MCP

<div align="center">
 
  ![License](https://img.shields.io/badge/License-MIT-blue.svg)
  ![Python](https://img.shields.io/badge/Python-3.8+-brightgreen.svg)
  ![Status](https://img.shields.io/badge/Status-Active-success.svg)
  
</div>

## 🔍 Overview

**SHODAN-MCP** is a powerful interface to the Shodan API, designed to simplify interaction with the world's first search engine for Internet-connected devices. It provides a comprehensive set of tools for security researchers, penetration testers, and cybersecurity professionals to explore, analyze, and monitor the global internet landscape.

> *"The more systems you can access, the more power you have."*

## ✨ Key Features

### 🔎 Search & Discovery
- **Advanced Search**: Query the Shodan database using powerful filtering capabilities and multiple parameters
- **Result Analysis**: Detailed breakdowns of search results with geographic distribution and organization insights
- **Count Function**: Get total numbers and statistical breakdowns without consuming API credits

### 📡 Host Intelligence
- **Detailed Host Information**: Comprehensive data about any IP address including all services, banners and configurations
- **Port Scanning**: View all open ports and running services on target systems
- **Banner Grabbing**: Access complete service banners and headers for in-depth analysis

### 🔒 Security Research
- **Vulnerability Discovery**: Find devices affected by specific CVEs or with particular vulnerabilities
- **CVE Information**: Get detailed intelligence on Common Vulnerabilities and Exposures
- **Exploitation Risk Assessment**: Evaluate threats with CVSS scores and EPSS exploitation likelihood metrics

### 🌍 Network Mapping
- **DNS Intelligence**: Retrieve comprehensive DNS information and subdomain discovery
- **Domain Insights**: Analyze domain infrastructure and associated services
- **Reverse DNS**: Map IP addresses to hostnames for network enumeration

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Shodan API key ([Get one here](https://account.shodan.io/))
- pip or uv for dependency management

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/shodan-mcp.git
cd shodan-mcp

# Install dependencies
pip install -r requirements.txt

# Set up your Shodan API key
echo "SHODAN_API_KEY=your_api_key_here" > .env
```

### Integration Options

SHODAN-MCP can be integrated with various AI and development environments:

#### 🤖 Claude Integration

Claude can interact with SHODAN-MCP using the MCP protocol:

1. In Claude Desktop, go to Settings → Developer → Edit Config
2. Edit the `claude_desktop_config.json` file and add the following configuration:

   ```json
   "mcpServers": {
     "shodan": {
       "command": "/path/to/uv",
       "args": [
         "--directory",
         "/path/to/shodan-mcp/shodan-mcp-server",
         "run",
         "shodan_mcp.py"
       ]
     }
   }
   ```

3. Replace `/path/to/uv` with your actual path to the uv executable (e.g., `~/.local/bin/uv` on macOS/Linux)
4. Replace `/path/to/shodan-mcp` with the actual path to your shodan-mcp project directory
5. Save the configuration and restart Claude
6. Now you can ask Claude to use Shodan tools directly in your conversations

#### 🖥️ Cursor IDE Integration

[Cursor](https://cursor.sh/) seamlessly integrates with SHODAN-MCP:

1. Open Cursor preferences (⌘+,)
2. Navigate to "Extensions" > "MCP Tools"
3. Click "Add MCP Tool" and provide:
   - Name: `shodan`
   - Command: `/path/to/uv`
   - Arguments: `--directory,/path/to/shodan-mcp/shodan-mcp-server,run,shodan_mcp.py`
4. Replace paths with your actual uv and shodan-mcp locations
5. Save and restart Cursor
6. Use the command palette (⌘+Shift+P) and type "MCP: Shodan" to access tools

#### 📝 VSCode Integration

For VSCode users, add the following to your settings.json file:

1. Open VS Code settings (⌘+Shift+P, then type "Preferences: Open Settings (JSON)")
2. Add the following configuration:

   ```json
   "mcp": {
     "inputs": [],
     "servers": {
       "shodan": {
         "command": "/path/to/uv",
         "args": [
           "--directory",
           "/path/to/shodan-mcp/shodan-mcp-server",
           "run",
           "shodan_mcp.py"
         ],
         "env": {}
       }
     }
   }
   ```

3. Replace `/path/to/uv` with your actual path to the uv executable (e.g., `~/.local/bin/uv` on macOS/Linux or the full path on Windows)
4. Replace `/path/to/shodan-mcp` with the actual path to your shodan-mcp project directory
5. Save the settings and restart VS Code
6. Access through the built-in AI features or command palette

### Installation with UV

[uv](https://github.com/astral-sh/uv) is recommended for managing Python environments and dependencies due to its speed and reliability:

```bash
# Install uv if you don't have it
curl -sSf https://github.com/astral-sh/uv/releases/download/0.1.21/uv-installer.sh | sh

# Install project dependencies with uv
uv pip install -r requirements.txt

# Run the MCP server with uv
uv --directory /path/to/shodan-mcp/shodan-mcp-server run shodan_mcp.py
```

## 🚀 Available Commands

| Category | Command | Description |
|----------|---------|-------------|
| **Core** | `test` | Test if the MCP server is working correctly |
| **Core** | `check_key` | Verify Shodan API key validity and view account information |
| **Search** | `search` | Search the Shodan database with powerful filtering capabilities |
| **Search** | `count` | Count results for a query without consuming API credits |
| **Search** | `get_filters` | Get all available Shodan search filters |
| **Search** | `get_facets` | Get available facets for statistical analysis |
| **Host** | `host` | Get detailed information about a specific IP address |
| **DNS** | `domain_info` | Get DNS information and subdomains for a domain |
| **DNS** | `dns_lookup` | Resolve hostnames to IP addresses |
| **DNS** | `reverse_dns` | Find hostnames associated with IP addresses |
| **Vulnerabilities** | `cve_info` | Get detailed information about a specific CVE |
| **Vulnerabilities** | `find_cpes` | Find CPE identifiers for a specific product |
| **Vulnerabilities** | `find_cves` | Find vulnerabilities by product or CPE identifier |

## 📊 Example Usage

### Integration with AI Assistants

SHODAN-MCP is designed to be used through AI assistants and IDEs that support the MCP protocol. You can interact with Shodan using natural language:

```
"Find all exposed Jenkins servers in Germany"
"Check if 8.8.8.8 has any known vulnerabilities"
"Show me the distribution of Nginx servers by country"
"List the top 5 countries with vulnerable MongoDB instances"
"Get DNS information for example.com"
```

### Available Commands through MCP

Once configured in your IDE or AI assistant, SHODAN-MCP offers the following commands:

## 💻 System Compatibility

| Platform | Supported | Notes |
|----------|-----------|-------|
| **macOS** | ✅ | Tested on Intel & Apple Silicon (M1/M2/M3) |
| **Linux** | ✅ | Tested on Ubuntu 22.04 |
| **Windows** | ⚠️ | Not fully tested, but should work in theory |
| **Docker** | ⚠️ | Support planned but not yet implemented |
| **Cloud** | ⚠️ | Support planned but not yet tested |

> Note: This project has been primarily developed and tested on macOS and Linux environments. Contributions to expand and test compatibility on other platforms are welcome!

## 🔧 Technical Architecture

SHODAN-MCP is built using:
- **FastMCP**: High-performance async framework for API interactions
- **Shodan API Client**: Official Python client for Shodan
- **HTTPX**: Modern asynchronous HTTP client
- **Python-dotenv**: For secure environment variable management
- **MCP Protocol**: For seamless integration with AI assistants

The system uses an asynchronous architecture to provide high-performance, non-blocking API interactions, enabling efficient processing of multiple requests simultaneously.

## 🔑 API Key Management

SHODAN-MCP uses the Shodan API key stored in a `.env` file in the project root. This approach keeps your API key secure and separate from the code.

1. **Get an API key**: Sign up at [Shodan](https://account.shodan.io/) to obtain your API key
2. **Create .env file**: Create a `.env` file in the project root with the following content:
   ```
   SHODAN_API_KEY=your_api_key_here
   ```

The `.env` file is included in `.gitignore` to prevent your API key from being uploaded to public repositories. The project automatically loads the API key from this file using the python-dotenv library.

> **Security note**: Never share your Shodan API key or include it in files that might be uploaded to public repositories.

## 🛡️ Security & Ethics

This tool is designed for legitimate security research and defensive purposes. Users are responsible for ensuring they comply with:

- Applicable laws and regulations
- Shodan's terms of service
- Ethical standards for security research

Always obtain proper authorization before scanning or analyzing systems you don't own.

## 📚 Usage Notes

- Some commands consume Shodan API credits (see [Shodan pricing](https://account.shodan.io/billing))
- Results provide comprehensive intelligence for analysis
- Data is presented in a structured, readable format
- Advanced formatting instructions ensure clarity of technical details
- For bulk operations, consider using the async batch methods to optimize performance

## 🔮 Upcoming Features

The following features are planned for future releases:

- **Markdown Report Generation**: Automatically create comprehensive reports in Markdown format for all queries
- **Batch Processing**: Process multiple queries in parallel for improved efficiency
- **Advanced Visualization**: Visual representations of search results and networks
- **Docker Container**: Ready-to-use containerized version for easier deployment
- **Cross-Platform Testing**: Expanded testing and support for Windows and other platforms

## 👥 Contributions Welcome!

This project was created by a security enthusiast, not a professional developer. There are many areas that could benefit from improvement, and contributions of all kinds are welcome!

### Areas Needing Improvement

- **Code Quality**: Refactoring and optimization
- **Error Handling**: More robust error handling and recovery
- **Documentation**: Expanded examples and use cases
- **Testing**: Unit tests and integration tests
- **UI Development**: A simple web interface for non-programmers
- **Cross-Platform Support**: Testing and fixes for Windows and other platforms

If you'd like to contribute, please feel free to submit pull requests or open issues with suggestions. No contribution is too small, and all help is greatly appreciated!

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| API Key errors | Verify your key is valid and correctly configured |
| Rate limiting | Implement exponential backoff or upgrade your Shodan plan |
| Module not found | Ensure all dependencies are installed correctly |
| Integration issues | Check your MCP paths and configurations |
| Timeout errors | Increase timeout settings for large queries |

## 🌟 Credits

- Powered by me 😇 using [Shodan API](https://www.shodan.io/) - The Internet's Search Engine
- Developed using Python's async architecture for optimal performance
- MCP protocol specification by [Anthropic](https://www.anthropic.com/)

---

<div align="center">
  <p><strong>SHODAN-MCP: See everything. Know everything.</strong></p>
  <small>0xh3l1x creation</small>
</div>