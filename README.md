# Multi-Agent Security Framework

This project is a multi-agent security framework that utilizes multiple LLM models to analyze and generate comprehensive security briefs. It leverages local LLM models via the Ollama API and can optionally use Together API. The framework reads `.txt` files from a specified directory or a specific file provided via command-line arguments and generates a final summary brief.

## Features

- **Threat Intelligence Analysis**: Analyzes threat intelligence data and provides a summary of key threats.
- **Log Analysis**: Analyzes log data for anomalies and suspicious activities.
- **Vulnerability Assessment**: Assesses vulnerabilities and provides a summary of critical vulnerabilities.
- **Incident Response**: Evaluates incidents and recommends appropriate response actions.
- **Overseer Summary**: Generates a final summary brief based on the outputs of the other agents.
- **Output to File**: Saves the final summary brief to a `.txt` file.

## Getting Started

### Prerequisites

- Python 3
- `requests` library (install via `pip install requests`)

### Setup

1. Clone the repository:
    ```sh
    git clone https://github.com/tegridydev/multi-agent-secops-llm.git
    cd multi-agent-secops-llm
    ```

2. Install the required Python packages:
    ```sh
    pip install requests
    ```

3. Set your API key in the script:
    ```python
    API_KEY = "your-api-key"  # Replace 'your-api-key' with your actual API key
    ```

### Running the Script

1. To analyze all `.txt` files in the `dataops` folder:
    ```sh
    python multiagent.py
    ```

2. To analyze a specific `.txt` file:
    ```sh
    python multiagent.py dataops/sampledata.txt
    ```

## How It Works

1. **Data Collection**: Reads and collects data from `.txt` files in the specified `dataops` folder or a specified file.
2. **Agent Analysis**: Uses multiple LLM agents to analyze different aspects of the data:
   - **Threat Intelligence Agent**: Analyzes threat intelligence data.
   - **Log Analysis Agent**: Analyzes log data for anomalies.
   - **Vulnerability Assessment Agent**: Assesses vulnerabilities.
   - **Incident Response Agent**: Evaluates incidents and recommends response actions.
3. **Overseer Agent**: Generates a final summary brief based on the outputs of the other agents.
4. **Output to File**: Saves the final summary brief to `final_summary_brief.txt`.