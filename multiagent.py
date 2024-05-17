import os
import requests
import json
import argparse

# Configuration
API_KEY = "your-api-key"  # Replace 'your-api-key' with your actual API key
APP_NAME = "Security Framework"
AGENT_MODEL_IDS = {
    "threat_intelligence": "phi3",
    "log_analysis": "phi3",
    "vulnerability_assessment": "phi3",
    "incident_response": "phi3"
}
TOGETHER_API_ENDPOINT = 'https://api.together.xyz/inference'
OLLAMA_API_ENDPOINT = 'http://localhost:11434/api/generate'
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "User-Agent": APP_NAME
}
USE_OLLAMA = True  # Set this to False to use Together API
DATAOPS_FOLDER = "dataops"

def api_call(model_id, prompt, max_tokens):
    """Call the appropriate API to generate text based on the model ID and prompt."""
    data = {
        "model": model_id,
        "prompt": prompt,
        "top_p": 1,
        "top_k": 40,
        "temperature": 0.8,
        "max_tokens": max_tokens,
        "repetition_penalty": 1
    }
    try:
        if USE_OLLAMA:
            response = requests.post(OLLAMA_API_ENDPOINT, json=data, stream=True)
            response.raise_for_status()
            
            # Handle streaming response
            response_text = ""
            for line in response.iter_lines():
                if line:
                    json_line = json.loads(line.decode('utf-8'))
                    response_text += json_line.get('response', '')

            return {"output": {"choices": [{"text": response_text}]}}
        else:
            response = requests.post(TOGETHER_API_ENDPOINT, json=data, headers=HEADERS)
            response.raise_for_status()
            return response.json()
    except requests.RequestException as e:
        print(f"API call error: {e}")
        return {}
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        return {"error": "JSON decode error"}

def threat_intelligence_analysis(data):
    """Analyze threat intelligence data."""
    prompt = f"Analyze the following threat intelligence data:\n{data}\nProvide a summary of the key threats."
    response = api_call(AGENT_MODEL_IDS["threat_intelligence"], prompt, 300)
    return response.get('output', {}).get('choices', [{}])[0].get('text', "Error: Response does not contain 'text' key.")

def log_analysis(data):
    """Analyze log data for anomalies."""
    prompt = f"Analyze the following log data:\n{data}\nIdentify any anomalies or suspicious activities."
    response = api_call(AGENT_MODEL_IDS["log_analysis"], prompt, 300)
    return response.get('output', {}).get('choices', [{}])[0].get('text', "Error: Response does not contain 'text' key.")

def vulnerability_assessment(data):
    """Assess vulnerabilities from reports."""
    prompt = f"Assess the following vulnerability data:\n{data}\nProvide a summary of the critical vulnerabilities."
    response = api_call(AGENT_MODEL_IDS["vulnerability_assessment"], prompt, 300)
    return response.get('output', {}).get('choices', [{}])[0].get('text', "Error: Response does not contain 'text' key.")

def incident_response(data):
    """Evaluate incidents and recommend actions."""
    prompt = f"Evaluate the following incident data:\n{data}\nRecommend appropriate response actions."
    response = api_call(AGENT_MODEL_IDS["incident_response"], prompt, 300)
    return response.get('output', {}).get('choices', [{}])[0].get('text', "Error: Response does not contain 'text' key.")

def generate_security_brief(threat_data, log_data, vuln_data, incident_data):
    """Generate a comprehensive security brief."""
    threat_summary = threat_intelligence_analysis(threat_data)
    log_summary = log_analysis(log_data)
    vuln_summary = vulnerability_assessment(vuln_data)
    incident_summary = incident_response(incident_data)

    brief = (
        "Security Brief:\n\n"
        "Threat Intelligence Summary:\n"
        f"{threat_summary}\n\n"
        "Log Analysis Summary:\n"
        f"{log_summary}\n\n"
        "Vulnerability Assessment Summary:\n"
        f"{vuln_summary}\n\n"
        "Incident Response Summary:\n"
        f"{incident_summary}\n"
    )
    return brief

def read_data_from_file(file_path):
    """Read data from a given file path."""
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def collect_data_from_folder(folder_path):
    """Collect data from all files in the specified folder."""
    collected_data = {
        "threat_data": "",
        "log_data": "",
        "vuln_data": "",
        "incident_data": ""
    }
    for root, _, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.txt'):
                file_path = os.path.join(root, file)
                data = read_data_from_file(file_path)
                if data:
                    if "threat" in file.lower():
                        collected_data["threat_data"] += data.strip() + "\n"
                    elif "log" in file.lower():
                        collected_data["log_data"] += data.strip() + "\n"
                    elif "vuln" in file.lower():
                        collected_data["vuln_data"] += data.strip() + "\n"
                    elif "incident" in file.lower():
                        collected_data["incident_data"] += data.strip() + "\n"
    return collected_data

def main():
    """Main function to run the security framework."""
    parser = argparse.ArgumentParser(description="Security Framework using Multi-Agent LLMs")
    parser.add_argument("file", nargs="?", help="Optional specific .txt file to analyze")
    args = parser.parse_args()

    if args.file:
        # If a specific file is provided, use it for analysis
        file_path = args.file
        data = read_data_from_file(file_path)
        if data:
            security_brief = generate_security_brief(data, data, data, data)
            print(security_brief)
        else:
            print("Failed to read data from the provided file.")
    else:
        # If no specific file is provided, analyze all files in the dataops folder
        collected_data = collect_data_from_folder(DATAOPS_FOLDER)
        
        threat_data = collected_data["threat_data"].strip() or "No threat data provided."
        log_data = collected_data["log_data"].strip() or "No log data provided."
        vuln_data = collected_data["vuln_data"].strip() or "No vulnerability data provided."
        incident_data = collected_data["incident_data"].strip() or "No incident data provided."

        security_brief = generate_security_brief(threat_data, log_data, vuln_data, incident_data)
        print(security_brief)

if __name__ == "__main__":
    main()
