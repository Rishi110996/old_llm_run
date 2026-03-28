import sys
import os
import json
import logging
import requests
from DefineRegisterTools import TOOL_REGISTRY, register_apk_tools

logging.getLogger("androguard").setLevel(logging.ERROR)

url1 = "http://34.57.123.78:8000/endpoint/v1/chat"

def setup_logger(log_file_path):
    logger = logging.getLogger("LLM_Interaction_Logger")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler(log_file_path, mode='w')
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    return logger

def run_tools(apk_path, logger):
    """Run all registered tools once and return results as dict."""
    results = {}
    for tool_name, tool_func in TOOL_REGISTRY.items():
        try:
            logger.info(f"Running tool: {tool_name}")
            result = tool_func({"apk_path": apk_path})
            results[tool_name] = result
        except Exception as e:
            results[tool_name] = {"error": str(e)}
            logger.error(f"Tool {tool_name} failed: {e}")
    return results

def ask_llm(apk_path, tool_results, logger, max_retries=3):
    """Send results to LLM for structured analysis and verdict with retries."""

    base_messages = [
        {
            "role": "system",
            "content": (
                "You are an expert Android malware analyst.\n"
                "Your task is to analyze tool outputs and return a STRICT JSON verdict.\n"
                "Schema:\n"
                "{\n"
                "  \"Malicious\": 0 or 1,\n"
                "  \"Suspicious\": 0 or 1,\n"
                "  \"Clean\": 0 or 1,\n"
                "  \"Summary\": \"short explanation\"\n"
                "}\n"
                "- Exactly one of Malicious/Suspicious/Clean must be 1, others 0.\n"
                "- Do not include extra text outside JSON.\n"
            )
        },
        {
            "role": "user",
            "content": (
                f"Analyze this APK: {apk_path}\n\n"
                f"Here are the tool results:\n{json.dumps(tool_results, indent=2)}\n\n"
                "Return the verdict in the required JSON format only."
            )
        }
    ]

    headers = {
        'x-api-key': 'QES7YEBMuoG8wMJhFC97EobniEWJ9l72sbF5PryhVRB',
        'User-Agent': 'Zscaler/2.3 Webkit',
        'Content-Type': 'application/json'
    }

    messages = base_messages[:]

    for attempt in range(1, max_retries + 1):
        payload = json.dumps({
            "messages": messages,
            "model": "llama3.1:8b",
            "stream": False
        })

        response = requests.post(url1, headers=headers, data=payload)

        try:
            data = response.json()
            content = data["message"]["content"]
            logger.info(f"LLM Attempt {attempt} Raw Response: {content}")
        except Exception:
            logger.error(f"Invalid LLM response (not JSON at transport level): {response.text}")
            continue

        # Try parsing into JSON safely
        try:
            verdict = json.loads(content)
        except json.JSONDecodeError:
            logger.warning(f"Attempt {attempt}: LLM did not return valid JSON. Retrying...")
            messages.append({
                "role": "system",
                "content": (
                    "⚠️ Your last response was invalid. "
                    "Return ONLY valid JSON in the required schema. "
                    "Do not include any text, explanation, or markdown formatting."
                )
            })
            continue

        # Validate schema
        required_keys = {"Malicious", "Suspicious", "Clean", "Summary"}
        if not required_keys.issubset(verdict.keys()):
            logger.warning(f"Attempt {attempt}: Verdict missing keys. Retrying...")
            messages.append({
                "role": "system",
                "content": (
                    "⚠️ Your last response missed required keys. "
                    "Return JSON with all keys: Malicious, Suspicious, Clean, Summary."
                )
            })
            continue

        if sum([verdict["Malicious"], verdict["Suspicious"], verdict["Clean"]]) != 1:
            logger.warning(f"Attempt {attempt}: Verdict flags not exclusive. Retrying...")
            messages.append({
                "role": "system",
                "content": (
                    "⚠️ Your last response had invalid flags. "
                    "Exactly one of Malicious, Suspicious, Clean must be 1, others 0."
                )
            })
            continue

        return verdict  # ✅ Success

    logger.error("LLM failed to return valid verdict after retries.")
    return None


def run_chat(apk_path):
    log_file_path = os.path.join(
        os.path.dirname(apk_path),
        os.path.basename(apk_path) + "_llm_interactions.log"
    )
    logger = setup_logger(log_file_path)

    # 1. Register tools
    register_apk_tools()

    # 2. Run all tools once
    tool_results = run_tools(apk_path, logger)

    # 3. Send all results to LLM
    verdict = ask_llm(apk_path, tool_results, logger)

    if verdict:
        print(f"\n[✅ Final Verdict for {os.path.basename(apk_path)}]\n{verdict}")

if __name__ == "__main__":
    folder_path = sys.argv[1]

    if not os.path.isdir(folder_path):
        print("Invalid folder path. Please provide a valid directory.")
        sys.exit(1)

    apk_files = [f for f in os.listdir(folder_path) if f.lower().endswith(".apk")]
    if not apk_files:
        print("No APK files found in the specified folder.")
        sys.exit(0)

    for file_name in apk_files:
        print(f"\n[📦 Analyzing APK file: {file_name}]")
        run_chat(os.path.join(folder_path, file_name))

    print("\n[🎉 All APK files processed. Exiting.]")
