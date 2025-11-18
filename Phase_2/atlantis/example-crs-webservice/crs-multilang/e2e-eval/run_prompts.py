import argparse
import html
import json
import ssl
from functools import wraps
from pathlib import Path

from flask import Flask, Response, render_template_string, request

app = Flask(__name__)

USERNAME = "admin"
PASSWORD = "atlantis1!"


def check_auth(username, password):
    return username == USERNAME and password == PASSWORD


def authenticate():
    return Response(
        "Authentication required\nPlease provide valid credentials",
        401,
        {"WWW-Authenticate": 'Basic realm="Prompt Viewer"'},
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>Prompt Viewer</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 30px;
            background-color: #f5f5f5;
            line-height: 1.6;
        }

        .input-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }

        textarea {
            width: 100%;
            box-sizing: border-box;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            padding: 15px;
            height: 300px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 14px;
            resize: vertical;
        }

        textarea:focus {
            outline: none;
            border-color: #007acc;
        }

        button {
            margin-top: 15px;
            padding: 12px 24px;
            background-color: #007acc;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 500;
        }

        button:hover {
            background-color: #005a9e;
        }

        .output-section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .message-box {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }

        .message-header {
            padding: 12px 16px;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .message-header.user {
            background-color: #e3f2fd;
            color: #1565c0;
            border-bottom: 1px solid #bbdefb;
        }

        .message-header.assistant {
            background-color: #f3e5f5;
            color: #7b1fa2;
            border-bottom: 1px solid #e1bee7;
        }

        .message-header.system {
            background-color: #fff3e0;
            color: #ef6c00;
            border-bottom: 1px solid #ffcc02;
        }

        .message-header.unknown {
            background-color: #f5f5f5;
            color: #616161;
            border-bottom: 1px solid #e0e0e0;
        }

        .message-content {
            padding: 16px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
            background: white;
        }

        .message-number {
            float: right;
            background: rgba(0,0,0,0.1);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: normal;
        }

        .error-message {
            background: #ffebee;
            color: #c62828;
            padding: 16px;
            border-radius: 6px;
            border-left: 4px solid #f44336;
            font-family: monospace;
        }

        h2 {
            color: #333;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="input-section">
        <h2>Enter JSON AI Prompts</h2>
        <form method=\"post\">
            <textarea name=\"json_input\" placeholder=\"Paste your JSON array here (e.g., [{&quot;type&quot;: &quot;user&quot;, &quot;content&quot;: &quot;Hello&quot;}, {&quot;type&quot;: &quot;assistant&quot;, &quot;content&quot;: &quot;Hi there!&quot;}])\">{{ json_input }}</textarea>
            <br>
            <button type=\"submit\">Parse & Display</button>
        </form>
    </div>

    <div class="output-section">
        <h2>Parsed Prompt Output</h2>
        {{ parsed_output|safe }}
    </div>
</body>
</html>
"""


def format_json_prompts(json_input):
    try:
        data = json.loads(json_input)
        if not data:
            return '<div class="error-message">No data provided</div>'

        output = []
        for i, entry in enumerate(data, 1):
            role = entry.get("type", "unknown").lower()
            content = entry.get("content", "").replace("\\n", "\n")

            # Escape HTML/XML tags to prevent them from being treated as HTML
            escaped_content = html.escape(content)

            # Create individual message box
            message_html = f"""
            <div class="message-box">
                <div class="message-header {role}">
                    {role.capitalize()}
                    <span class="message-number">#{i}</span>
                </div>
                <div class="message-content">{escaped_content}</div>
            </div>
            """
            output.append(message_html)

        return "".join(output)
    except json.JSONDecodeError as e:
        return (
            f'<div class="error-message">JSON Parse Error: {html.escape(str(e))}</div>'
        )
    except Exception as e:
        return f'<div class="error-message">Error: {html.escape(str(e))}</div>'


@app.route("/", methods=["GET", "POST"])
@requires_auth
def index():
    json_input = ""
    parsed_output = ""
    if request.method == "POST":
        json_input = request.form.get("json_input", "")
        parsed_output = format_json_prompts(json_input)
    return render_template_string(
        HTML_TEMPLATE, json_input=json_input, parsed_output=parsed_output
    )


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run the Prompt Viewer with optional SSL and auth"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5050,
        help="Port to run the server on (default: 5050)",
    )
    parser.add_argument("--username", default="admin", help="Basic auth username")
    parser.add_argument("--password", default="atlantis1!", help="Basic auth password")
    parser.add_argument(
        "--cert-path",
        type=Path,
        default="./keys/fullchain.pem",
        help="Path to SSL certificate file (default: ./keys/fullchain.pem)",
    )
    parser.add_argument(
        "--key-path",
        type=Path,
        default="./keys/privkey.pem",
        help="Path to SSL private key file (default: ./keys/privkey.pem)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    USERNAME = args.username
    PASSWORD = args.password

    ssl_context = None
    if (
        args.cert_path
        and args.key_path
        and args.cert_path.exists()
        and args.key_path.exists()
    ):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(
            certfile=str(args.cert_path), keyfile=str(args.key_path)
        )
        print(f"Running in HTTPS mode on https://{args.host}:{args.port}")
    else:
        print(f"Running in HTTP mode on http://{args.host}:{args.port}")

    app.run(host=args.host, port=args.port, ssl_context=ssl_context)
