import os
import json
import logging
from flask import Flask, request, session, render_template # type: ignore
from cerberus import Validator # type: ignore

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

#for ends configuration validator
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Define the schema TBDDDDDDDDDDDDDD
endsschema = {
    "company_address": {"type": "string", "regex": r"^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$", "required": False},  # CIDR format
    "all_interfaces": {"type": "boolean", "required": False},
    "integrity_check": {"type": "boolean", "required": False},
    "threads": {"type": "integer", "min": 1, "required": False},  # Positive integer
    "aggressiveness": {"type": "string", "allowed": ["NORMAL_SCAN", "HIGH_SCAN"], "required": False},
    "log_level": {"type": "string", "allowed": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], "required": False},
    "insecure_allow_invalid_certificate": {"type": "boolean", "required": False},
    "no_upload": {"type": "boolean", "required": False},
    "out_folder": {"type": "string", "regex": r"^(\./.*|(/[a-zA-Z0-9._-]+)+|([a-zA-Z]:\\{2}[a-zA-Z0-9._-]+\\{2}.*))$", "required": False},
    "run_auth_scan_templates": {"type": "boolean", "required": False},
    "targets": {
        "type": "dict",
        "keysrules": {"type": "string", "regex": r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$"},  # IP addresses as keys
        "valuesrules": {
            "type": "dict",
            "schema": {
                "username": {"type": "string", "required": False},
                "password": {"type": "string", "required": False},  # Hidden in real-world display
                "ssh_username": {"type": "string", "required": False},
                "ssh_password": {"type": "string", "required": False},  # Hidden in real-world display
                "driver": {"type": "string", "allowed": ["ios", "asa", "nexus", "iosxr", "ftd", "wlc", "eos", "arubaos-cx", "arubaos-switch", "exos", "junos", "panos", "fortios", "netscaler", "bigip", "os6", "ftos", "os10"], "required": False},
                "integrity_check": {"type": "boolean", "required": False},
                "optional_args": {
                    "type": "dict",
                    "schema": {
                        "secret": {"type": "string"},
                        "port": {"type": "integer", "min": 1, "max": 65535, "required": False}
                    }
                }
            }
        }
    },
    "ip": {
        "type": "list",
        "schema": {"type": "string", "regex": r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$"}  # List of IP addresses or ranges
    },
    "post_auth": {
        "type": "list",
        "schema": {"type": "string", "regex": r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(/(3[0-2]|[12]?[0-9]))?$"} # List of IP addresses or ranges
    }
}

validator = Validator(endsschema, allow_unknown=False)

@app.route('/', methods=['GET', 'POST'])
def endsvalidator():
    if request.method == 'GET':
        # Handle the initial page load
        session.clear()
        app.logger.info("/endsvalidator accessed")
        return render_template('endsvalidator.html')
    
    if request.method == 'POST':
        # Handle file upload and validation
        if 'file' not in request.files:
            return render_template('endsvalidator.html', result="No file part in the request", status="Error")
        file = request.files['file']
        if file.filename == '':
            return render_template('endsvalidator.html', result="No selected file", status="Error")

        # Save the uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(filepath)

        # Read and validate the JSON file
        try:
            with open(filepath, 'r') as f:
                json_data = json.load(f)
        except json.JSONDecodeError as e:
            error_message = f"Invalid JSON format: {e.msg} at line {e.lineno}, column {e.colno}"
            return render_template('endsvalidator.html', result=error_message, status="Error")

        # Validate JSON
        validation_errors = {}
        if not validator.validate(json_data):
            validation_errors = validator.errors
            
            # Detect unknown fields
            unknown_fields = [field for field in json_data.keys() if field not in endsschema]
            if unknown_fields:
                validation_errors["unknown_fields"] = unknown_fields

            result = {"status": "Invalid JSON", "errors": validation_errors}
            return render_template('endsvalidator.html', result=result, status="Invalid")
        else:
            result = {"status": "Valid JSON", "data": json_data}
            return render_template('endsvalidator.html', result=result, status="Valid")


if __name__ == '__main__':
    app.run(debug=False)
