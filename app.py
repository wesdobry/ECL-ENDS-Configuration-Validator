import os
import tarfile
import subprocess
import json
import shutil
import logging
from flask import Flask, request, jsonify, session, render_template # type: ignore
from flask_session import Session  # type: ignore
from cerberus import Validator # type: ignore

app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
app.logger.addHandler(handler)

app.config['SECRET_KEY'] = 'ICantBelieveIForgotThis12312313'
app.config['SESSION_TYPE'] = 'filesystem'  # Specifies session type to use file system for storage
app.config['SESSION_PERMANENT'] = False  # Session data is not permanent
app.config['SESSION_USE_SIGNER'] = True  # Secure cookies by signing them

Session(app)  # Initialize the Session

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




@app.route('/')
def index():
    session.clear() 
    app.logger.info("/ requested")
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    app.logger.info("tar.gz uploaded")
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': "No selected file"}), 400
    if file and file.filename.endswith('.tar.gz'):
        try:
            filepath = os.path.join('/tmp', file.filename)
            extracted_dir = os.path.join('/tmp', 'extracted')

            # Save the uploaded file
            file.save(filepath)

            # Extract the file
            extracted_files = extract_tar_gz(filepath, extracted_dir)

            # Find spidump.bin within the extracted directory
            spidump_path = find_file('spidump.bin', extracted_dir)

            if not spidump_path:
                print("No SPIdump found in archive.")

            json_data = parse_json_files(extracted_files)
            session['results'] = json_data 
            print("Stored in session:", session['results'])  # Add this to verify

            # Process the spidump.bin with chipsec
            #result = run_command(spidump_path)
            #json_data.append(result)  # Append new result to existing

            # Clean up: remove the tar.gz and extracted files
            clean_up(filepath, extracted_dir)

            # return jsonify({'success': True, 'data': json_data}), 200
            return jsonify({'success': True}), 200
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    else:
        return jsonify(error="Unsupported file format"), 400
    
@app.route('/results')
def show_results():
    app.logger.info("Results rendered")
    results = session.get('results', 'No results found.')
    print("Retrieved from session:", results)  # Add this to verify
    #return f'{results}'
    return jsonify(results), 200

def extract_tar_gz(filepath, extracted_dir):
    with tarfile.open(filepath, "r:gz") as tar:
        tar.extractall(path=extracted_dir)
        extracted_files = tar.getnames()
    return [os.path.join(extracted_dir, f) for f in extracted_files if f.endswith('.json')]

def find_file(filename, search_path):
    for root, dirs, files in os.walk(search_path):
        if filename in files:
            return os.path.join(root, filename)
    return None

def run_command(file_path):
    result = subprocess.run(['/usr/local/bin/python', '/opt/chipsec/chipsec_main.py', '-n', '-i', '-nb', '--skip_config', '-m', 'acpi,check,cmos,config,cpu,decode,deltas,ec,gdt,help,idt,igd,io,iommu,mem,mmcfg,mmcfg_base,mmio,msgbus,msr,nmi,pci,platform,reg,smbios,smbus,smi,spd,spi,spidesc,tpm,txt,ucode,uefi,vmem,vmm', file_path], capture_output=True, text=True, check=True)
    print(result)
    print(result.stdout)
    return json.loads(result.stdout)

def parse_json_files(files):
    #data = []
    data = {}
    base_path = '/tmp/extracted/'  # Define the base path that you want to strip out
    for file in files:
        with open(file) as f:
            json_content = json.load(f)
            # Remove the base path from the file path
            relative_path = file[len(base_path):] if file.startswith(base_path) else file
            # file_data = {
            #     'relative_path': relative_path,
            #     'content': json_content
            # }
            #data.append(file_data)

            data[relative_path] = json_content
    return data



def clean_up(tar_path, extracted_dir):
    app.logger.info("Cleanup routine executed")
    if os.path.exists(tar_path):
        os.remove(tar_path)
    if os.path.isdir(extracted_dir):
        for filename in os.listdir(extracted_dir):
            file_path = os.path.join(extracted_dir, filename)
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        os.rmdir(extracted_dir)

@app.route('/ends')
def endsconfigbuilder():
    session.clear() 
    app.logger.info("/ends accessed")
    return render_template('endsconfig.html')

@app.route('/endsvalidator', methods=['GET', 'POST'])
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
