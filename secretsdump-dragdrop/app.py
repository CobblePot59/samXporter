from flask import Flask, render_template, request, jsonify
import os
import subprocess
import tempfile
from itertools import permutations

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

def run_secretsdump(sam_path, system_path, security_path):
    try:
        cmd = [
            'secretsdump.py',
            '-sam', sam_path,
            '-system', system_path,
            '-security', security_path,
            'LOCAL'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout: command took too long"
    except FileNotFoundError:
        return -1, "", "secretsdump.py not found"
    except Exception as e:
        return -1, "", str(e)

def try_all_combinations(files_dict):
    file_names = list(files_dict.keys())
    attempts = []
    
    for perm in permutations(file_names):
        if len(perm) < 2:
            continue
            
        sam_path = files_dict[perm[0]]
        system_path = files_dict[perm[1]]
        security_path = files_dict[perm[2]] if len(perm) > 2 else files_dict[perm[1]]
        
        returncode, stdout, stderr = run_secretsdump(sam_path, system_path, security_path)
        
        output_combined = stdout + stderr
        attempt_info = "Attempt: {} -> {} -> {}".format(perm[0], perm[1], security_path)
        
        has_hashes = ':::' in stdout or 'NT' in stdout or 'aad3b435b51404eeaad3b435b51404ee' in stdout
        has_error = 'not subscriptable' in output_combined or 'Error' in output_combined or 'Traceback' in output_combined
        
        if has_hashes and not has_error:
            attempt_info += " - SUCCESS"
            return {
                'success': True,
                'output': stdout if stdout else output_combined,
                'attempts': attempts
            }
        else:
            error_line = stderr.strip().split('\n')[0] if stderr else "No hashes found"
            attempt_info += " - FAIL: {}".format(error_line[:60])
        
        attempts.append(attempt_info)
    
    return {
        'success': False,
        'output': '',
        'error': 'No valid combination found.',
        'attempts': attempts
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'files' not in request.files:
        return jsonify({'success': False, 'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('files')
    
    if len(files) < 2:
        return jsonify({'success': False, 'error': 'You must upload at least 2 files'}), 400
    
    temp_files = {}
    temp_paths = []
    
    try:
        for idx, file in enumerate(files):
            if file.filename == '':
                return jsonify({'success': False, 'error': 'A file is empty'}), 400
            
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            file.save(temp_file.name)
            temp_files[file.filename] = temp_file.name
            temp_paths.append(temp_file.name)
        
        result = try_all_combinations(temp_files)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    
    finally:
        for temp_path in temp_paths:
            try:
                os.unlink(temp_path)
            except:
                pass

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)