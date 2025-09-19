#!/usr/bin/env python3
import subprocess
import os
import sys
import argparse
import glob
import json
import logging

# Setup logging
logger = logging.getLogger(__name__)

# -------------------------
# Read configuration file
home_path = os.path.expanduser("~")
CONFIG_FILE = os.path.join(home_path, ".config", "PersonalConfig", "l_rsync_config.json")
if not os.path.exists(CONFIG_FILE):
    logger.error(f"Configuration file {CONFIG_FILE} does not exist, please create it first!")
    sys.exit(1)

with open(CONFIG_FILE, "r", encoding="utf-8") as f:
    config = json.load(f)

REMOTE_USER = config.get("REMOTE_USER")
REMOTE_HOST = config.get("REMOTE_HOST")
REMOTE_PASS = config.get("REMOTE_PASS")
DEFAULT_REMOTE_PATH = config.get("DEFAULT_REMOTE_PATH")
# -------------------------

def run_cmd(cmd):
    """Run shell command and return output"""
    try:
        logger.debug(f"Executing command: {cmd}")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
        logger.debug(f"Command result: stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}', returncode={result.returncode}")
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except Exception as e:
        logger.error(f"Command execution error: {str(e)}")
        return "", f"Command execution error: {str(e)}", 1

def check_remote_file(remote_path, filename):
    """Check if remote file exists"""
    logger.debug(f"Checking if remote file exists: {remote_path}/{filename}")
    
    # Try Windows-style command first, then Unix-style
    windows_cmd = f'sshpass -p "{REMOTE_PASS}" ssh -o StrictHostKeyChecking=no {REMOTE_USER}@{REMOTE_HOST} "if exist \\"{remote_path}\\{filename}\\" (echo 1) else (echo 0)"'
    out, err, code = run_cmd(windows_cmd)
    
    if code == 0 and out in ["0", "1"]:
        result = out == "1"
        logger.debug(f"Windows file check successful: {filename} exists = {result}")
        return result
    
    # Fallback to Unix-style command
    logger.debug("Windows check failed, trying Unix-style command...")
    unix_cmd = f'sshpass -p "{REMOTE_PASS}" ssh -o StrictHostKeyChecking=no {REMOTE_USER}@{REMOTE_HOST} "[ -e \\"{remote_path}/{filename}\\" ] && echo 1 || echo 0"'
    out, err, code = run_cmd(unix_cmd)
    result = out == "1"
    logger.debug(f"Unix file check result: {filename} exists = {result}")
    return result

def rsync_path(local_path, remote_path, force=False):
    """Upload files or folders"""
    # Check if local files exist before proceeding
    matching_files = glob.glob(local_path)
    if not matching_files:
        logger.error(f"No files found matching pattern: {local_path}")
        return
    
    # Check each file exists and is accessible
    valid_files = []
    for path in matching_files:
        if not os.path.exists(path):
            logger.error(f"File does not exist: {path}")
            continue
        if not os.access(path, os.R_OK):
            logger.error(f"File is not readable: {path}")
            continue
        valid_files.append(path)
    
    if not valid_files:
        logger.error("No valid files to transfer")
        return
    
    logger.debug(f"Found {len(valid_files)} valid files to transfer")
    
    # First check if we can connect to remote host
    logger.debug("Testing SSH connection...")
    test_cmd = f'sshpass -p "{REMOTE_PASS}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {REMOTE_USER}@{REMOTE_HOST} "echo test"'
    out, err, code = run_cmd(test_cmd)
    if code != 0:
        logger.error(f"SSH connection failed: {err}")
        return
    logger.debug("SSH connection successful")
    
    # Check if rsync is available on remote host
    logger.debug("Checking if rsync is available on remote host...")
    rsync_check_cmd = f'sshpass -p "{REMOTE_PASS}" ssh -o StrictHostKeyChecking=no {REMOTE_USER}@{REMOTE_HOST} "where rsync 2>nul || which rsync 2>/dev/null || echo rsync_not_found"'
    out, err, code = run_cmd(rsync_check_cmd)
    if "rsync_not_found" in out or (not out and err):
        logger.debug("rsync may not be available on remote host. Using scp instead...")
        use_scp = True
    else:
        logger.debug(f"rsync found at: {out}")
        use_scp = False
    
    for path in valid_files:
        name = os.path.basename(path.rstrip("/"))
        logger.debug(f"Processing file: {name}")
        
        if check_remote_file(remote_path, name):
            if not force:
                try:
                    # Check if we're in an interactive terminal
                    if not sys.stdin.isatty():
                        # Non-interactive environment, skip by default
                        print(f"Non-interactive mode: Skipping {name} (use -f to force overwrite)")
                        continue
                    
                    choice = input(f"Remote already has {name}, overwrite? (y/n) ")
                    if choice.lower() != "y":
                        print(f"Skipping {name}")
                        continue
                except (EOFError, KeyboardInterrupt):
                    # Handle input errors gracefully
                    print(f"\nInput interrupted. Skipping {name}")
                    continue
        
        logger.debug(f"Transferring {name} to remote {remote_path} ...")
        
        if use_scp:
            # Use scp instead of rsync
            if os.path.isdir(path):
                cmd = f'sshpass -p "{REMOTE_PASS}" scp -r -o StrictHostKeyChecking=no "{path}" {REMOTE_USER}@{REMOTE_HOST}:"{remote_path}/"'
            else:
                cmd = f'sshpass -p "{REMOTE_PASS}" scp -o StrictHostKeyChecking=no "{path}" {REMOTE_USER}@{REMOTE_HOST}:"{remote_path}/"'
        else:
            # Use rsync
            cmd = f'sshpass -p "{REMOTE_PASS}" rsync -avz -e "ssh -o StrictHostKeyChecking=no" "{path}" {REMOTE_USER}@{REMOTE_HOST}:"{remote_path}/"'
        
        out, err, code = run_cmd(cmd)
        if code == 0:
            # Use print for success message to always show it regardless of log level
            # print(f"{name} transfer completed")
            logger.info(f"{name} transfer completed, path: {remote_path}/{name}")
        else:
            logger.error(f"{name} transfer failed: {err}")
            if out:
                logger.debug(f"Output: {out}")

def setup_logging(verbose=False):
    """Setup logging configuration"""
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    
    # Set level based on verbosity
    if verbose:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
    else:
        # In default mode, only show errors and completion messages
        logger.setLevel(logging.WARNING)
        console_handler.setLevel(logging.WARNING)
        formatter = logging.Formatter('%(message)s')
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Prevent duplicate logs
    logger.propagate = False

def main():
    parser = argparse.ArgumentParser(description="Upload files/folders to remote Windows, supports overwrite prompt and default path")
    parser.add_argument("-f", "--force", action="store_true", help="Force overwrite remote files without prompting")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (show all logs)")
    parser.add_argument("local_path", help="Local file or folder path (supports wildcards)")
    parser.add_argument("remote_path", nargs="?", default=DEFAULT_REMOTE_PATH, help="Remote path (optional)")
    args = parser.parse_args()

    # Setup logging based on verbosity
    setup_logging(args.verbose)

    rsync_path(args.local_path, args.remote_path, args.force)

if __name__ == "__main__":
    main()
