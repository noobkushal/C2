import os
import zipfile
import urllib.request
import json

LLAMA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "llama_bin")

def get_latest_windows_release():
    url = "https://api.github.com/repos/ggml-org/llama.cpp/releases"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response:
        releases = json.loads(response.read().decode())
    
    for r in releases:
        for asset in r.get('assets', []):
            name = asset.get('name', '')
            if 'bin-win-cpu-x64.zip' in name:
                return asset['browser_download_url'], name
    raise RuntimeError("No prebuilt Windows CPU binary asset found.")

def download_and_extract_llamacpp():
    os.makedirs(LLAMA_DIR, exist_ok=True)
    cli_exe = os.path.join(LLAMA_DIR, "llama-cli.exe")
    if os.path.exists(cli_exe):
        print(f"[+] llama.cpp prebuilt binaries ready at: {LLAMA_DIR}")
        return cli_exe

    download_url, zip_name = get_latest_windows_release()
    zip_path = os.path.join(LLAMA_DIR, zip_name)

    print(f"[*] Downloading {zip_name} from llama.cpp releases...")
    req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response, open(zip_path, 'wb') as out_file:
        out_file.write(response.read())

    print(f"[*] Extracting binaries to {LLAMA_DIR}...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(LLAMA_DIR)

    if os.path.exists(zip_path):
        os.remove(zip_path)

    print(f"[+] Installed llama.cpp binary at: {cli_exe}")
    return cli_exe

if __name__ == "__main__":
    download_and_extract_llamacpp()
