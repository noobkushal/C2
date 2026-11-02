import os
import argparse
from huggingface_hub import hf_hub_download

DEFAULT_REPO = "Qwen/Qwen2.5-1.5B-Instruct-GGUF"
DEFAULT_FILENAME = "qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

def download_model(repo_id=DEFAULT_REPO, filename=DEFAULT_FILENAME, target_dir=MODELS_DIR):
    os.makedirs(target_dir, exist_ok=True)
    destination_path = os.path.join(target_dir, filename)

    if os.path.exists(destination_path):
        print(f"[+] Model already exists at: {destination_path}")
        return destination_path

    print(f"[*] Downloading {filename} from {repo_id}...")
    local_file = hf_hub_download(
        repo_id=repo_id,
        filename=filename,
        local_dir=target_dir,
        local_dir_use_symlinks=False
    )
    print(f"[+] Download complete: {local_file}")
    return local_file

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download GGUF model from Hugging Face")
    parser.add_argument("--repo", type=str, default=DEFAULT_REPO, help="Hugging Face repo ID")
    parser.add_argument("--filename", type=str, default=DEFAULT_FILENAME, help="GGUF filename")
    args = parser.parse_args()

    download_model(args.repo, args.filename)
