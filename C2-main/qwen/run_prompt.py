import os
import sys
import subprocess
import argparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
LLAMA_DIR = os.path.join(BASE_DIR, "llama_bin")
DEFAULT_MODEL_PATH = os.path.join(MODELS_DIR, "qwen2.5-1.5b-instruct-q4_k_m.gguf")

def ensure_setup(model_path=DEFAULT_MODEL_PATH):
    cli_exe = os.path.join(LLAMA_DIR, "llama-cli.exe")
    if not os.path.exists(cli_exe):
        from download_llamacpp_bin import download_and_extract_llamacpp
        cli_exe = download_and_extract_llamacpp()

    if not os.path.exists(model_path):
        from download_model import download_model
        model_path = download_model()

    return cli_exe, model_path

def run_prompt(prompt, model_path=DEFAULT_MODEL_PATH, system_prompt="You are a helpful, smart, and precise AI assistant.", n_ctx=2048):
    cli_exe, model_path = ensure_setup(model_path)

    cmd = [
        cli_exe,
        "-m", model_path,
        "-p", f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n",
        "-c", str(n_ctx),
        "--no-display-prompt"
    ]

    print("\n--- Running llama.cpp ---")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Error running llama-cli: {e}")

def run_interactive(model_path=DEFAULT_MODEL_PATH, system_prompt="You are a helpful, smart, and precise AI assistant.", n_ctx=2048):
    cli_exe, model_path = ensure_setup(model_path)

    cmd = [
        cli_exe,
        "-m", model_path,
        "-sys", system_prompt,
        "-c", str(n_ctx),
        "-cnv"
    ]

    print("\n--- Starting Interactive Session ---")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nExiting interactive chat.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run prompt using prebuilt llama.cpp CLI")
    parser.add_argument("--prompt", "-p", type=str, help="Prompt text to generate a response for")
    parser.add_argument("--system", "-s", type=str, default="You are a helpful, smart, and precise AI assistant.", help="System prompt")
    parser.add_argument("--model", "-m", type=str, default=DEFAULT_MODEL_PATH, help="Path to GGUF model")
    parser.add_argument("--ctx", type=int, default=2048, help="Context size")
    parser.add_argument("--interactive", "-i", action="store_true", help="Start interactive conversation")

    args = parser.parse_args()

    if args.interactive or not args.prompt:
        if not args.prompt:
            print("[*] No prompt passed. Starting interactive mode...")
        run_interactive(model_path=args.model, system_prompt=args.system, n_ctx=args.ctx)
    else:
        run_prompt(prompt=args.prompt, model_path=args.model, system_prompt=args.system, n_ctx=args.ctx)
