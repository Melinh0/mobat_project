from pathlib import Path

SCRIPT_NAME = Path(__file__).name
OUTPUT_FILE = "compiladomobat.txt"
IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".idea", ".vscode", "dist", "build"}

def should_skip_file(file_path: Path) -> bool:
    if file_path.name == SCRIPT_NAME or file_path.name == OUTPUT_FILE:
        return True
    if any(part in IGNORE_DIRS for part in file_path.parts):
        return True
    if file_path.suffix.lower() != '.py':
        return True
    return False

def read_file_content(file_path: Path) -> str:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except (UnicodeDecodeError, OSError):
        try:
            with open(file_path, "r", encoding="latin-1") as f:
                return f.read()
        except Exception as e:
            return f"[Erro ao ler arquivo: {e}]"

def main():
    root_dir = Path(__file__).parent.resolve()
    output_path = root_dir / OUTPUT_FILE

    with open(output_path, "w", encoding="utf-8") as out:
        for file_path in root_dir.rglob("*"):
            if not file_path.is_file():
                continue
            if should_skip_file(file_path):
                continue

            rel_path = file_path.relative_to(root_dir)
            content = read_file_content(file_path)

            out.write(f"{'=' * 80}\n")
            out.write(f"ARQUIVO: {rel_path}\n")
            out.write(f"{'=' * 80}\n")
            out.write(content)
            out.write("\n\n")

    print(f"Compilado salvo em: {output_path}")

if __name__ == "__main__":
    main()