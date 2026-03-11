import os


SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".php",
    ".rb",
    ".c",
    ".cpp",
}


EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "build",
    "dist",
}


def get_source_files(root_path):
    """
    Recursively collect source files from a directory.

    Returns:
        list[str] : list of file paths
    """
    source_files = []

    for root, dirs, files in os.walk(root_path):
        # remove excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            file_path = os.path.join(root, file)

            ext = os.path.splitext(file)[1].lower()

            if ext in SUPPORTED_EXTENSIONS:
                source_files.append(file_path)

    return source_files

