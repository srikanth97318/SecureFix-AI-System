import subprocess


def list_files(directory):
    command = f"ls {directory}"
    return subprocess.run(
        command,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
