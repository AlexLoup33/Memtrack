from pathlib import Path

import os
import subprocess

def install_lib():
    lib_folder_path = Path(__file__).parent.parent.joinpath("interceptor")
    lib_path = Path(__file__).parent.parent.joinpath("interceptor/libmemtrack.so")

    if not os.path.exists(lib_path):
        try:
            ret = subprocess.run(["make"], cwd=lib_folder_path, check=True)
            print(ret.stdout)

        except subprocess.CalledProcessError as e:
            print(f"Following command failed with code : {e.returncode}")
            print(f"Standard error : {e.stderr}")

            return False
    return True
        