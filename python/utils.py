import os

def check_file(path_to_file):
    if not os.path.exists(path_to_file):
        print(f"Unable to continue, make sure that {path_to_file} exists(errno 2)")
        exit(2)
