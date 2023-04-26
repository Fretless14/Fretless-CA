import os
import subprocess


if __name__ == '__main__':

    # determine if application is a script file or frozen exe
    if getattr(sys, 'frozen', False):
        home_directory = os.path.dirname(sys.executable)
    elif __file__:
        home_directory = os.path.dirname(__file__)
    else:
        raise Exception

    subprocess.run(f"export CA_DIR={home_directory} && docker-compose up -d", check=True, shell=True, cwd=home_directory)
