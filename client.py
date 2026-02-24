import os
import requests
import json
import time

server = ""
maxsize = 32 * 1024 * 1024

def load_credentials(filename):
    with open(filename, 'r') as f:
        return json.load(f)

def get_token(credentials):
    return credentials['token']

def get_usr(credentials):
    return credentials['usr']

def upload_files(root_path, token, usr):
    url = server + '/upload_files'

    if not os.path.exists(root_path):
        print(f"Path is not present, path: {root_path}")
        requests.post(url,cookies={'token': token, 'usr': usr},data={"path": root, 'last_file': 'true'})
        return None

    all_files = set()
    for root, dirs, files in os.walk(root_path):
        for filename in files:
            all_files.add((root, filename))

    uploaded_files = set()

    for root, dirs, files in os.walk(root_path):
        for filename in files:
            filepath = os.path.join(root, filename)
            if (root, filename) in uploaded_files:
                continue
            if os.path.getsize(filepath) < maxsize:
                with open(filepath, 'rb') as opened_file:
                    data = {'path': root}
                    files_to_upload = [('files', (filename, opened_file, 'application/octet-stream'))]
                    response = requests.post(
                        url,
                        cookies={'token': token, 'usr': usr},
                        data=data,
                        files=files_to_upload,
                    )

                    if response.status_code == 401:
                        print(f"Error: Token or Username invalid!")
                        exit(401)

                    print(f"{filename} Uploaded")

                    try:
                        response.json()
                        uploaded_files.add((root, filename))
                    except requests.JSONDecodeError:
                        print("Non-JSON Response:", response.text)
                    if all_files == uploaded_files:
                        print("All files uploaded.")
                        response = requests.post(
                            url,
                            cookies={'token': token, 'usr': usr},
                            data={'path': root, 'last_file': 'true'},
                        )
                        uploaded_files=set()
            else:
                print(f"File is too large: {filepath}")

def get_upload_paths(token, usr):
    url = server + '/get_upload_path'
    response = requests.get(url, cookies={'token': token, 'usr': usr})

    if response.status_code == 401:
        print(f"Error: Username or Password invalid!")
        exit(401)

    try:
        return response.json()
    except requests.JSONDecodeError:
        print("Invalid Response:", response.text)
        return {"paths": []}

def main():
    credentials = load_credentials('credentials.json')
    token = get_token(credentials)
    usr = get_usr(credentials)

    
    while True:
        path_response = get_upload_paths(token, usr)
        path = path_response.get('path')

        if path:
            print(f"Path uploading... Path: {path}")
            upload_response = upload_files(path, token, usr)
        else:
            print("No new file...")

        time.sleep(10)

if __name__ == '__main__':
    main()
