import requests
import json
import os
import requests
import zipfile
import io
import re

zintel_url = 'https://z-intel-plus.corp.zscaler.com/'
zintel_api = 'aab3eae570554b95a128f123b3a5968b'


def get_latest_export_id():
    """
    Parse the JSON response data and return the `id` of the first dictionary with `status` == "completed".

    :param response_data: JSON response data (as a dictionary).
    :return: `id` of the first dictionary with status "completed", or None if no such entry exists.
    """
    try:
        # Extract the 'results' list from the 'data' key
        url = f'{zintel_url}api/coverage/yara-exports/'
        headers = {
        'accept': 'application/json',
        'Authorization': f'Api-Key {zintel_api}',
        'Content-Type': 'application/json'
        }
        response = requests.get(url, headers=headers)
        response_data = response.json()
        results = response_data.get("data", {}).get("results", [])
        
        # Iterate through the results and find the first entry with status "completed"
        for item in results:
            if item.get("status") == "completed":
                return str(item.get("id")).strip()  # Return the ID of the matching dictionary
        
        # If no match is found, return None
        return None
    
    except Exception as e:
        print(f"Error parsing data: {e}")
        return None


# {"data":{"count":2433,"num_pages":122,"next":"http://z-intel-plus.corp.zscaler.com/api/coverage/yara-exports/?page=2","previous":null,"results":[{"id":2456,"status":"completed","created_date":"2025-06-27T17:35:11.252879+05:30","modified_date":"2025-06-27T19:50:35.668294+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2455,"status":"completed","created_date":"2025-06-26T17:37:56.756859+05:30","modified_date":"2025-06-26T19:01:46.203365+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2454,"status":"completed","created_date":"2025-06-25T17:47:36.285469+05:30","modified_date":"2025-06-25T18:46:22.976718+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2453,"status":"completed","created_date":"2025-06-24T19:12:31.638772+05:30","modified_date":"2025-06-24T19:59:23.463399+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2452,"status":"completed","created_date":"2025-06-23T18:44:05.724648+05:30","modified_date":"2025-06-23T19:29:50.997235+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2451,"status":"completed","created_date":"2025-06-19T18:38:47.126518+05:30","modified_date":"2025-06-19T18:39:21.284538+05:30","user":{"id":3,"username":"tdewan","email":"tdewan@zscaler.com","first_name":"Tarun","last_name":"Dewan","image":null,"timezone":"Asia/Kolkata"}},{"id":2450,"status":"completed","created_date":"2025-06-19T12:10:14.151048+05:30","modified_date":"2025-06-19T14:07:31.563827+05:30","user":{"id":3,"username":"tdewan","email":"tdewan@zscaler.com","first_name":"Tarun","last_name":"Dewan","image":null,"timezone":"Asia/Kolkata"}},{"id":2449,"status":"completed","created_date":"2025-06-17T19:58:35.482972+05:30","modified_date":"2025-06-17T21:25:14.113584+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2448,"status":"completed","created_date":"2025-06-17T12:22:27.376402+05:30","modified_date":"2025-06-17T13:33:32.523057+05:30","user":{"id":3,"username":"tdewan","email":"tdewan@zscaler.com","first_name":"Tarun","last_name":"Dewan","image":null,"timezone":"Asia/Kolkata"}},{"id":2447,"status":"completed","created_date":"2025-06-16T19:51:37.296369+05:30","modified_date":"2025-06-16T20:33:41.362338+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2446,"status":"completed","created_date":"2025-06-16T17:22:27.564510+05:30","modified_date":"2025-06-16T19:07:32.298641+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2445,"status":"completed","created_date":"2025-06-13T18:27:08.552254+05:30","modified_date":"2025-06-13T20:13:01.125189+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2444,"status":"failed","created_date":"2025-06-12T17:42:33.762613+05:30","modified_date":"2025-06-12T19:00:11.234020+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2443,"status":"completed","created_date":"2025-06-11T18:40:21.778248+05:30","modified_date":"2025-06-11T20:12:23.421912+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2442,"status":"completed","created_date":"2025-06-11T01:35:10.827448+05:30","modified_date":"2025-06-11T01:35:47.560810+05:30","user":{"id":53,"username":"rhegde","email":"rhegde@zscaler.com","first_name":"Rohit","last_name":"Hegde","image":null,"timezone":"US/Pacific"}},{"id":2441,"status":"completed","created_date":"2025-06-10T20:29:17.218413+05:30","modified_date":"2025-06-10T21:32:53.948187+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2440,"status":"completed","created_date":"2025-06-09T18:04:08.631062+05:30","modified_date":"2025-06-09T21:34:10.878385+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2439,"status":"completed","created_date":"2025-06-06T23:28:41.789682+05:30","modified_date":"2025-06-07T00:46:44.020411+05:30","user":{"id":3,"username":"tdewan","email":"tdewan@zscaler.com","first_name":"Tarun","last_name":"Dewan","image":null,"timezone":"Asia/Kolkata"}},{"id":2438,"status":"completed","created_date":"2025-06-05T18:24:36.489151+05:30","modified_date":"2025-06-05T21:22:29.828628+05:30","user":{"id":6,"username":"akumar","email":"avinash.kumar@zscaler.com","first_name":"Avinash","last_name":"Kumar","image":null,"timezone":"Asia/Kolkata"}},{"id":2437,"status":"completed","created_date":"2025-06-04T23:35:40.523499+05:30","modified_date":"2025-06-05T00:36:42.839453+05:30","user":{"id":3,"username":"tdewan","email":"tdewan@zscaler.com","first_name":"Tarun","last_name":"Dewan","image":null,"timezone":"Asia/Kolkata"}}]}}

# def download_export_file(export_id):
#     url = f'{zintel_url}api/coverage/yara-exports/{export_id}/download/'
#     headers = {
#         'accept': 'application/json',
#         'Authorization': f'Api-Key {zintel_api}',
#         'Content-Type': 'application/json'
#     }
#     response = requests.get(url, headers=headers)
#     data = response.content
#     if str(response.status_code).startswith("2"):
#         export_file = open("export.zip","wb")
#         export_file.write(data)
#         export_file.close()




def download_and_update_export_files(export_id, unzip_location):
    """
    Fetch a zip file from a URL, unzip it to a given location, and update only changed or new files.

    :param url: The URL to fetch the zip file from.
    :param unzip_location: The directory to unzip the contents to.
    """
    #if export id is newest then skip
    files = os.listdir('.')
    last_export_id = ""
    pattern = re.compile(r'^export_(\d+)\.zip$')
    for filename in files:
        match = pattern.match(filename)
        if match:
            last_export_id = match.group(1)
            break  # stop at the first match
    print(str(last_export_id))
    print(str(export_id))
    print(str(last_export_id)==str(export_id))

    if str(last_export_id) == str(export_id):
        print("All files are already up to date.")
        return

    # Step 1: Make a request to download the zip file
    url = f'{zintel_url}api/coverage/yara-exports/{export_id}/download/'
    headers = {
        'accept': 'application/json',
        'Authorization': f'Api-Key {zintel_api}',
        'Content-Type': 'application/json'
    }
    print("Downloading zip file from:", url)
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Failed to fetch zip file. HTTP Status Code: {response.status_code}")
        return
    data = response.content
    if str(response.status_code).startswith("2"):
        export_file = open("export_"+export_id+".zip","wb")
        export_file.write(data)
        export_file.close()
    
    # Step 2: Open the zip file from the response content
    with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
        # Step 3: Iterate through each file in the zip
        for file_name in zip_file.namelist():
            # Create the full file path
            if "." not in file_name:
                continue
            file_path = os.path.join(unzip_location, file_name)
            
            # Check if the file already exists
            if os.path.exists(file_path):
                # Check if the current file in zip differs from the existing file
                with zip_file.open(file_name) as zip_file_content:
                    existing_file_content = open(file_path, 'rb').read()
                    new_file_content = zip_file_content.read()
                    
                    # If the file's content matches, skip updating it
                    if existing_file_content == new_file_content:
                        print(f"File '{file_name}' is up to date. Skipping update.")
                        continue
            
            # Save the new/updated file to the directory
            print(f"Updating file: {file_name}")
            with zip_file.open(file_name) as source, open(file_path, 'wb') as target:
                target.write(source.read())

    print("All files have been updated successfully.")

# Example usage:
def update_yara_export_files():
# if __name__ == "__main__":
    export_id = get_latest_export_id()
    UNZIP_LOCATION = "E:\\LLM\\yara_exports"
    download_and_update_export_files(export_id, UNZIP_LOCATION)
update_yara_export_files()
