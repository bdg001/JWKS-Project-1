import requests

# Define the base URL
base_url = 'http://127.0.0.1:8080'

# Send a GET request to /well-known/jwks.json
get_response = requests.get(f'{base_url}/.well-known/jwks.json')

# Send a POST request to /auth with some data (you can customize this data)
post_data = {
    'username': 'your_username',
    'password': 'your_password'
}
post_response = requests.post(f'{base_url}/auth', data=post_data)

# Check the responses
if get_response.status_code == 200:
    print(f'GET /well-known/jwks.json response: {get_response.text}')
else:
    print(f'GET request failed with status code: {get_response.status_code}')

if post_response.status_code == 200:
    print(f'POST /auth response: {post_response.text}')
else:
    print(f'POST request failed with status code: {post_response.status_code}')