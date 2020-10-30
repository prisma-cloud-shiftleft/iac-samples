# Postman Collection for Async Scan Flow 
## Import Postman Demo & Environment file
From Postman menu, select File > Import.  Then select demo file(s) and the environment file.
## Provide Environment details for API server & credentials
1. Click on Manage Environment button in top right
2. Click on the "<api server>.prismacloud.io" item in the Manage Environments popup
3. Enter values under CURRENT VALUE for **server, username, and password**

- Alternatively, you can directly modify the api_server.postman_environment.json with a text editor, filling in the value fields for "server", "username", and "password", for example:
```
{
	"id": "064d974c-383e-47fe-b9cc-8bab0b6c8bff",
	"name": "<api server>.prismacloud.io",
	"values": [
		{
			"key": "server",
			"value": "**my api server name**",
			"enabled": true
		},
		{
			"key": "username",
			"value": "**my access key**",
			"enabled": true
		},
		{
			"key": "password",
			"value": "**my secret key**",
			"enabled": true
		}
	],
	"_postman_variable_scope": "environment",
	"_postman_exported_at": "2020-10-28T17:57:27.024Z",
	"_postman_exported_using": "Postman/7.34.0"
}
```
## Running Demo Collection
- You can run individual API Request in sequence within the collection (as it's tagged with prefix with a number from 1 to 7)
- Or run the entire collection using the Collection Runner 
     1. From Menu, select File > New Runner Window.
     2. Select your collection name from the list.
     3. Click blue Run button.
