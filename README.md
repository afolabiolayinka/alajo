# alajo api
## A minimal 3rd party api for businesses
### Flask + Sqlite

```
$ . venv/bin/activate
```
```
$ flask --app main --debug run
```
This should start a server running on port 5000

#### To reset the instance (database) you will need to delete the instance folder and run localhost:5000/setup endpoint

### Endpoints
The endpoints postman is this repo.

### Docker

```
$ docker build --tag alajo .
```
```
sudo docker run -d -p 5000:5000 alajo
```