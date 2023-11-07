from flask import Flask, request
from pymongo import MongoClient

app = Flask(__name__)

#define MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client.cluster1    # use cluster1 db

@app.route("/")
def list_collections():
    # get list of database name from cluster1 db
    category = db.get_collection("sample_geospatial")
    collections = category.list_collection_names()
    
    # generate HTML list of collection names
    collection_list_html = "<ul>"
    
    for collection in collections:
        collection_list_html += f"<li>{collection}</li>"
        
    collection_list_html += "</ul>"
        
    return f"<h1>Collections in 'sample_geospatial' Category within 'cluster1' Database:</h1>{collection_list_html}"
    
if __name__ == "__main__":
    app.run()