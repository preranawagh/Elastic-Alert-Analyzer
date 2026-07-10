from elasticsearch import Elasticsearch
from config import ELASTIC_URL, ELASTIC_API_KEY

es = Elasticsearch(
    ELASTIC_URL,
    api_key=ELASTIC_API_KEY
)