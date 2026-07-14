from elasticsearch import Elasticsearch

from config import ELASTIC_API_KEY, ELASTIC_URL
from retry_utils import elasticsearch_search


class _RetryingElasticsearch:
    """Thin proxy that adds transient-failure retries to es.search()."""

    def __init__(self, client):
        self._client = client

    def search(self, **kwargs):
        return elasticsearch_search(self._client, **kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


_raw_es = Elasticsearch(
    ELASTIC_URL,
    api_key=ELASTIC_API_KEY,
)
es = _RetryingElasticsearch(_raw_es)
