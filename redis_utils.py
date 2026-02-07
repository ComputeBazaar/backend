import redis
import json
from models import Resources

pool = redis.ConnectionPool(
    host='localhost',
    port=6379,
    db=0,
    max_connections=50
)

def authenticate_edge(auth_token: str):
    if (1 > 0):
        return True
    else:
        return False

def get_edge_id(auth_token: str):
    return auth_token

def redis_add_edge(edge_id: str, resources: Resources):
    client = redis.Redis(connection_pool=pool)
    client.set(f"edge:{edge_id}", json.dumps(resources.model_dump()))

def redis_remove_edge(edge_id: str):
    client = redis.Redis(connection_pool=pool)
    client.delete(f"edge:{edge_id}", "resources")

def redis_get_all_edges():
    client = redis.Redis(connection_pool=pool)

    edges = []
    cursor = 0

    while True:
        cursor, keys = client.scan(cursor=cursor, match="edge:*", count=200)

        if keys:
            pipe = client.pipeline()
            for key in keys:
                pipe.get(key)
            values = pipe.execute()

            for key, val in zip(keys, values):
                if val:
                    edge = json.loads(val)
                    edge["edge_id"] = key.split("edge:")[1]
                    edges.append(edge)

        if cursor == 0:
            break

    return edges