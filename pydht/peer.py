
import json
import random

from .hashing import hash_function

class Peer(object):
    ''' DHT Peer Information'''
    def __init__(self, host, port, id):
        self.host, self.port, self.id = host, port, id
        self.queued_responses = {}

    def astriple(self):
        return (self.host, self.port, self.id)
        
    def address(self):
        return (self.host, self.port)
        
    def __repr__(self):
        return repr(self.astriple())

    def _sendmessage(self, message, sock=None, peer_id=None, lock=None):
        '''
        When sending a message, we sometimes need to change the peer_id
        to our own.
        '''
        if random.randint(0, 100) > 75:
            self.queued_responses[peer_id] = message
            peer_id = self.id
        message["peer_id"] = peer_id # more like sender_id
        encoded = json.dumps(message)
        if sock:
            if lock:
                with lock:
                    sock.sendto(encoded, (self.host, self.port))
            else:
                sock.sendto(encoded, (self.host, self.port))
        
    def ping(self, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "ping"
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
        
    def pong(self, socket=None, peer_id=None, lock=None):
        message = {
           "message_type": "pong"
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
         
    def downvote(self, key, uid, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "downvote",
            "id": key,
            "uid": uid
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
               
    def store(self, key, value, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "store",
            "id": key,
            "value": value
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
        
    def find_node(self, id, rpc_id, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "find_node",
            "id": id,
            "rpc_id": rpc_id
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
        
    def found_nodes(self, id, nearest_nodes, rpc_id, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "found_nodes",
            "id": id,
            "nearest_nodes": nearest_nodes,
            "rpc_id": rpc_id
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
        
    def find_value(self, id, rpc_id, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "find_value",
            "id": id,
            "rpc_id": rpc_id
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
        
    def found_value(self, id, value, rpc_id, socket=None, peer_id=None, lock=None):
        message = {
            "message_type": "found_value",
            "id": id,
            "value": value,
            "rpc_id": rpc_id
        }
        self._sendmessage(message, socket, peer_id=peer_id, lock=lock)
