from flask import Flask, request, abort, Response, Blueprint
from abc import ABC, abstractmethod
import simplejson as json
import re
from pprint import pprint
from typing import get_type_hints

app = Flask(__name__)
bp = Blueprint('api', __name__)

servers = {}

v4pattern = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}$")

def typechecked(func):
    def wrapper(self, **kwargs):
        hints = get_type_hints(func)

        for key, value in kwargs.items():
            hint = hints.get(key, None)
            if hint is None:
                continue

            if not isinstance(value, hint):
                fmt = 'Expected {0.__name__} for {1!r}, received {2.__class__.__name__} instead'
                raise TypeError(fmt.format(hint, key, value))

        return func(self, **kwargs)

    return wrapper

class Serializable(ABC):
    @abstractmethod
    def serialize(self):
        pass

class Client(Serializable):
    @typechecked
    def __init__(self, *, name: str, clan: str, country: int, score: int, team: int, **kwargs):
        self.name = name
        self.clan = clan
        self.country = country
        self.score = score
        self.team = team

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return self.__dict__

class Map(Serializable):
    @typechecked
    def __init__(self, *, name: str, crc: str, sha256: str, size: int, **kwargs):
        self.name = name
        self.crc = crc
        self.sha256 = sha256
        self.size = size

        try:
            int(crc, 16)
            int(sha256, 16)
        except ValueError:
            raise ValueError("'crc' and 'sha256' have to be base 16")

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return self.__dict__

class Server(Serializable):
    @typechecked
    def __init__(self, *, ipv4: str, ipv6: str, port: int, name: str, game_type: str,
                 passworded: bool, version: str, max_players: int, max_clients: int,
                 clients: list, map: dict, secret: str, beat: int, **kwargs):
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.port = port
        self.name = name
        self.game_type = game_type
        self.passworded = passworded
        self.version = version
        self.max_players = max_players
        self.max_clients = max_clients
        self.clients = clients
        self.map = map
        self.secret = secret
        self.beat = beat

        if not 0 <= port <= 65536:
            raise ValueError('port has to be between 0 and 65536')

    def set_ip(self, ipv4, ipv6):
        if ipv4:
            self.ipv4 = ipv4
        if ipv6:
            self.ipv6 = ipv6

    @classmethod
    def from_req_dict(cls, data, ipv4, ipv6):
        info = data.pop('info')
        clients = [Client(**c) for c in info.pop('clients')]
        map = Map(**info.pop('map'))

        return cls(ipv4=ipv4, ipv6=ipv6, clients=clients, map=map, **data, **info)

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return {"ip": self.ipv4, "ipv6": self.ipv6,
                "info": { k:getattr(self, k) for k in ('name', 'game_type', 'passworded', 'version',
                                       'max_players', 'max_clients', 'clients', 'map')},
                "port": self.port}


def serialize(obj):
    if issubclass(type(obj), Serializable):
        return obj.serialize()

    raise TypeError(repr(obj) + " is not JSON serializable")

def json_wrap(json):
    return Response(json + "\n", mimetype='application/json')

@bp.route('/servers', methods=['POST'])
def server_beat():
    if request.is_json:
        data = request.json
        if data is None:
            abort(400)

        try:
            s = Server.from_req_dict(data, "", "")
        except (KeyError, TypeError, ValueError):
            abort(400)

        key = s.secret
        if key in servers.keys():
            s.set_ip(servers[key].ipv4, servers[key].ipv6)

        if v4pattern.match(request.remote_addr):
            s.set_ip(request.remote_addr, None)
        else:
            s.set_ip(None, request.remote_addr)

        if key not in servers.keys() or servers[key].beat > s.beat:
            servers[key] = s

    # Also need to ensure no two servers register with the same ip,
    # which will be a little bit of trouble given each server can have 2 ips
    # a problem for another day

        return 'Done'

    else:
        abort(400)

@bp.route('/servers')
def server_list():
    return json_wrap(json.dumps(list(servers.values()), default=serialize))

app.register_blueprint(bp, url_prefix='/v1')
