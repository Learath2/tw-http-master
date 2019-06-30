from flask import Flask, request, abort, Response, Blueprint
from abc import ABC, abstractmethod
import simplejson as json
from pprint import pprint
app = Flask(__name__)
bp = Blueprint('api', __name__)

servers = {}

class ValidationError(Exception):
    pass

class Serializable(ABC):
    @abstractmethod
    def serialize(self):
        pass

class Client(Serializable):
    def __init__(self, name, clan, country, score, team):
        self.name = name
        self.clan = clan
        self.country = country
        self.score = score
        self.team = team

    def validate_dict(d):
        if not all(k in d for k in ('name', 'clan', 'country', 'score', 'team')):
            raise ValidationError

        if not (isinstance(d['name'], str) and
                isinstance(d['clan'], str) and
                isinstance(d['country'], str) and
                isinstance(d['score'], int) and
                isinstance(d['team'], int)):
            raise ValidationError

        return True

    def from_dict(d):
        if not Client.validate_dict(d):
            return None

        return Client(d['name'], d['clan'], d['country'], d['score'], d['team'])

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return self.__dict__

class Map(Serializable):
    def __init__(self, name, crc, sha256, size):
        self.name = name
        self.crc = crc
        self.sha256 = sha256
        self.size = size

    def validate_dict(d):
        if not all(k in d for k in ('name', 'crc', 'sha256', 'size')):
            raise ValidationError

        if not (isinstance(d['name'], str) and
                isinstance(d['crc'], str) and
                isinstance(d['sha256'], str) and
                isinstance(d['size'], int)):
            raise ValidationError

        try:
            int(d['crc'], 16)
            int(d['sha256'], 16)
        except ValueError:
            raise ValidationError

        return True

    def from_dict(d):
        if not Map.validate_dict(d):
            return None

        return Map(d['name'], d['crc'], d['sha256'], d['size'])

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return self.__dict__

class Server(Serializable):
    def __init__(self, ip, port, name, game_type, passworded, version, max_players, max_clients, clients, map, secret, beat):
        self.ip = ip
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

    def validate_req_dict(d):
        if not all(k in d for k in ('info', 'port', 'secret', 'beat')):
            raise ValidationError

        if not (isinstance(d['info'], dict) and
                isinstance(d['port'], int) and
                isinstance(d['secret'], str) and
                isinstance(d['beat'], int)):
            raise ValidationError

        info = d['info']
        if not all(k in info for k in ('name', 'game_type', 'passworded', 'version',
                                       'max_players', 'max_clients', 'clients', 'map')):
            raise ValidationError


        if not (isinstance(info['name'], str) and
                isinstance(info['game_type'], str) and
                isinstance(info['passworded'], bool) and
                isinstance(info['version'], str) and
                isinstance(info['max_players'], int) and
                isinstance(info['max_clients'], int) and
                isinstance(info['clients'], list) and
                isinstance(info['map'], dict)):
            raise ValidationError

        if not 0 <= d['port'] <= 65536:
            raise ValidationError

        if not (Map.validate_dict(info['map']) and
                all((isinstance(p, dict) and Client.validate_dict(p)) for p in info['clients'])):
            raise ValidationError

        return True

    def from_req_dict(d, ip):
        if not Server.validate_req_dict(d):
            return None

        info = d['info']

        clients = []
        for p in info['clients']:
            t = Client.from_dict(p)
            if t is None:
                raise Exception("Invalid player in player list")
            clients.append(t)

        map = Map.from_dict(info['map'])

        return Server(ip, d['port'], info['name'], info['game_type'], info['passworded'],
                      info['version'], info['max_players'], info['max_clients'], clients, map,
                      d['secret'], d['beat'])

    def to_dict(self):
        return self.__dict__

    def serialize(self):
        return {"ip": self.ip,
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

        s = Server.from_req_dict(data, request.remote_addr)
        key = '{}#{}'.format(request.remote_addr, s.port)
        if not (key in servers.keys() and servers[key].beat > s.beat):
            servers[key] = s

        return 'Done'

    else:
        abort(400)

@bp.route('/servers')
def server_list():
    return json_wrap(json.dumps(list(servers.values()), default=serialize))

app.register_blueprint(bp, url_prefix='/v1')
