import hashlib

from base64 import b64decode
from base64 import b64encode

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util.number import bytes_to_long

from swiftclient import Connection

from app import utils


class Swift:


    def __init__(self, token, base="OrchestratorDashboard"):
        self.base = base
        self.private_key = hashlib.sha256(self.base.encode("utf-8")).digest()
        self.bs = 16
        self._split(token)
        self.token = token
        self.connection = None

        self.emptyMd5 = "d41d8cd98f00b204e9800998ecf8427e"

    def getconnection(self):
        if self.connection is None:
            if self.version == '3':
                os_options = {
                    'project_name': self.tenant,
                    'project_domain_name': '',
                    'user_domain_name': '',
                }
                self.connection = Connection(
                    auth_version='3',
                    authurl=self.authurl,
                    user=self.user,
                    key=self.key,
                    os_options=os_options)

            elif self.version == '1':
                self.connection = Connection(
                    auth_version='1',
                    authurl=self.authurl,
                    user=self.user,
                    key=self.key,
                    tenant_name='UNUSED')

            else:
                raise NotImplementedError(
                    'auth_version? {!r}'.format(self.version))
        return self.connection

    def setbase(self, base):
        if isinstance(base, str):
            if len(base) >= 8:
                self.base = base
                self.private_key = hashlib.sha256(self.base.encode("utf-8")).digest()
                self.cipher = AES.new(self.private_key, AES.MODE_ECB)
                if self.token is not None:
                    t = "OS" + "§" \
                        + self.authurl + "§" \
                        + self.version + "§" \
                        + self.user + "§" \
                        + self.key + "§" \
                        + self.tenant + "§" \
                        + self.basecontainername
                    self.token = self._pack(t)
                self.connection = None
                return self.token
        raise ValueError("Invalid key.")

    def mapvalue(self, v):
        if v in self.mapped:
            return self.mapped[v]
        return None

    def getownedcontainers(self):
        return self.getconnection().get_account()[1]

    def getcontainerobjects(self, containername):
        return self.getconnection().get_container(containername)[1]

    def createcontainer(self, containername):
        return self.getconnection().put_container(containername)

    def createobject(self, containername, objectname, contents):
        return self.getconnection().put_object(container=containername,
                        obj=objectname,
                        contents=contents,
                        content_type='application/octet-stream')

    def removeobject(self, containername, objectname):
        self.getconnection().delete_object(container=containername,
                                                  obj=objectname)

    def _pack(self, data):
        iv = get_random_bytes(self.bs)
        self.cipher = AES.new(self.private_key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'),
                                                      AES.block_size))).decode('utf-8')

    def _unpack(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.private_key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size).decode('utf-8')

    def _split(self, settings):
        self.mapped = {}
        try:
            splitted = self._unpack(settings).split("§")
            if splitted[0] == "OS":
                if len(splitted) == 7:
                    self.authurl = self.mapped["swift_a"] = splitted[1]  # Auth url
                    self.version = self.mapped["swift_v"] = splitted[2]  # Auth version
                    self.user = self.mapped["swift_u"] = splitted[3]  # user
                    self.key = self.mapped["swift_k"] = splitted[4]  # key
                    self.tenant = self.mapped["swift_t"] = splitted[5]  # tenant
                    self.basecontainername = self.mapped["swift_c"] = splitted[6]  # base container name
        except Exception as error:
            utils.logexception("decoding data:".format(error))

        return self.mapped


    def md5hash(self, f, offset=0, length=0, buffer_size=2097152):
        """ Generate MD5 hash for specified file (chunck).
        :param f: file path or file object.
        :param offset: offset.
        :param length: length.
        :param buffer_size: buffer size. Defaults to 65536.
        :return: MD5 hash string
        """
        if isinstance(f, str):
            with open(f, 'rb') as o:
                return self.md5hash(o, offset, length, buffer_size)

        hasher = hashlib.md5()
        if offset > 0:  # chunked
            f.seek(offset)
        if length > 0:  # chunked
            total_read = 0
            while length > total_read:
                if total_read + buffer_size < length:
                    buff = f.read(buffer_size)
                else:
                    buff = f.read(length - total_read)
                hasher.update(buff)
                total_read += len(buff)
        else:
            for buff in iter(lambda: f.read(buffer_size), b""):
                hasher.update(buff)

        return hasher.hexdigest()
