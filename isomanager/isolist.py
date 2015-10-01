import yaml
import glob
import os
import urllib.parse


class IsoList(object):
    def __init__(self):
        self.downloads = []
        self.raw = None

        self.types = []
        self.distros = []
        self.architectures = []
        self.targets = []
        self.desktop_environments = ['none']

    @staticmethod
    def load_all_definitions():
        iso_list = IsoList()
        path = os.path.abspath(__file__)
        dir_path = os.path.dirname(path)

        for filename in glob.glob("{}/definitions/*.yml".format(dir_path)):
            with open(filename) as definition_file:
                definition_string = definition_file.read()
            iso_list.load(definition_string)
        return iso_list

    def load(self, yaml_string):
        self.raw = yaml.load(yaml_string)
        for distro in self.raw:
            if distro not in self.distros:
                self.distros.append(distro)
            definition_type = self.raw[distro]['type']
            if definition_type not in self.types:
                self.types.append(definition_type)
            if definition_type == "linux":
                self._load_linux_distro(distro)

    def get(self, filters):
        result = []
        for definition in self.downloads:
            if filters['type']:
                if definition.type not in filters['type']:
                    continue
            if filters['arch']:
                if definition.arch not in filters['arch']:
                    continue
            if filters['desktop']:
                if 'none' in filters['desktop']:
                    filters['desktop'].append(None)
                if definition.arch not in filters['arch']:
                    continue
            if filters['distro']:
                if definition.distro not in filters['distro']:
                    continue
            if filters['support']:
                if definition.long_time_support and filters['support'] == 'non-lts':
                    continue
                if not definition.long_time_support and filters['support'] == 'lts':
                    continue
            if filters['target']:
                if definition.target not in filters['target']:
                    continue
            result.append(definition)
        return result

    def _load_linux_distro(self, distro):
        data = self.raw[distro]
        for release in data['releases']:
            for download in release['downloads']:
                definition = IsoDefinition()
                definition.distro = distro
                definition.label = download['label']
                definition.release_number = release['number']
                definition.codename = release['codename']
                definition.long_time_support = release['lts']
                definition.checksum_file = release['checksums']
                definition.pgp_suffix = release['signature-suffix']

                definition.pgp_key_id = release['pgp']['id']
                definition.pgp_keyserver = release['pgp']['keyserver']

                definition.arch = download['arch']
                if download['arch'] not in self.architectures:
                    self.architectures.append(download['arch'])

                definition.desktop_environment = download['de']
                if download['de'] and download['de'] not in self.desktop_environments:
                    self.desktop_environments.append(download['de'])

                definition.netboot = download['netboot']
                definition.target = download['target']
                if download['target'] not in self.targets:
                    self.targets.append(download['target'])

                definition.url = download['url']
                self.downloads.append(definition)


class IsoDefinition(object):
    def __init__(self):
        self.distro = None
        self.label = None
        self.release_number = None
        self.long_time_support = False
        self.codename = None
        self.checksum_file = {}
        self.arch = None
        self.desktop_environment = None
        self.netboot = False
        self.target = None
        self.url = None
        self.pgp_key_id = None
        self.pgp_keyserver = None
        self.pgp_suffix = None
        self.filename = None

    def get_path(self, format_pattern):
        parameters = {
            'distro': self.distro,
            'label': self.label,
            'number': self.release_number,
            'codename': self.codename,
            'arch': self.arch,
            'de': self.desktop_environment,
            'target': self.target
        }
        for key in list(parameters.keys()):
            if isinstance(parameters[key], str):
                parameters[key.title()] = parameters[key].title()
        return format_pattern.format(**parameters)

    def get_status(self, format_pattern):
        path = self.get_path(format_pattern)
        if not os.path.isfile(path):
            return "Needs downloading"
        else:
            return "Exists"

    def get_filename_for_checksum(self):
        if self.filename:
            return self.filename
        else:
            url = urllib.parse.urlparse(self.url)
            path = url.path
            return os.path.basename(path)

    def __repr__(self):
        return "<IsoDefinition {}>".format(self.label)
