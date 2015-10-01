import os
from clint.textui import progress, prompt
import xdg.BaseDirectory
import hashlib
import urllib.request
import subprocess


class IsoVerifier(object):
    def start(self, jobs, path_format):
        checksum_files = []
        pgp_public_keys = {}
        for job in jobs:
            file_list = None
            if "sha1" in job.checksum_file:
                file_list = job.checksum_file["sha1"]
            elif "md5" in job.checksum_file:
                file_list = job.checksum_file["md5"]
            else:
                print("No checksums available for {}".format(job.label))
            if file_list:
                if not isinstance(file_list, list):
                    file_list = [file_list]
                for file in file_list:
                    if (file, False) not in checksum_files:
                        checksum_files.append((file, False))
                        if job.pgp_suffix:
                            checksum_files.append(("{}{}".format(file, job.pgp_suffix), True))
                        pgp_public_keys[file] = {
                            'id': job.pgp_key_id,
                            'keyserver': job.pgp_keyserver
                        }

        cache_dir = xdg.BaseDirectory.save_cache_path('iso-manager')
        checksum_cache_dir = os.path.join(cache_dir, "checksums")
        if not os.path.isdir(checksum_cache_dir):
            os.mkdir(checksum_cache_dir)

        with progress.Bar(label="Downloading checksum files", expected_size=len(checksum_files), hide=False) as bar:
            bar.show(0)
            index = 0
            for file in checksum_files:
                file_id = hashlib.sha1(file[0].encode('utf-8')).hexdigest()
                target_path = os.path.join(checksum_cache_dir, file_id)
                if not os.path.isfile(target_path):
                    urllib.request.urlretrieve(file[0], target_path)
                index += 1
                bar.show(index)

        with progress.Bar(label="Verifying PGP signatures", expected_size=len(checksum_files) / 2, hide=False) as bar:
            bar.show(0)
            index = 0
            for file in checksum_files:
                if file[1]:  # This is a signature file
                    checksum_for = '.'.join(file[0].split('.')[0:-1])
                    file_id = hashlib.sha1(checksum_for.encode('utf-8')).hexdigest()
                    checksum_file_id = hashlib.sha1(file[0].encode('utf-8')).hexdigest()
                    checksum_file = os.path.join(checksum_cache_dir, file_id)
                    signature_file = os.path.join(checksum_cache_dir, checksum_file_id)
                    result = subprocess.call(["gpg", "--verify", signature_file, checksum_file],
                                             stderr=subprocess.DEVNULL)
                    pgp_info = pgp_public_keys[checksum_for]
                    if result == 2:
                        print("\nSignature could not be verified for {}".format(checksum_for))
                        options = [
                            {
                                'selector': '1',
                                'prompt': 'Download the public key {id} from {keyserver}'.format(**pgp_info),
                                'return': 'download'
                            },
                            {
                                'selector': '2',
                                'prompt': "Don't check the signature for the checksum file",
                                'return': 'ignore'
                            },
                            {
                                'selector': '3',
                                'prompt': 'Abort verifying altogether',
                                'return': 'abort'
                            }
                        ]
                        ask = prompt.options("Do you want to download the public key {}?".format(pgp_info['id']),
                                             options)
                        if ask == 'download':
                            subprocess.call(['gpg', '--keyserver', pgp_info['keyserver'], '--recv-keys',
                                             '0x{}'.format(pgp_info['id'])])
                    elif result == 1:
                        print("\n\nSignature invalid for {}. Aborting.".format(checksum_for))
                        exit(1)
                    index += 1
                    bar.show(index)

        with progress.Bar(label="Verifying checksums", expected_size=len(jobs), hide=False) as bar:
            bar.show(0)
            index = 0
            for job in jobs:
                iso_file = job.get_path(path_format)
                if os.path.isfile(iso_file):
                    if "sha1" in job.checksum_file:
                        file_list = job.checksum_file["sha1"]
                        algorithm = "sha1"
                    elif "md5" in job.checksum_file:
                        file_list = job.checksum_file["md5"]
                        algorithm = "md5"
                    else:
                        raise Exception("No hash key found")
                    if not isinstance(file_list, list):
                        file_list = [file_list]
                    hashes = {}
                    for file in file_list:
                        cache_id = hashlib.sha1(file.encode('utf-8')).hexdigest()
                        checksum_file = os.path.join(checksum_cache_dir, cache_id)
                        hashes.update(self.parse_hash_file(checksum_file))

                    file_hash = self.file_hash(algorithm, iso_file)
                    if file_hash != hashes[job.get_filename_for_checksum()]:
                        print("Checksum invalid for {}. Aborting.".format(job.label))
                        exit(1)
                index += 1
                bar.show(index)

    def file_hash(self, algorithm, filename):
        block_size = 2 ** 16
        if algorithm == "md5":
            hasher = hashlib.md5()
        elif algorithm == "sha1":
            hasher = hashlib.sha1()
        else:
            raise Exception("Hash function not supported")
        with open(filename, 'rb') as file:
            buf = file.read(block_size)
            while len(buf) > 0:
                hasher.update(buf)
                buf = file.read(block_size)
        return hasher.hexdigest()

    def parse_hash_file(self, filename):
        result = {}
        with open(filename) as file:
            for line in file:
                file_hash, file_name = line.split(' ', maxsplit=1)
                file_name = file_name[1:].strip()
                result[file_name] = file_hash
        return result
