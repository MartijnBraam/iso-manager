import os
import requests
from clint.textui import progress


class IsoDownloader(object):
    def start(self, jobs, path_format):
        total_jobs = len(jobs)
        job_number = 1
        for job in jobs:
            path = job.get_path(path_format)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            print("[{}/{}] Starting to download {} to {}".format(job_number, total_jobs, job.label, path))
            job_number += 1
            r = requests.get(job.url, stream=True)
            with open(path, 'wb') as f:
                total_length = int(r.headers.get('content-length'))
                for chunk in progress.bar(r.iter_content(chunk_size=1024), expected_size=(total_length / 1024) + 1, hide=False):
                    if chunk:
                        f.write(chunk)
                        f.flush()