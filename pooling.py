#! /usr/bin/python
from __future__ import division, print_function, unicode_literals

from concurrent.futures import ThreadPoolExecutor
import socketserver
import queue

class BoundedThreadPoolExecutor(ThreadPoolExecutor):
    """A variant of the ThreadPoolExecutor with a bounded queue size"""

    def __init__(self, max_queue_size = 0, *args, **kwargs):
        super(BoundedThreadPoolExecutor, self).__init__(
            *args, **kwargs)
        self._work_queue = queue.Queue(maxsize = max_queue_size)

class ThreadPoolMixIn:
    """Mix-in class to handle each request using a thread pool."""

    # Maximum number of workers
    max_workers = 100

    # Maximum number of jobs queued for workers
    max_queue_size = 1000

    # Executor
    _executor = None

    def process_request_thread(self, request, client_address):
        """Same as in BaseServer but executed from a thread.

        In addition, exception handling is done here.
        """

        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)

    def process_request(self, request, client_address):
        """Process the request.  Queue up work for a thread."""

        if self._executor is None:
            self._executor = BoundedThreadPoolExecutor(
                max_workers = self.max_workers,
                max_queue_size = self.max_queue_size)

        self._executor.submit(self.process_request_thread,
                              request, client_address)

        import os
        print("child", os.getpid(), "queue size is", self._executor._work_queue.qsize())

    def server_close(self):
        super().server_close()
        if self._executor is not None:
            self._executor.close()

class ThreadPoolTCPServer(ThreadPoolMixIn, socketserver.TCPServer):
    pass
