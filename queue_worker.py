import time
import queue
from threading import Thread


def tick_gen(period):
    t = time.time()
    count = 0
    while True:
        count += 1
        yield max(t + count*period - time.time(), 0)

class Worker(Thread):
    def __init__(self, queue, stop_marker, period):
        super().__init__()
        self.queue = queue
        self.stop_marker = stop_marker
        self.period = period
        self.daemon = True
        self.start()

    # Discussion:
    # https://stackoverflow.com/questions/8600161/executing-periodic-actions-in-python/28034554#28034554
    def run(self):
        g = tick_gen(self.period)
        while True:
            time.sleep(next(g))
            try:
                instruction = self.queue.get(timeout=self.period)
                if instruction is self.stop_marker:
                    break
                else:
                    f, args = instruction
                    f(*args)
            except queue.Empty:
                pass
        return



